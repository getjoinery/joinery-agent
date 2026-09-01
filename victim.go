package main

// The victim side of a decommission: how a host-posture agent finds the
// container site it has been asked to destroy, reads what it needs to stage
// the approval, and asks THAT site's operator for consent.
//
// EVERY PATH IS COMPOSED HERE from compiled-in patterns and the validated site
// name — the wire supplies a NAME and nothing else (the delete_backup rule).
// The victim is located through two files the HOST owns or holds:
//
//   - /etc/apache2/sites-available/<site>.conf — written by install.sh ON THE
//     HOST, never writable from inside the container. Its ProxyPass line names
//     the container's published web port, and install.sh publishes the
//     container's Postgres on 127.0.0.1 at web port + 1000 (both allocations
//     are install.sh's own; see do_site_docker).
//   - /var/lib/docker/volumes/<site>_config/_data/Globalvars_site.php — the
//     config volume's host-side path. Read from the host filesystem, NEVER
//     via docker exec: a teardown must not execute a binary inside a
//     possibly-compromised container as its first act.
//
// TRUST BOUNDARY, NAMED: the config file and every row read from the victim's
// database are container-controlled bytes. The config parse stays the same
// narrow line regex the agent uses on its own config, and every victim-sourced
// string that ends up in the statement is passed through displaySafe — it is
// untrusted display data, nothing more.
//
// The victim's DB credential is held in memory for the life of the connection
// — never at rest, never in argv or environment (the DSN goes to lib/pq as an
// in-process string, not to a subprocess).

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"joinery-agent/primitives"
)

const (
	// victimVhostPattern and victimConfigPattern are the two compiled-in
	// locations. %s is the validated site name (^[a-z0-9_-]{1,50}$ — no
	// separators, so no composed path escapes its directory).
	victimVhostPattern  = "/etc/apache2/sites-available/%s.conf"
	victimConfigPattern = "/var/lib/docker/volumes/%s_config/_data/Globalvars_site.php"

	// victimDBPortOffset is install.sh's own allocation rule: the container
	// publishes Postgres on 127.0.0.1 at web port + 1000 (do_site_docker,
	// DB_PORT=$((PORT + 1000))). If a container was ever run outside that
	// rule the connection fails and the job refuses — never guesses.
	victimDBPortOffset = 1000

	victimDialTimeout = 10 * time.Second
)

// proxyPassPort finds the published web port in the host-owned vhost.
var proxyPassPort = regexp.MustCompile(`ProxyPass\s+/\s+http://127\.0\.0\.1:(\d{2,5})/`)

// victimCeremonyFor gates the ceremony on posture: only a machine with no site
// of its own destroys co-resident sites. A site machine gets nil, and the
// primitive's own refusal names the reason.
func victimCeremonyFor(cfg *Config) func(context.Context, string) (primitives.ApprovalStatement, primitives.ApprovalGate, func(), error) {
	if cfg == nil || !cfg.Siteless {
		return nil
	}
	return victimCeremony
}

// victimCeremony builds the decommission ceremony for one container site:
// the statement (from the victim's own records) and the gate (staged into the
// victim's own settings, sealed to the victim's own proven recovery key).
// Returned cleanup closes the victim connection.
func victimCeremony(ctx context.Context, site string) (primitives.ApprovalStatement, primitives.ApprovalGate, func(), error) {
	none := primitives.ApprovalStatement{}

	// Belt to the validator's braces: nothing below composes a path from a
	// name this did not accept.
	if !regexp.MustCompile(`^[a-z0-9_-]{1,50}$`).MatchString(site) {
		return none, nil, nil, &primitives.RefusalError{Reason: "the site name is not one this host composes paths from"}
	}

	webPort, err := victimWebPort(site)
	if err != nil {
		return none, nil, nil, err
	}

	cfg, err := victimConfig(site)
	if err != nil {
		return none, nil, nil, err
	}

	dbPort := webPort + victimDBPortOffset
	dsn := fmt.Sprintf("host=127.0.0.1 port=%d dbname=%s user=%s password=%s sslmode=disable connect_timeout=10",
		dbPort, quoteDSNValue(cfg["dbname"]), quoteDSNValue(cfg["dbusername"]), quoteDSNValue(cfg["dbpassword"]))
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return none, nil, nil, &primitives.RefusalError{Reason: fmt.Sprintf(
			"the site %s's database connection could not be prepared, so its operator cannot be asked: %v", site, err)}
	}
	pingCtx, cancel := context.WithTimeout(ctx, victimDialTimeout)
	defer cancel()
	if err := db.PingContext(pingCtx); err != nil {
		db.Close()
		return none, nil, nil, &primitives.RefusalError{Reason: fmt.Sprintf(
			"the site %s's database did not answer on its published port (127.0.0.1:%d), so its operator "+
				"cannot be asked to approve its removal — a site that cannot consent is not removed this way", site, dbPort)}
	}

	statement := decommissionStatement(ctx, db, site, cfg)
	gate := newScopedApproval(victimSettings{db: db}, decommissionScope)
	cleanup := func() { _ = db.Close() }
	return statement, gate, cleanup, nil
}

// victimWebPort reads the container's published web port out of the host-owned
// vhost. The vhost is the HOST's statement of where this site lives, which is
// better provenance than anything the container could say.
func victimWebPort(site string) (int, error) {
	path := fmt.Sprintf(victimVhostPattern, site)
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, &primitives.RefusalError{Reason: fmt.Sprintf(
			"this host has no vhost for a site named %s (%s), so there is no such container site here", site, path)}
	}
	m := proxyPassPort.FindSubmatch(raw)
	if m == nil {
		return 0, &primitives.RefusalError{Reason: fmt.Sprintf(
			"the vhost for %s carries no ProxyPass port, so this is not a container site this host fronts "+
				"— a bare-metal site is not removed this way", site)}
	}
	port, err := strconv.Atoi(string(m[1]))
	if err != nil || port < 1 || port > 65535 {
		return 0, &primitives.RefusalError{Reason: fmt.Sprintf("the vhost for %s names an unusable port", site)}
	}
	return port, nil
}

// victimConfig reads the victim's own site config from the config volume's
// host-side path — the same narrow line regex the agent uses on its own
// config, over container-controlled bytes.
func victimConfig(site string) (map[string]string, error) {
	path := fmt.Sprintf(victimConfigPattern, site)
	settings, err := parseGlobalvars(path)
	if err != nil {
		return nil, &primitives.RefusalError{Reason: fmt.Sprintf(
			"the site %s's config could not be read from its config volume (%s), so its database cannot "+
				"be reached and its operator cannot be asked: %v", site, path, err)}
	}
	for _, key := range []string{"dbname", "dbusername", "dbpassword"} {
		if strings.TrimSpace(settings[key]) == "" {
			return nil, &primitives.RefusalError{Reason: fmt.Sprintf(
				"the site %s's config carries no %s, so its database cannot be reached", site, key)}
		}
	}
	return settings, nil
}

// decommissionStatement is the host's account of what this job destroys, with
// the one load-bearing fact read from the victim's own records: its last
// COMPLETED offsite upload — its own testimony, not the bucket's, because this
// host holds no bucket credential and must not.
func decommissionStatement(ctx context.Context, db *sql.DB, site string, cfg map[string]string) primitives.ApprovalStatement {
	domain := displaySafe(cfg["webDir"], 100)
	if domain == "" {
		domain = "unknown domain"
	}

	facts := []primitives.ApprovalFact{
		{Label: "Site", Value: site},
		{Label: "Domain", Value: domain},
		{Label: "What happens to it", Value: "the container, its database, its uploaded files, its " +
			"configuration and its web presence on this host are all destroyed, permanently. Nothing is put back."},
		{Label: "Last completed offsite upload", Value: lastCompletedUpload(ctx, db)},
	}

	return primitives.ApprovalStatement{
		Primitive: "decommission_site",
		Summary: "This will permanently DESTROY the site " + site + " (" + domain + ") on its host. " +
			"This is not a restore and not a move: everything this site is — its database, files and " +
			"container — is deleted, and only its offsite backups survive.",
		Facts: facts,
	}
}

// lastCompletedUpload reads the newest row in the victim's own backup history
// that records a completed upload, and says whose testimony that is.
func lastCompletedUpload(ctx context.Context, db *sql.DB) string {
	var uploaded time.Time
	var kind sql.NullString
	err := db.QueryRowContext(ctx,
		`SELECT bkh_upload_time, bkh_type FROM bkh_backup_history
		 WHERE bkh_outcome = 'success' AND bkh_upload_time IS NOT NULL AND bkh_delete_time IS NULL
		 ORDER BY bkh_upload_time DESC LIMIT 1`).Scan(&uploaded, &kind)
	if err == sql.ErrNoRows {
		return "NONE — this site's own history records no completed offsite upload. " +
			"If this site is destroyed now, nothing of it survives."
	}
	if err != nil {
		return "unknown — this site's own backup history could not be read (" + displaySafe(err.Error(), 120) + ")"
	}
	age := time.Since(uploaded)
	days := int(age.Hours() / 24)
	var rendered string
	switch {
	case age < time.Hour:
		rendered = fmt.Sprintf("%s UTC (%d minutes ago)", uploaded.UTC().Format("2006-01-02 15:04:05"), int(age.Minutes()))
	case age < 48*time.Hour:
		rendered = fmt.Sprintf("%s UTC (%d hours ago)", uploaded.UTC().Format("2006-01-02 15:04:05"), int(age.Hours()))
	default:
		rendered = fmt.Sprintf("%s UTC (%d days ago)", uploaded.UTC().Format("2006-01-02 15:04:05"), days)
	}
	if kind.Valid && displaySafe(kind.String, 20) != "" {
		rendered += " (" + displaySafe(kind.String, 20) + ")"
	}
	return rendered + " — this site's own record of its uploads, not the storage bucket's"
}

// victimSettings is approvalStore over the victim's connection: the same two
// statements readAgentSetting/writeAgentSetting run against the agent's own
// database, aimed at the victim's.
type victimSettings struct{ db *sql.DB }

func (v victimSettings) Read(name string) (string, error) {
	var value sql.NullString
	err := v.db.QueryRow("SELECT stg_value FROM stg_settings WHERE stg_name = $1", name).Scan(&value)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return value.String, nil
}

func (v victimSettings) Write(name, value string) error {
	_, err := v.db.Exec(
		`INSERT INTO stg_settings (stg_name, stg_value, stg_usr_user_id, stg_create_time, stg_update_time, stg_group_name)
		 VALUES ($1, $2, 1, NOW(), NOW(), 'general')
		 ON CONFLICT (stg_name) DO UPDATE SET stg_value = EXCLUDED.stg_value, stg_update_time = NOW()`,
		name, value)
	return err
}

// displaySafe renders a container-controlled string as inert display data:
// control characters dropped, length capped. It protects the operator's screen
// and the agent log, not the mechanism — nothing here is parsed further.
func displaySafe(s string, max int) string {
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			continue
		}
		b.WriteRune(r)
		if b.Len() >= max {
			break
		}
	}
	return strings.TrimSpace(b.String())
}

// quoteDSNValue makes a config value safe inside a lib/pq keyword DSN: values
// are single-quoted with backslash escaping, so a password containing a space
// or quote connects rather than injecting DSN keys.
func quoteDSNValue(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `'`, `\'`)
	return "'" + s + "'"
}
