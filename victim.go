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
//     container's Postgres at web port + 1000 (both allocations are
//     install.sh's own; see do_site_docker). The address it is published on
//     is the engine's answer (engine port SITE 5432/tcp): loopback for most
//     sites, a private address for one whose database other machines read.
//   - <Docker root>/volumes/<site>_config/_data/Globalvars_site.php — the
//     config volume's host-side path. Read from the host filesystem, NEVER
//     via docker exec: a teardown must not execute a binary inside a
//     possibly-compromised container as its first act. The Docker root is
//     the daemon's own answer (docker info), not a guess: /var/lib/docker, or
//     /var/lib/docker/<uid>.<gid> on a host with user-namespace remapping.
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
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"joinery-agent/primitives"
)

const (
	// victimVhostPattern and victimConfigPattern are the two compiled-in
	// locations. %s is the validated site name (^[a-z0-9_-]{1,50}$ — no
	// separators, so no composed path escapes its directory).
	victimVhostPattern  = "/etc/apache2/sites-available/%s.conf"
	victimConfigPattern = "%s/volumes/%s_config/_data/Globalvars_site.php"

	// victimDBPortOffset is install.sh's own allocation rule: the container
	// publishes Postgres at web port + 1000 (do_site_docker,
	// DB_PORT=$((PORT + 1000))). If a container was ever run outside that
	// rule the connection fails and the job refuses — never guesses.
	victimDBPortOffset = 1000

	victimDialTimeout = 10 * time.Second

	// victimQueryTimeout bounds each statement on the victim's connection.
	victimQueryTimeout = 10 * time.Second
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

	db, cfg, err := openVictimDB(ctx, site, "its operator cannot be asked to approve its removal — a site that cannot consent is not removed this way")
	if err != nil {
		return none, nil, nil, err
	}

	statement := decommissionStatement(ctx, db, site, cfg)
	gate := newScopedApproval(victimSettings{db: db}, decommissionScope)
	cleanup := func() { _ = db.Close() }
	return statement, gate, cleanup, nil
}

// openVictimDB connects to one container site's own database, located through
// the host-owned vhost and the site's config volume (see the file comment).
// why finishes the refusal when the database does not answer: what cannot
// happen because it does not. The caller closes the connection.
func openVictimDB(ctx context.Context, site, why string) (*sql.DB, map[string]string, error) {
	webPort, err := victimWebPort(site)
	if err != nil {
		return nil, nil, err
	}

	cfg, err := victimConfig(site)
	if err != nil {
		return nil, nil, err
	}

	dbPort := webPort + victimDBPortOffset
	host, err := victimDBHost(ctx, site, dbPort)
	if err != nil {
		return nil, nil, &primitives.RefusalError{Reason: fmt.Sprintf(
			"the site %s's database address could not be found, so %s: %v", site, why, err)}
	}
	addr := net.JoinHostPort(host, strconv.Itoa(dbPort))
	dsn := fmt.Sprintf("host=%s port=%d dbname=%s user=%s password=%s sslmode=disable connect_timeout=10",
		quoteDSNValue(host), dbPort, quoteDSNValue(cfg["dbname"]), quoteDSNValue(cfg["dbusername"]), quoteDSNValue(cfg["dbpassword"]))
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, nil, &primitives.RefusalError{Reason: fmt.Sprintf(
			"the site %s's database connection could not be prepared, so %s: %v", site, why, err)}
	}
	pingCtx, cancel := context.WithTimeout(ctx, victimDialTimeout)
	defer cancel()
	if err := db.PingContext(pingCtx); err != nil {
		db.Close()
		// The driver's own words say which of the usual causes it is (nothing
		// listening, a pg_hba rule refusing this host's address, the
		// credential refused, no answer in time). They name addresses, the
		// role and the database, never the password, which travels only in
		// the DSN and is not part of any error.
		return nil, nil, &primitives.RefusalError{Reason: fmt.Sprintf(
			"the site %s's database did not answer on its published port (%s), so %s (%v)", site, addr, why, err)}
	}
	return db, cfg, nil
}

// victimDBPorts lists the container's host bindings for its Postgres, one
// address:port per line, from the host's engine (docker or the site container
// engine; both answer port NAME 5432/tcp the same way). The engine is the
// host's record of what it published, which the container cannot change. A
// var so a test can answer for the engine.
var victimDBPorts = func(ctx context.Context, site string) (string, error) {
	name, bin, err := siteEngine()
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, victimDialTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "port", site, "5432/tcp").Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && len(ee.Stderr) > 0 {
			return "", fmt.Errorf("%s port: %v: %s", name, err, displaySafe(strings.TrimSpace(string(ee.Stderr)), 200))
		}
		return "", fmt.Errorf("%s port: %v", name, err)
	}
	return string(out), nil
}

// victimDBHost is the address to dial for the site's database: the engine's
// binding of 5432 whose port is install.sh's (web port + 1000), so a binding
// the allocation rule did not make is never followed. Loopback is preferred
// when the site has one; a wildcard binding is dialed on loopback; otherwise
// the one address the engine names, which must be an IP literal.
func victimDBHost(ctx context.Context, site string, dbPort int) (string, error) {
	out, err := victimDBPorts(ctx, site)
	if err != nil {
		return "", err
	}
	var hosts []string
	var seen []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		seen = append(seen, line)
		h, p, err := net.SplitHostPort(line)
		if err != nil || p != strconv.Itoa(dbPort) {
			continue
		}
		ip := net.ParseIP(h)
		if ip == nil {
			continue
		}
		switch {
		case ip.IsUnspecified() && ip.To4() != nil:
			h = "127.0.0.1"
		case ip.IsUnspecified():
			h = "::1"
		default:
			h = ip.String()
		}
		hosts = append(hosts, h)
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip.IsLoopback() {
			return h, nil
		}
	}
	if len(hosts) > 0 {
		return hosts[0], nil
	}
	if len(seen) == 0 {
		return "", fmt.Errorf("the container engine says %s publishes no database port", site)
	}
	return "", fmt.Errorf("the container engine publishes %s's database at %s, not on port %d as this host allocated it",
		site, displaySafe(strings.Join(seen, ", "), 200), dbPort)
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
	root, err := engineRootDir()
	if err != nil {
		return nil, &primitives.RefusalError{Reason: fmt.Sprintf(
			"the container engine did not say where it keeps the site %s's volumes, so its config cannot be read: %v", site, err)}
	}
	path := fmt.Sprintf(victimConfigPattern, root, site)
	settings, err := readVictimConfig(path)
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

// victimSettings is approvalStore over the victim's connection. ctx, when
// set, is the job's own context, so a cancelled word stops its query too; the
// approval store interface carries none, so a gate's store bounds each
// statement by victimQueryTimeout alone.: the same two
// statements readAgentSetting/writeAgentSetting run against the agent's own
// database, aimed at the victim's. Each is bounded by victimQueryTimeout: the
// victim's Postgres is container-controlled, and one that accepts the
// connection and then never answers would otherwise hold the job lock, and so
// every job, for good.
type victimSettings struct {
	db  *sql.DB
	ctx context.Context
}

func (v victimSettings) parent() context.Context {
	if v.ctx != nil {
		return v.ctx
	}
	return context.Background()
}

func (v victimSettings) Read(name string) (string, error) {
	ctx, cancel := context.WithTimeout(v.parent(), victimQueryTimeout)
	defer cancel()
	var value sql.NullString
	err := v.db.QueryRowContext(ctx, "SELECT stg_value FROM stg_settings WHERE stg_name = $1", name).Scan(&value)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return value.String, nil
}

func (v victimSettings) Write(name, value string) error {
	ctx, cancel := context.WithTimeout(v.parent(), victimQueryTimeout)
	defer cancel()
	_, err := v.db.ExecContext(ctx,
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

// victimConfigLimit bounds what is read of a site's config file.
const victimConfigLimit = 1 << 20

// readVictimConfig reads a site's Globalvars_site.php from its config volume.
// The folders above it are root's (volumes/<name>/_data), but the file itself
// is the site's own, writable from inside its container. So it is opened
// without following a link (a link to another site's config would hand over
// that site's database password), without blocking (a FIFO would hold the job
// lock, and so every job, recipe and update, for good), only as a regular
// file, and read to at most victimConfigLimit, before the same line regex the
// agent uses on its own config.
func readVictimConfig(path string) (map[string]string, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return nil, fmt.Errorf("%s is a link, which is not followed", path)
		}
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file (%v), which is not read", path, st.Mode().Type())
	}
	return parseGlobalvarsFrom(io.LimitReader(f, victimConfigLimit), path)
}

// engineRootDir is where this host's container engine keeps its data, from the
// engine itself: Docker's root directory (with user-namespace remapping every
// volume lives one directory deeper, /var/lib/docker/100000.100000/volumes),
// or the site container engine's storage (its graphroot), whose volumes are
// laid out the same way (volumes/<name>/_data). The path is never assumed.
// Only the host's engine CLI runs; nothing runs inside a container. A var so a
// test can answer for the engine.
var engineRootDir = func() (string, error) {
	name, bin, err := siteEngine()
	if err != nil {
		return "", err
	}
	format := engineStorageFormat(name)
	ctx, cancel := context.WithTimeout(context.Background(), victimDialTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "info", "-f", format).Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && len(ee.Stderr) > 0 {
			return "", fmt.Errorf("%s info: %v: %s", name, err, displaySafe(strings.TrimSpace(string(ee.Stderr)), 200))
		}
		return "", fmt.Errorf("%s info: %v", name, err)
	}
	return checkEngineRoot(strings.TrimSpace(string(out)))
}

// checkEngineRoot accepts only a clean absolute directory: the answer is
// composed into a path, so anything else is refused rather than followed.
func checkEngineRoot(root string) (string, error) {
	if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return "", fmt.Errorf("the container engine's root directory came back as %q, which is not a clean absolute path", displaySafe(root, 120))
	}
	return root, nil
}
