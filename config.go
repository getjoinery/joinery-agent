package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"joinery-agent/primitives"
)

type Config struct {
	DBHost     string
	DBPort     string
	DBName     string
	DBUser     string
	DBPassword string

	PollInterval      time.Duration
	HeartbeatInterval time.Duration
	AgentName         string

	// SecretBoxKey is the site's secret_box_key (base64, 32 bytes) read from
	// Globalvars_site.php. Used to unseal backup-target credentials resolved
	// from __SM_CREDS_<id>__ placeholders at step-execution time. Empty on a
	// site that has no key configured — placeholder resolution then works only
	// for legacy plaintext targets and fails loudly for encrypted ones.
	SecretBoxKey string

	// SiteRoot is the directory holding config/ and public_html/ — the tree a
	// script-invoking primitive's paths resolve against, and the tree the signed
	// release manifest describes.
	SiteRoot string
	// WebRoot is the public_html directory. The disk collector reports the
	// filesystem holding it, which is the one a site operator cares about.
	WebRoot string

	// PlaneTLSInsecure is for a management node behind a self-signed
	// certificate (dev networks). Enrollment itself carries no configuration
	// here: it is the node-initiated join, driven from the local admin page,
	// and shares no secret (A6).
	PlaneTLSInsecure bool

	// PolicyPath is the root-owned acceptance policy (§3.3).
	PolicyPath string

	// LocalJobs is whether this agent also serves the plane-local job queue in
	// its own database. Starts true and is settled at startup by looking for
	// the tables that queue lives in: a machine that is purely a managed node
	// has no plane-local work, and polling a queue that is not its business is
	// not something to leave to configuration. AGENT_LOCAL_JOBS=0 forces it off
	// on a control plane that should not serve its own queue.
	LocalJobs bool

	// AgentDistDir is where platform releases deliver the shipped agent
	// artifact (manifest.json + signed binaries). Derived from the site tree
	// that JOINERY_CONFIG points into; override with AGENT_DIST_DIR.
	AgentDistDir string

	// Siteless is true on a machine that hosts no Joinery site: a mail relay,
	// a Docker host, anything the plane manages that is not itself a
	// deployment. It is a POSTURE, not a failure — SiteRoot, WebRoot and the
	// database fields are legitimately empty and every consumer is expected to
	// degrade rather than refuse to start (spec A13).
	//
	// The distinction that matters is between "there is no site here" and
	// "the site's config could not be read just now". The first is permanent
	// and is this flag; the second is an outage — a node mid-upgrade or
	// mid-restore has no readable config for a few seconds — and must keep
	// waiting, because a machine that gave up and declared itself siteless
	// would silently stop doing its own site's work. So this is set only when
	// the config file is ABSENT, never when it is present and unusable.
	Siteless bool
}

// Default path to the Joinery config file. Override with JOINERY_CONFIG env var.
const defaultJoineryConfig = "/var/www/html/joinerytest/config/Globalvars_site.php"

// agentEnvFile is the environment file the systemd unit loads
// (EnvironmentFile=-/etc/joinery-agent/joinery-agent.env); install_agent.sh
// writes JOINERY_CONFIG there. A variable so tests can point it elsewhere.
var agentEnvFile = "/etc/joinery-agent/joinery-agent.env"

// joineryConfigPath is where this process looks for the site's config: the
// JOINERY_CONFIG variable if the environment carries it, else the same
// variable out of the unit's environment file, else the compiled default.
//
// The daemon always has the variable, because systemd loads the file for it.
// `joinery-agent status` or `join` run by hand from a root shell does not, and
// before the file was consulted such a run fell through to the default — a
// path that exists on one development box — and reported "machine posture (no
// site)" on a machine whose daemon was serving a site. The daemon and the CLI
// now resolve the site the same way.
func joineryConfigPath() string {
	if v := os.Getenv("JOINERY_CONFIG"); v != "" {
		return v
	}
	if v := envFileValue(agentEnvFile, "JOINERY_CONFIG"); v != "" {
		return v
	}
	return defaultJoineryConfig
}

// envFileValue reads KEY=VALUE lines the way systemd's EnvironmentFile does
// for the simple case: blank lines and # comments skipped, optional matching
// quotes around the value stripped. Absent file or key → "".
func envFileValue(path, key string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	found := ""
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(k) != key {
			continue
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 && ((v[0] == '"' && v[len(v)-1] == '"') || (v[0] == '\'' && v[len(v)-1] == '\'')) {
			v = v[1 : len(v)-1]
		}
		found = v // last assignment wins, as in a shell
	}
	return found
}

func LoadConfig() (*Config, error) {
	// Start with defaults
	cfg := &Config{
		DBHost:            "localhost",
		DBPort:            "5432",
		DBUser:            "postgres",
		AgentName:         "joinery-agent",
		PollInterval:      5 * time.Second,
		HeartbeatInterval: 30 * time.Second,
		LocalJobs:         true,
	}

	// Step 1: Try to read DB credentials from Globalvars_site.php
	configPath := joineryConfigPath()
	phpSettings, err := parseGlobalvars(configPath)
	if err != nil {
		// ABSENT is a posture; UNREADABLE is an outage. os.IsNotExist is the
		// whole distinction, and getting it the wrong way round would either
		// wedge a relay for ever or let a node mid-upgrade quietly decide it
		// has no site and stop doing that site's work.
		if os.IsNotExist(err) {
			cfg.Siteless = true
			log.Printf("no Joinery site at %s — starting in machine posture (no site, no local database)", configPath)
		} else {
			log.Printf("NOTE: Could not read Joinery config at %s: %v", configPath, err)
			log.Printf("  Falling back to environment variables / env file.")
		}
	} else {
		log.Printf("read database credentials from %s", configPath)
		if v, ok := phpSettings["dbname"]; ok {
			cfg.DBName = v
		}
		if v, ok := phpSettings["dbusername"]; ok {
			cfg.DBUser = v
		}
		if v, ok := phpSettings["dbpassword"]; ok {
			cfg.DBPassword = v
		}
		if v, ok := phpSettings["secret_box_key"]; ok {
			cfg.SecretBoxKey = v
		}
	}

	// Step 2: Environment variables override everything
	if v := os.Getenv("DB_HOST"); v != "" {
		cfg.DBHost = v
	}
	if v := os.Getenv("DB_PORT"); v != "" {
		cfg.DBPort = v
	}
	if v := os.Getenv("DB_NAME"); v != "" {
		cfg.DBName = v
	}
	if v := os.Getenv("DB_USER"); v != "" {
		cfg.DBUser = v
	}
	if v := os.Getenv("DB_PASSWORD"); v != "" {
		cfg.DBPassword = v
	}
	if v := os.Getenv("AGENT_NAME"); v != "" {
		cfg.AgentName = v
	}

	// Everything is derived from the site whose config we read:
	// {site root}/config/Globalvars_site.php → {site root}/public_html/...
	//
	// A siteless machine derives none of it. Leaving these empty is the point:
	// script primitives refuse without a SiteRoot, the disk collector skips,
	// and the SSL probe says it has no webroot — each of which is the honest
	// answer on a machine that has no site, and all of which would be replaced
	// by a wrong answer if this invented a path from a config file that is not
	// there.
	siteRoot := ""
	if !cfg.Siteless {
		siteRoot = filepath.Dir(filepath.Dir(configPath))
		cfg.SiteRoot = siteRoot
		cfg.WebRoot = filepath.Join(siteRoot, "public_html")
	}
	// The signed agent artifact lives in CORE, not in the server_manager plugin.
	// Every node must receive it, and the open-core rule is that no plugin arrives
	// as a side effect of a core upgrade — server_manager is commercial and
	// entitlement-gated, so it cannot be what carries the agent to a node.
	//
	// Empty on a siteless machine, and deliberately not a relative path: a
	// release never delivers an artifact to a machine with no site tree, so
	// there is nothing here to watch. Such a machine updates over the channel
	// instead (§3 of specs/agent_machine_posture_and_relay_converge.md); until
	// that ships it holds the version it was installed with, which is a state
	// the heartbeat reports rather than one that fails.
	if siteRoot != "" {
		cfg.AgentDistDir = filepath.Join(siteRoot, "public_html", "agent_dist")
	}
	if v := os.Getenv("AGENT_DIST_DIR"); v != "" {
		cfg.AgentDistDir = v
	}
	cfg.PlaneTLSInsecure = os.Getenv("JOINERY_PLANE_TLS_INSECURE") == "1"
	cfg.PolicyPath = getEnv("AGENT_POLICY_PATH", primitives.DefaultPolicyPath)
	if os.Getenv("AGENT_LOCAL_JOBS") == "0" {
		cfg.LocalJobs = false
	}

	if d, err := time.ParseDuration(os.Getenv("POLL_INTERVAL")); err == nil {
		cfg.PollInterval = d
	}
	if d, err := time.ParseDuration(os.Getenv("HEARTBEAT_INTERVAL")); err == nil {
		cfg.HeartbeatInterval = d
	}

	// A siteless machine has no database to name, and demanding one is what
	// used to park it in loadConfigWaiting's retry loop for ever — the loop is
	// right for a node whose config is briefly absent and fatal for a machine
	// where it is absent by design. Environment variables still win above, so
	// a siteless machine CAN be pointed at a database if it ever has a reason
	// to; it simply is not required to have one.
	if cfg.Siteless {
		cfg.LocalJobs = false // no plane-local queue without a plane-local database
		return cfg, nil
	}

	// Validate required fields
	if cfg.DBName == "" {
		return nil, fmt.Errorf("could not determine database name.\n"+
			"  The agent reads DB credentials from Globalvars_site.php automatically.\n"+
			"  Looked for: %s\n"+
			"  Either fix that path (set JOINERY_CONFIG env var) or set DB_NAME directly.", configPath)
	}
	if cfg.DBPassword == "" {
		return nil, fmt.Errorf("could not determine database password.\n"+
			"  The agent reads DB credentials from Globalvars_site.php automatically.\n"+
			"  Looked for: %s\n"+
			"  Either fix that path (set JOINERY_CONFIG env var) or set DB_PASSWORD directly.", configPath)
	}

	return cfg, nil
}

// parseGlobalvars reads a Joinery Globalvars_site.php file and extracts
// $this->settings['key'] = 'value' pairs. Returns a map of key→value.
// Only reads lines matching the settings pattern — ignores PHP logic.
func parseGlobalvars(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Match: $this->settings['dbname'] = 'value';
	// Captures the key (group 1) and value (group 2)
	re := regexp.MustCompile(`\$this->settings\['([^']+)'\]\s*=\s*'([^']*)'`)

	settings := make(map[string]string)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		matches := re.FindStringSubmatch(line)
		if len(matches) == 3 {
			settings[matches[1]] = matches[2]
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	if len(settings) == 0 {
		return nil, fmt.Errorf("no settings found in %s — file may be empty or in unexpected format", path)
	}

	return settings, nil
}

func getEnv(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}
