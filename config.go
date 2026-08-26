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

	// PlaneURL and PairingToken drive first-run enrollment in node posture. Both
	// come from the env file; the token is single-use and is stripped from that
	// file as soon as it has been spent.
	PlaneURL     string
	PairingToken string
	// PlaneTLSInsecure is for a plane behind a self-signed certificate.
	PlaneTLSInsecure bool

	// PolicyPath is the root-owned acceptance policy (§3.3).
	PolicyPath string

	// LocalJobs is whether this agent also serves the plane-local job queue in
	// its own database. True everywhere by default. A node that is purely a
	// managed node — no control plane on it — has no plane-local work, and
	// turning this off makes that explicit rather than leaving the agent
	// polling a queue that is not its business.
	LocalJobs bool

	// AgentDistDir is where platform releases deliver the shipped agent
	// artifact (manifest.json + signed binaries). Derived from the site tree
	// that JOINERY_CONFIG points into; override with AGENT_DIST_DIR.
	AgentDistDir string
}

// Default path to the Joinery config file. Override with JOINERY_CONFIG env var.
const defaultJoineryConfig = "/var/www/html/joinerytest/config/Globalvars_site.php"

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
	configPath := getEnv("JOINERY_CONFIG", defaultJoineryConfig)
	phpSettings, err := parseGlobalvars(configPath)
	if err != nil {
		log.Printf("NOTE: Could not read Joinery config at %s: %v", configPath, err)
		log.Printf("  Falling back to environment variables / env file.")
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

	// agent_dist lives inside the public_html tree of the site whose config
	// we read: {site root}/config/Globalvars_site.php →
	// {site root}/public_html/plugins/server_manager/agent_dist
	siteRoot := filepath.Dir(filepath.Dir(configPath))
	cfg.SiteRoot = siteRoot
	cfg.WebRoot = filepath.Join(siteRoot, "public_html")
	cfg.AgentDistDir = filepath.Join(siteRoot, "public_html", "plugins", "server_manager", "agent_dist")
	if v := os.Getenv("AGENT_DIST_DIR"); v != "" {
		cfg.AgentDistDir = v
	}
	cfg.PlaneURL = strings.TrimRight(os.Getenv("JOINERY_PLANE_URL"), "/")
	cfg.PairingToken = os.Getenv("JOINERY_PAIRING_TOKEN")
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
