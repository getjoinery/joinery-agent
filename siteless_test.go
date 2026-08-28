package main

import (
	"os"
	"path/filepath"
	"testing"
)

// Machine posture (spec A13): the agent runs on machines that host no Joinery
// site. These tests pin the distinction the whole posture rests on — a site
// config that is ABSENT is a posture, one that is UNREADABLE is an outage —
// because getting it the wrong way round fails in opposite and equally bad
// directions: a relay wedged in a retry loop for ever, or a node mid-upgrade
// quietly deciding it has no site and abandoning that site's work.

func withConfigPath(t *testing.T, path string) {
	t.Helper()
	old, had := os.LookupEnv("JOINERY_CONFIG")
	os.Setenv("JOINERY_CONFIG", path)
	t.Cleanup(func() {
		if had {
			os.Setenv("JOINERY_CONFIG", old)
		} else {
			os.Unsetenv("JOINERY_CONFIG")
		}
	})
	// The env fallbacks would otherwise supply what the file did not, and the
	// test would be measuring the environment rather than the config.
	for _, key := range []string{"DB_NAME", "DB_PASSWORD", "DB_USER", "AGENT_DIST_DIR"} {
		if v, ok := os.LookupEnv(key); ok {
			os.Unsetenv(key)
			k, val := key, v
			t.Cleanup(func() { os.Setenv(k, val) })
		}
	}
}

func TestNoSiteConfigIsAPostureNotAnError(t *testing.T) {
	withConfigPath(t, filepath.Join(t.TempDir(), "there", "is", "no", "Globalvars_site.php"))

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("a machine with no site must start, not error: %v", err)
	}
	if !cfg.Siteless {
		t.Error("a missing site config should set the siteless posture")
	}
}

func TestASitelessMachineInventsNoPaths(t *testing.T) {
	// The failure this prevents is subtle: filepath.Join("", "public_html")
	// yields the RELATIVE path "public_html", which resolves against whatever
	// directory the agent happens to have been started in. A script primitive
	// would then verify a file in a tree nobody meant.
	withConfigPath(t, filepath.Join(t.TempDir(), "nothing", "Globalvars_site.php"))

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]string{
		"SiteRoot":     cfg.SiteRoot,
		"WebRoot":      cfg.WebRoot,
		"AgentDistDir": cfg.AgentDistDir,
	} {
		if value != "" {
			t.Errorf("%s is %q on a machine with no site; it must be empty, "+
				"and never a relative path", name, value)
		}
	}
	if cfg.LocalJobs {
		t.Error("a machine with no database cannot serve a plane-local job queue")
	}
}

func TestAnUnreadableSiteConfigIsNotASitelessMachine(t *testing.T) {
	// The other half of the distinction, and the one that would be dangerous
	// to get wrong: a node mid-upgrade or mid-restore has a config file that is
	// briefly unreadable. It must keep waiting for its own site, never decide
	// it has become a relay.
	dir := t.TempDir()
	path := filepath.Join(dir, "Globalvars_site.php")
	if err := os.WriteFile(path, []byte("<?php // no settings at all\n"), 0o000); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root: an unreadable file is still readable, so this distinction cannot be exercised")
	}
	withConfigPath(t, path)

	cfg, err := LoadConfig()
	if err == nil && cfg.Siteless {
		t.Error("an unreadable config must not read as 'this machine has no site' — " +
			"that turns a transient outage into an agent that abandons its own site's work")
	}
}

func TestAPresentButIncompleteConfigStillFails(t *testing.T) {
	// A config that exists and names no database is a broken node, not a
	// siteless machine. It must still produce the actionable error, because
	// the operator has something to fix.
	dir := t.TempDir()
	path := filepath.Join(dir, "Globalvars_site.php")
	if err := os.WriteFile(path, []byte("<?php // present, but names nothing\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	withConfigPath(t, path)

	if _, err := LoadConfig(); err == nil {
		t.Error("a site config that exists but names no database should still be an error to fix")
	}
}

func TestASiteHavingMachineIsUnchanged(t *testing.T) {
	// The regression guard for the nine nodes in the field: none of them needs
	// any of this, and all of them must behave exactly as before.
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "config"), 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "config", "Globalvars_site.php")
	body := "<?php\n" +
		"$this->settings['dbname'] = 'joinerytest';\n" +
		"$this->settings['dbusername'] = 'postgres';\n" +
		"$this->settings['dbpassword'] = 'secret';\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	withConfigPath(t, path)

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("a normal site config must still load: %v", err)
	}
	if cfg.Siteless {
		t.Fatal("a machine with a site must not be in machine posture")
	}
	if cfg.SiteRoot != root {
		t.Errorf("SiteRoot is %q, want %q", cfg.SiteRoot, root)
	}
	if want := filepath.Join(root, "public_html"); cfg.WebRoot != want {
		t.Errorf("WebRoot is %q, want %q", cfg.WebRoot, want)
	}
	if want := filepath.Join(root, "public_html", "agent_dist"); cfg.AgentDistDir != want {
		t.Errorf("AgentDistDir is %q, want %q", cfg.AgentDistDir, want)
	}
	if !cfg.LocalJobs {
		t.Error("a site-having machine still probes for its local job queue")
	}
}

// --- CLI -------------------------------------------------------------------

func TestTheCLIHandlesOnlyItsOwnSubcommands(t *testing.T) {
	// Anything else must fall through to starting the service. A binary that
	// swallowed an unknown argument would be a supervisor launching an agent
	// that silently exits.
	for _, args := range [][]string{
		{"joinery-agent"},
		{"joinery-agent", "--policy=/etc/whatever"},
		{"joinery-agent", "serve"},
	} {
		if handled, _ := runCLI(args); handled {
			t.Errorf("%v should start the service, not be handled as a subcommand", args[1:])
		}
	}

	for _, name := range []string{"join", "status", "leave", "enable", "disable", "help", "--version"} {
		if handled, _ := runCLI([]string{"joinery-agent", name}); !handled {
			t.Errorf("%q should be handled as a subcommand", name)
		}
	}
}

func TestJoinRefusesWithoutAManagementNode(t *testing.T) {
	if code := cliJoin(nil); code == 0 {
		t.Error("join with no management node should fail, not silently do nothing")
	}
	if code := cliJoin([]string{"--management-node=plane.example.com"}); code == 0 {
		t.Error("a management node without a scheme should be refused rather than guessed at")
	}
	if code := cliJoin([]string{"--nonsense"}); code == 0 {
		t.Error("an unrecognised argument should be refused, not ignored")
	}
}

func TestTheSwitchIsWrittenWhereTheSupervisorReadsIt(t *testing.T) {
	// On a siteless machine this marker is the truth rather than a projection
	// of a settings row, because there is no settings table to project from.
	// The keepalive and the installer both read this exact file.
	dir := t.TempDir()
	t.Setenv("AGENT_STATE_DIR", dir)
	if filepath.Dir(markerPath()) != dir {
		t.Skipf("agent state dir is not overridable in this build (marker at %s)", markerPath())
	}

	if code := cliSwitch(true); code != 0 {
		t.Fatalf("enable failed with code %d", code)
	}
	if !markerSaysRun() {
		t.Error("after enable, the marker should read as on")
	}

	if code := cliSwitch(false); code != 0 {
		t.Fatalf("disable failed with code %d", code)
	}
	if markerSaysRun() {
		t.Error("after disable, the marker should read as off")
	}
}
