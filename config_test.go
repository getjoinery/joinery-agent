package main

import (
	"os"
	"path/filepath"
	"testing"
)

// The CLI and the daemon must find the site the same way: the environment
// variable first, then the unit's environment file, then the default.
func TestJoineryConfigPathReadsTheUnitEnvironmentFile(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, "joinery-agent.env")
	restoreFile := agentEnvFile
	agentEnvFile = envPath
	t.Cleanup(func() { agentEnvFile = restoreFile })
	t.Setenv("JOINERY_CONFIG", "")

	if got := joineryConfigPath(); got != defaultJoineryConfig {
		t.Fatalf("no variable, no file: expected the default %q, got %q", defaultJoineryConfig, got)
	}

	body := "# written by install_agent.sh\nAGENT_NAME=x\nJOINERY_CONFIG=\"/var/www/html/keyless9/config/Globalvars_site.php\"\n"
	if err := os.WriteFile(envPath, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	if got := joineryConfigPath(); got != "/var/www/html/keyless9/config/Globalvars_site.php" {
		t.Fatalf("the unit's environment file names the site: got %q", got)
	}

	t.Setenv("JOINERY_CONFIG", "/srv/other/config/Globalvars_site.php")
	if got := joineryConfigPath(); got != "/srv/other/config/Globalvars_site.php" {
		t.Fatalf("an explicit variable wins over the file: got %q", got)
	}
}

func TestEnvFileValueParsesLikeSystemd(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "env")
	body := "\n# comment\nA=1\nB='two words'\nC = spaced\nA=override\n"
	if err := os.WriteFile(p, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{"A": "override", "B": "two words", "C": "spaced", "D": ""}
	for k, want := range cases {
		if got := envFileValue(p, k); got != want {
			t.Errorf("%s: want %q got %q", k, want, got)
		}
	}
	if got := envFileValue(filepath.Join(dir, "missing"), "A"); got != "" {
		t.Errorf("a missing file reads as empty, got %q", got)
	}
}
