package primitives

import (
	"context"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
)

// A script that runs as the site user starts in that user's home, never in
// the agent's own working directory.
//
// Why it matters: the agent runs from /root, which the site user cannot
// enter. A child left there fails whatever needs its starting directory back:
// find exits 1 with "Failed to restore initial working directory", and that
// failed every incremental backup on a Starter host at its code-tree check.
// The fixture puts the agent in a directory only root may enter, then runs a
// site-user script that calls find.
func TestASiteUserScriptStartsInItsOwnHome(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("dropping to the site user needs root")
	}
	if _, err := user.Lookup(siteUserName); err != nil {
		t.Skipf("this machine has no %s account", siteUserName)
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	rel := "maintenance_scripts/sysadmin_tools/report_dir.sh"
	full := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/bash\npwd\nfind \"$(pwd)\" -maxdepth 0 >/dev/null && echo FIND_OK\n"
	if err := os.WriteFile(full, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	locked := filepath.Join(t.TempDir(), "root_only")
	if err := os.Mkdir(locked, 0o700); err != nil {
		t.Fatal(err)
	}
	was, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(locked); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(was)

	p := Primitive{
		Name:   "proof_only_site_user_dir",
		Class:  ClassOperate,
		Script: &ScriptSpec{Interpreter: "/bin/bash", ScriptPath: rel, AsSiteUser: true},
	}
	env := &ExecEnv{SiteRoot: root, Manifest: &recordingVerifier{accept: full}}
	out, err := runScriptPrimitive(context.Background(), env, p, Params{})
	if err != nil {
		t.Fatalf("the script should have run: %v (output %v)", err, out["output"])
	}
	text, _ := out["output"].(string)
	_, home, _ := siteUserCredential()
	lines := strings.Split(strings.TrimSpace(text), "\n")
	if len(lines) == 0 || lines[0] != home {
		t.Errorf("the script started in %q, want the site user's home %q", lines[0], home)
	}
	if !strings.Contains(text, "FIND_OK") {
		t.Errorf("find failed in the site user's script: %q", text)
	}
}
