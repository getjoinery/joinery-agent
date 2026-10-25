package primitives

import "testing"

// disable_root_login takes nothing, is an operate machine word, and runs its
// shipped script with no argv and no stdin (specs/implemented/beta_break_glass_root_access.md 5.3).
func TestDisableRootLoginTakesNothingAndRunsItsScript(t *testing.T) {
	p, ok := Lookup("disable_root_login")
	if !ok {
		t.Fatal("disable_root_login should be registered")
	}
	if p.Class != ClassOperate {
		t.Errorf("disable_root_login is operate, not %q", p.Class)
	}
	if !p.Machine {
		t.Error("a Docker host has an sshd too; disable_root_login is a machine word")
	}
	if len(p.Params) != 0 {
		t.Errorf("disable_root_login takes no parameters, got %d", len(p.Params))
	}
	if p.Script == nil || p.Script.ScriptPath != "maintenance_scripts/sysadmin_tools/disable_root_login.sh" {
		t.Fatalf("disable_root_login runs disable_root_login.sh, got %+v", p.Script)
	}
	if len(p.Script.Args) != 0 || p.Script.StdinFrom != nil {
		t.Error("disable_root_login.sh is given no argv and no stdin")
	}
}
