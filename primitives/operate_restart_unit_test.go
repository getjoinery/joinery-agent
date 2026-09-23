package primitives

import (
	"testing"
	"time"
)

// restart_unit and restart_container are the two repairs of service_health.
// The tests pin the shape their hostile-caller reviews rely on.

func TestRestartUnitTakesOnlyAnExpectedUnit(t *testing.T) {
	p, ok := Lookup("restart_unit")
	if !ok {
		t.Fatal("restart_unit should be registered")
	}
	for _, unit := range restartUnitUnits {
		if _, err := Validate(p.Params, map[string]interface{}{"unit": unit}); err != nil {
			t.Errorf("%q is an expected unit and must validate: %v", unit, err)
		}
	}
	for _, bad := range []string{"joinery-agent", "sshd", "ssh", "apache2.service", "php8.3-fpm", "cron; reboot", "*", ""} {
		if _, err := Validate(p.Params, map[string]interface{}{"unit": bad}); err == nil {
			t.Errorf("unit %q must be refused", bad)
		}
	}
	if _, err := Validate(p.Params, map[string]interface{}{}); err == nil {
		t.Error("unit is required")
	}
	if _, err := Validate(p.Params, map[string]interface{}{"unit": "cron", "verb": "stop"}); err == nil {
		t.Error("an undeclared key must be refused")
	}
}

// The agent is restarted only through restart_agent and its proof (rule 3).
func TestRestartUnitNeverNamesTheAgent(t *testing.T) {
	for _, u := range restartUnitUnits {
		if u == "joinery-agent" || u == "sshd" || u == "ssh" {
			t.Errorf("%q must never be restartable through restart_unit", u)
		}
	}
}

func TestRestartUnitShape(t *testing.T) {
	p, _ := Lookup("restart_unit")
	if p.Class != ClassOperate {
		t.Errorf("restart_unit is operate, not %q", p.Class)
	}
	if !p.Machine {
		t.Error("a Docker host runs fail2ban and cron too; restart_unit is a machine word")
	}
	if p.RequiresLogAccess || p.Run != nil || p.Script == nil || p.Script.Redact {
		t.Error("a script word that reads nothing: no log switch, no redaction, no embedded body")
	}
	if p.Script.ScriptPath != restartUnitScript || len(p.Script.Args) != 1 || p.Script.Args[0] != "{unit}" {
		t.Errorf("should run the shipped script with the one slot, got %q %v", p.Script.ScriptPath, p.Script.Args)
	}
	if p.Script.StdinFrom != nil || p.Script.ArgsFrom != nil {
		t.Error("argv is the fixed template")
	}
	if p.Timeout > 5*time.Minute {
		t.Errorf("timeout %v is longer than a restart", p.Timeout)
	}
}

func TestRestartContainerTakesOnlyASiteName(t *testing.T) {
	p, ok := Lookup("restart_container")
	if !ok {
		t.Fatal("restart_container should be registered")
	}
	for _, good := range []string{"joinerydemo", "site_2", "a-b"} {
		if _, err := Validate(p.Params, map[string]interface{}{"name": good}); err != nil {
			t.Errorf("%q is a site name and must validate: %v", good, err)
		}
	}
	for _, bad := range []string{"", "Site", "../x", "a b", "x;reboot", "--all", "averyveryveryveryveryveryveryveryveryverylongname51x"} {
		if _, err := Validate(p.Params, map[string]interface{}{"name": bad}); err == nil {
			t.Errorf("name %q must be refused", bad)
		}
	}
	if p.Class != ClassOperate || !p.Machine || p.Script == nil || p.Script.ScriptPath != restartContainerScript {
		t.Error("restart_container is an operate machine script word running the shipped script")
	}
	if len(p.Script.Args) != 1 || p.Script.Args[0] != "{name}" {
		t.Errorf("argv should be the one validated slot, got %v", p.Script.Args)
	}
}
