package primitives

import (
	"testing"
	"time"
)

func TestUnbanAddressTakesAJailAndAnAddress(t *testing.T) {
	p, ok := Lookup("unban_address")
	if !ok {
		t.Fatal("unban_address should be registered")
	}
	for _, good := range []map[string]interface{}{
		{"jail": "apache-badbots", "address": "203.0.113.9"},
		{"jail": "sshd", "address": "2001:db8::9"},
		{"jail": "recidive", "address": "::1"},
		{"jail": "sshd", "address": "::ffff:192.0.2.1"},
	} {
		if _, err := Validate(p.Params, good); err != nil {
			t.Errorf("%v must validate: %v", good, err)
		}
	}
	for _, bad := range []map[string]interface{}{
		{"jail": "sshd"},
		{"address": "203.0.113.9"},
		{"jail": "--all", "address": "203.0.113.9"},
		{"jail": "sshd; reboot", "address": "203.0.113.9"},
		{"jail": "sshd", "address": "--all"},
		{"jail": "sshd", "address": "203.0.113.9 --all"},
		{"jail": "sshd", "address": "203.0.113.0/24"},
		{"jail": "sshd", "address": "example.com"},
		{"jail": "sshd", "address": ""},
		{"jail": "sshd", "address": "203.0.113.9", "action": "banip"},
	} {
		if _, err := Validate(p.Params, bad); err == nil {
			t.Errorf("%v must be refused", bad)
		}
	}
}

func TestUnbanAddressShape(t *testing.T) {
	p, _ := Lookup("unban_address")
	if p.Class != ClassOperate {
		t.Errorf("unban_address is operate, not %q", p.Class)
	}
	if !p.Machine {
		t.Error("a Docker host runs fail2ban too; unban_address is a machine word")
	}
	if p.RequiresLogAccess || p.Run != nil || p.Script == nil || p.Script.Redact {
		t.Error("a script word that reads nothing: no log switch, no redaction, no embedded body")
	}
	if p.Script.ScriptPath != unbanAddressScript || len(p.Script.Args) != 2 || p.Script.Args[0] != "{jail}" || p.Script.Args[1] != "{address}" {
		t.Errorf("should run the shipped script with the two slots, got %q %v", p.Script.ScriptPath, p.Script.Args)
	}
	if p.Script.StdinFrom != nil || p.Script.ArgsFrom != nil {
		t.Error("argv is the fixed template")
	}
	if p.Timeout > 5*time.Minute {
		t.Error("two bounded fail2ban-client calls need no more than minutes")
	}
}
