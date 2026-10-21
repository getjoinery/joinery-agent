package primitives

import (
	"testing"
	"time"
)

// install_security_updates installs what the machine's own policy allows, now.
// The tests pin the shape its hostile-caller review relies on: no parameter to
// name a package or an option, operate class, the one shipped script with no
// argv, a machine word, and nothing it prints that needs masking.

func TestInstallSecurityUpdatesTakesNothing(t *testing.T) {
	p, ok := Lookup("install_security_updates")
	if !ok {
		t.Fatal("install_security_updates should be registered")
	}
	if len(p.Params) != 0 {
		t.Fatalf("the word takes no parameters; the machine's policy decides what is installed, got %v", p.Params)
	}
	if _, err := Validate(p.Params, map[string]interface{}{}); err != nil {
		t.Errorf("an empty job must validate: %v", err)
	}
	for _, key := range []string{"package", "packages", "option", "args", "reboot", "upgrade"} {
		if _, err := Validate(p.Params, map[string]interface{}{key: "x"}); err == nil {
			t.Errorf("a job carrying %q must be refused; there is no pass-through", key)
		}
	}
}

func TestInstallSecurityUpdatesShape(t *testing.T) {
	p, _ := Lookup("install_security_updates")
	if p.Class != ClassOperate {
		t.Errorf("it changes what is installed; it is operate, not %q", p.Class)
	}
	if !p.Machine {
		t.Error("a siteless host needs its fixes too; it is a machine word")
	}
	if p.RequiresLogAccess {
		t.Error("it reads no log; asking for the owner's log switch would refuse a word that needs no leave")
	}
	if p.Run != nil || p.Script == nil {
		t.Fatal("install_security_updates is a script word and nothing else")
	}
	if p.Script.Redact {
		t.Error("it prints package names, versions and service names only; masking them would corrupt the answer")
	}
	if p.Script.ScriptPath != installSecurityUpdatesScript || p.Script.Interpreter != "/bin/bash" {
		t.Errorf("should invoke the shipped script under bash, got %q %q", p.Script.Interpreter, p.Script.ScriptPath)
	}
	if len(p.Script.Args) != 0 || p.Script.ArgsFrom != nil || p.Script.StdinFrom != nil {
		t.Error("the script takes no argv and no stdin")
	}
	// The script's own limits sum to 57 minutes; the agent's kill must come
	// after them, or it would cut a package install short.
	if p.Timeout < 58*time.Minute {
		t.Errorf("timeout %v is inside the script's own limits", p.Timeout)
	}
}
