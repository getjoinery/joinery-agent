package primitives

import (
	"testing"
	"time"
)

// never_do_check is a zero-parameter, read-only script word, like host_report.
// These pin the shape its hostile-caller review relies on.

func TestNeverDoCheckAsksForNothing(t *testing.T) {
	p, ok := Lookup("never_do_check")
	if !ok {
		t.Fatal("never_do_check should be registered")
	}
	if len(p.Params) != 0 {
		t.Fatalf("never_do_check declares %d parameter(s); it must declare none — "+
			"a path or a list here would be the plane steering what a root walk reads", len(p.Params))
	}
	for _, key := range []string{"path", "skip", "allow", "since", "file"} {
		if _, err := Validate(p.Params, map[string]interface{}{key: "anything"}); err == nil {
			t.Errorf("a job carrying %q must be refused; there is no pass-through", key)
		}
	}
	if _, err := Validate(p.Params, nil); err != nil {
		t.Errorf("a job with no parameters should validate: %v", err)
	}
}

func TestNeverDoCheckIsAReadOnlyScriptWord(t *testing.T) {
	p, _ := Lookup("never_do_check")
	if p.Class != ClassObserve {
		t.Errorf("never_do_check is observe, not %q", p.Class)
	}
	if !p.Machine {
		t.Error("never_do_check is about the machine, not a site")
	}
	if p.Script == nil || p.Run != nil {
		t.Fatal("never_do_check is a script word with no embedded Run")
	}
	if p.Script.ScriptPath != neverDoCheckScript {
		t.Errorf("should invoke %q, got %q", neverDoCheckScript, p.Script.ScriptPath)
	}
	if p.Script.Interpreter != "/bin/bash" {
		t.Errorf("interpreter is %q", p.Script.Interpreter)
	}
	if len(p.Script.Args) != 0 || p.Script.ArgsFrom != nil || p.Script.StdinFrom != nil {
		t.Error("no argv and no stdin: an element here is a place for a wire value to appear")
	}
	if p.Script.Redact {
		t.Error("the check prints only composed facts (paths, fingerprints, sizes); masking them hides nothing")
	}
	if p.RequiresLogAccess {
		t.Error("the check reads no site log")
	}
	if p.Timeout > 5*time.Minute {
		t.Errorf("the plane asks every five minutes; a timeout of %v overlaps the next ask", p.Timeout)
	}
}
