package primitives

import (
	"testing"
	"time"
)

// host_report is the zero-parameter, read-only script word. The tests are about
// the shape the hostile-caller review in its header relies on: that it asks for
// nothing, that nothing the plane sends is accepted, that it runs the one
// shipped script with no argv and no stdin, and that it is short.

func TestHostReportAsksForNothing(t *testing.T) {
	p, ok := Lookup("host_report")
	if !ok {
		t.Fatal("host_report should be registered")
	}
	if len(p.Params) != 0 {
		t.Fatalf("host_report declares %d parameter(s); it must declare none — "+
			"a unit name, a jail or a line count here would be the plane steering a root process", len(p.Params))
	}
}

func TestNothingThePlaneSendsReachesHostReport(t *testing.T) {
	p, _ := Lookup("host_report")
	for _, key := range []string{
		"unit",   // "just this unit's state"
		"jail",   //
		"lines",  // a journal length
		"since",  // a journal window
		"file",   // "read this file for me"
		"format", //
	} {
		if _, err := Validate(p.Params, map[string]interface{}{key: "anything"}); err == nil {
			t.Errorf("a job carrying %q must be refused; there is no pass-through", key)
		}
	}
	if _, err := Validate(p.Params, nil); err != nil {
		t.Errorf("a job with no parameters is the only well-formed one, and it should validate: %v", err)
	}
}

func TestHostReportIsAShortReadOnlyScriptWord(t *testing.T) {
	p, _ := Lookup("host_report")

	if p.Class != ClassObserve {
		t.Errorf("host_report is observe, not %q — a node accepting only observe words must be able to run it", p.Class)
	}
	if p.Script == nil {
		t.Fatal("host_report is a script word: only script.go may start a process, and the report needs systemctl, fail2ban-client, sshd -T and journalctl")
	}
	if p.Run != nil {
		t.Error("host_report must not carry an embedded Run beside its script")
	}
	if p.Script.ScriptPath != hostReportScript {
		t.Errorf("should invoke the shipped report %q, got %q", hostReportScript, p.Script.ScriptPath)
	}
	if p.Script.Interpreter != "/bin/bash" {
		t.Errorf("the report is a bash script; interpreter is %q", p.Script.Interpreter)
	}
	if len(p.Script.Args) != 0 || p.Script.ArgsFrom != nil {
		t.Errorf("argv should be empty, got %v — an element here is a place for a wire value to appear", p.Script.Args)
	}
	if p.Script.StdinFrom != nil {
		t.Error("the report reads no stdin; supplying one opens a channel nothing needs")
	}
	if p.Timeout > time.Minute {
		t.Errorf("host_report is cheap enough to run every tick; a timeout of %v says otherwise", p.Timeout)
	}
}
