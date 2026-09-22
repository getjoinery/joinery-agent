package primitives

import (
	"testing"
	"time"
)

// disk_usage is the second zero-parameter script word. Its review rests on
// three things: it cannot be pointed anywhere, it needs no owner switch
// because it reads no content, and it is allowed to be slow.

func TestDiskUsageAsksForNothing(t *testing.T) {
	p, ok := Lookup("disk_usage")
	if !ok {
		t.Fatal("disk_usage should be registered")
	}
	if len(p.Params) != 0 {
		t.Fatalf("disk_usage declares %d parameter(s); it must declare none — a path, a depth "+
			"or a count here would be the plane steering a root process across the filesystem", len(p.Params))
	}
	for _, key := range []string{"path", "dir", "depth", "max_depth", "entries", "root", "exclude"} {
		if _, err := Validate(p.Params, map[string]interface{}{key: "anything"}); err == nil {
			t.Errorf("a job carrying %q must be refused; the tree and the machine list are compiled", key)
		}
	}
	if _, err := Validate(p.Params, nil); err != nil {
		t.Errorf("a job with no parameters is the only well-formed one: %v", err)
	}
}

func TestDiskUsageIsAnUngatedReadOnlyScriptWord(t *testing.T) {
	p, _ := Lookup("disk_usage")

	if p.Class != ClassObserve {
		t.Errorf("disk_usage is observe, not %q", p.Class)
	}
	if p.Script == nil {
		t.Fatal("disk_usage is a script word: only script.go may start a process, and this one needs du")
	}
	if p.Run != nil {
		t.Error("disk_usage must not carry an embedded Run beside its script")
	}
	if p.Script.ScriptPath != diskUsageScript {
		t.Errorf("should invoke the shipped walker %q, got %q", diskUsageScript, p.Script.ScriptPath)
	}
	if len(p.Script.Args) != 0 || p.Script.ArgsFrom != nil {
		t.Errorf("argv should be empty, got %v", p.Script.Args)
	}
	if p.Script.StdinFrom != nil {
		t.Error("the walker reads no stdin")
	}

	// No switch, and that is a decision rather than an omission: the word
	// reports the SIZE of directories and never their contents, so there is
	// nothing here the owner's log-access switch is about.
	if p.RequiresLogAccess {
		t.Error("disk_usage reads no log and no content; gating it behind the log switch would " +
			"make a size report look like a content read")
	}
	if p.Script.Redact {
		t.Error("every string this word prints is a path it reduced itself; masking a byte count " +
			"would corrupt an answer to hide nothing")
	}

	// Allowed to be slow, and bounded anyway: du over a large tree on a small
	// box is minutes on a cold cache, which is exactly the machine that needs
	// the answer.
	if p.Timeout < 2*time.Minute {
		t.Errorf("a timeout of %v will fail on the machine this word exists for", p.Timeout)
	}
	if p.Timeout > 10*time.Minute {
		t.Errorf("a timeout of %v leaves a root walk running long after anyone is waiting", p.Timeout)
	}
}
