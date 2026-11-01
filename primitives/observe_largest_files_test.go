package primitives

import (
	"testing"
	"time"
)

// largest_files names files, so its review rests on four things: it cannot be
// pointed anywhere, it runs only where the owner allows log access, what it
// prints is redacted, and it writes nothing.

func TestLargestFilesAsksForNothing(t *testing.T) {
	p, ok := Lookup("largest_files")
	if !ok {
		t.Fatal("largest_files should be registered")
	}
	if len(p.Params) != 0 {
		t.Fatalf("largest_files declares %d parameter(s); it must declare none — a path or a count "+
			"here would be the plane steering a root walk across the filesystem", len(p.Params))
	}
	for _, key := range []string{"path", "dir", "root", "count", "min_bytes", "site", "exclude"} {
		if _, err := Validate(p.Params, map[string]interface{}{key: "anything"}); err == nil {
			t.Errorf("a job carrying %q must be refused; the trees are the script's own site", key)
		}
	}
	if _, err := Validate(p.Params, nil); err != nil {
		t.Errorf("a job with no parameters is the only well-formed one: %v", err)
	}
}

func TestLargestFilesIsAGatedRedactedReadOnlyScriptWord(t *testing.T) {
	p, _ := Lookup("largest_files")

	if p.Class != ClassObserve {
		t.Errorf("largest_files is observe, not %q", p.Class)
	}
	if !p.RequiresLogAccess {
		t.Error("largest_files names files; a file name can say what somebody stored, so the " +
			"owner's log-access switch governs it")
	}
	if p.Machine {
		t.Error("largest_files walks a site; a machine with no site of its own has none to walk")
	}
	if p.Script == nil {
		t.Fatal("largest_files is a script word: only script.go may start a process, and this one needs find")
	}
	if p.Run != nil {
		t.Error("largest_files must not carry an embedded Run beside its script")
	}
	if p.Script.ScriptPath != largestFilesScript {
		t.Errorf("should invoke the shipped walker %q, got %q", largestFilesScript, p.Script.ScriptPath)
	}
	if len(p.Script.Args) != 0 || p.Script.ArgsFrom != nil {
		t.Errorf("argv should be empty, got %v", p.Script.Args)
	}
	if p.Script.StdinFrom != nil {
		t.Error("the walker reads no stdin")
	}
	if !p.Script.Redact {
		t.Error("file names are text the node did not compose; they go through the redactor")
	}
	if p.Timeout < 2*time.Minute || p.Timeout > 10*time.Minute {
		t.Errorf("a timeout of %v is outside two to ten minutes", p.Timeout)
	}
}
