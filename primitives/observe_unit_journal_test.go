package primitives

import (
	"testing"
	"time"
)

// unit_journal is the gated script word with a closed unit list. The tests are
// about the shape its hostile-caller review relies on: that a unit outside the
// list cannot be named, that the line count is bounded, that the switch is
// declared, that what it prints is redacted, and that it starts the one
// shipped script.

func TestUnitJournalTakesOnlyAUnitFromTheList(t *testing.T) {
	p, ok := Lookup("unit_journal")
	if !ok {
		t.Fatal("unit_journal should be registered")
	}

	for _, unit := range unitJournalUnits {
		if _, err := Validate(p.Params, map[string]interface{}{"unit": unit}); err != nil {
			t.Errorf("%q is in the compiled list and must validate: %v", unit, err)
		}
	}

	// Everything an operator might reach for that is NOT on the list, and the
	// shapes an attacker would try. A unit name is not a string here; it is a
	// member of a set.
	for _, bad := range []string{
		"sshd",              // deliberately absent: who connected, from where
		"ssh",               //
		"mysql",             // plausible, not offered
		"man-db.service",    // the list holds names, not unit files
		"man-db ; rm -rf /", // there is no shell, and this is not a member either
		"../../etc/shadow",  //
		"*",                 //
		"",                  //
	} {
		if _, err := Validate(p.Params, map[string]interface{}{"unit": bad}); err == nil {
			t.Errorf("unit %q must be refused: the list is the whole vocabulary", bad)
		}
	}

	// A job with no unit at all is not a job that reads every unit.
	if _, err := Validate(p.Params, map[string]interface{}{}); err == nil {
		t.Error("unit is required; a missing one must refuse rather than default to something")
	}
}

func TestUnitJournalBoundsTheLineCount(t *testing.T) {
	p, _ := Lookup("unit_journal")
	ok := map[string]interface{}{"unit": "man-db", "lines": 200}
	if _, err := Validate(p.Params, ok); err != nil {
		t.Errorf("200 lines is the cap and must validate: %v", err)
	}
	for _, bad := range []interface{}{0, -1, 201, 100000} {
		if _, err := Validate(p.Params, map[string]interface{}{"unit": "man-db", "lines": bad}); err == nil {
			t.Errorf("lines=%v must be refused; the cap is %d", bad, unitJournalMaxLines)
		}
	}
	// Nothing else steers it: no window, no format, no path.
	for _, key := range []string{"since", "until", "format", "file", "path", "grep"} {
		if _, err := Validate(p.Params, map[string]interface{}{"unit": "man-db", key: "anything"}); err == nil {
			t.Errorf("a job carrying %q must be refused; there is no pass-through", key)
		}
	}
}

func TestUnitJournalIsGatedAndRedacted(t *testing.T) {
	p, _ := Lookup("unit_journal")

	if !p.RequiresLogAccess {
		t.Error("unit_journal reads a log: without the switch it would read one the owner had switched off")
	}
	if p.Script == nil || !p.Script.Redact {
		t.Error("the journal is text this node did not compose; it is masked here or it leaves unmasked")
	}
	if p.Class != ClassObserve {
		t.Errorf("unit_journal is observe, not %q — it reads, and clearing a unit is a different word", p.Class)
	}
	if p.Run != nil {
		t.Error("unit_journal must not carry an embedded Run beside its script")
	}
	if p.Script.ScriptPath != unitJournalScript {
		t.Errorf("should invoke the shipped reader %q, got %q", unitJournalScript, p.Script.ScriptPath)
	}
	if p.Script.Interpreter != "/bin/bash" {
		t.Errorf("the reader is a bash script; interpreter is %q", p.Script.Interpreter)
	}
	if p.Script.StdinFrom != nil || p.Script.ArgsFrom != nil {
		t.Error("argv is the fixed template; nothing composes it from the environment")
	}
	if len(p.Script.Args) != 2 || p.Script.Args[0] != "{unit}" || p.Script.Args[1] != "{lines}" {
		t.Errorf("argv should be the two validated slots, got %v", p.Script.Args)
	}
	if p.Timeout > time.Minute {
		t.Errorf("two local reads; a timeout of %v says otherwise", p.Timeout)
	}
}

// The list is a mirror in three places. This asserts the one property the
// mirroring is for: sshd is not readable through this word, whatever anybody
// adds later without reading the review.
func TestUnitJournalNeverOffersSshd(t *testing.T) {
	for _, unit := range unitJournalUnits {
		if unit == "sshd" || unit == "ssh" {
			t.Fatalf("%q is in the unit list: its journal is who connected and from where, "+
				"which host_report counts and refuses to quote", unit)
		}
	}
}
