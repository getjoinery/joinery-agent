package primitives

import (
	"testing"
	"time"
)

// reset_failed_unit changes what the machine says about itself, from the same
// closed list unit_journal reads. The tests pin the shape its hostile-caller
// review relies on: only a listed unit, never "all units", operate class, the
// one shipped script with one validated argument, and nothing it prints that
// needs masking.

func TestResetFailedUnitTakesOnlyAUnitFromTheList(t *testing.T) {
	p, ok := Lookup("reset_failed_unit")
	if !ok {
		t.Fatal("reset_failed_unit should be registered")
	}
	for _, unit := range unitJournalUnits {
		if _, err := Validate(p.Params, map[string]interface{}{"unit": unit}); err != nil {
			t.Errorf("%q is in the compiled list and must validate: %v", unit, err)
		}
	}
	for _, bad := range []string{"sshd", "mysql", "man-db.service", "man-db ; reboot", "*", "", "--all"} {
		if _, err := Validate(p.Params, map[string]interface{}{"unit": bad}); err == nil {
			t.Errorf("unit %q must be refused: the list is the whole vocabulary", bad)
		}
	}
	// No unit is not "every unit": systemctl reset-failed with no argument
	// clears the whole machine, and this word must never be that.
	if _, err := Validate(p.Params, map[string]interface{}{}); err == nil {
		t.Error("unit is required; a missing one must refuse")
	}
	for _, key := range []string{"lines", "all", "path", "verb"} {
		if _, err := Validate(p.Params, map[string]interface{}{"unit": "man-db", key: "x"}); err == nil {
			t.Errorf("a job carrying %q must be refused; there is no pass-through", key)
		}
	}
}

// The unit that can be asked why is the unit that can be cleared: one list.
func TestResetFailedUnitSharesUnitJournalsList(t *testing.T) {
	reset, _ := Lookup("reset_failed_unit")
	journal, _ := Lookup("unit_journal")
	var a, b []string
	for _, ps := range reset.Params {
		if ps.Name == "unit" {
			a = ps.Values
		}
	}
	for _, ps := range journal.Params {
		if ps.Name == "unit" {
			b = ps.Values
		}
	}
	if len(a) == 0 || len(a) != len(b) {
		t.Fatalf("the two words must offer the same units: %v vs %v", a, b)
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("unit lists diverge at %d: %q vs %q", i, a[i], b[i])
		}
	}
}

func TestResetFailedUnitShape(t *testing.T) {
	p, _ := Lookup("reset_failed_unit")
	if p.Class != ClassOperate {
		t.Errorf("reset_failed_unit changes what the machine reports; it is operate, not %q", p.Class)
	}
	if p.RequiresLogAccess {
		t.Error("it reads no log; asking for the owner's log switch would refuse a word that needs no leave")
	}
	if p.Run != nil || p.Script == nil {
		t.Fatal("reset_failed_unit is a script word and nothing else")
	}
	if p.Script.Redact {
		t.Error("it prints compiled states only; masking them would corrupt the answer to hide nothing")
	}
	if p.Script.ScriptPath != resetFailedUnitScript || p.Script.Interpreter != "/bin/bash" {
		t.Errorf("should invoke the shipped script under bash, got %q %q", p.Script.Interpreter, p.Script.ScriptPath)
	}
	if len(p.Script.Args) != 1 || p.Script.Args[0] != "{unit}" {
		t.Errorf("argv should be the one validated slot, got %v", p.Script.Args)
	}
	if p.Script.StdinFrom != nil || p.Script.ArgsFrom != nil {
		t.Error("argv is the fixed template; nothing composes it from the environment")
	}
	if p.Timeout > 5*time.Minute {
		t.Errorf("three systemctl calls; a timeout of %v says otherwise", p.Timeout)
	}
}
