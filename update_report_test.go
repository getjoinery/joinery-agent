package main

import "testing"

// The poll's self-update report (spec release_transparency, O7): nothing until
// a check concludes, then the version on offer and the verdict, with nothing
// on offer said as "none" so it clears a refusal the plane holds.
func TestUpdateReportSaysNothingBeforeTheFirstCheck(t *testing.T) {
	u := &Updater{}
	if _, _, ok := u.UpdateReport(); ok {
		t.Fatal("a fresh start reports nothing")
	}
}

func TestUpdateReportCarriesTheVerdict(t *testing.T) {
	u := &Updater{}
	u.setState("1.66.0", updateStateUnlogged)
	offered, state, ok := u.UpdateReport()
	if !ok || offered != "1.66.0" || state != updateStateUnlogged {
		t.Fatalf("got %q %q %v", offered, state, ok)
	}
	u.setState("", "")
	offered, state, ok = u.UpdateReport()
	if !ok || offered != "" || state != updateStateNone {
		t.Fatalf("nothing on offer reports none; got %q %q %v", offered, state, ok)
	}
}
