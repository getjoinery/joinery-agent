package main

import (
	"testing"
	"time"
)

// The poll's self-update report (spec release_transparency, O7): nothing until
// a check concludes, then the version on offer and the verdict, with nothing
// on offer said as "none" so it clears a refusal the plane holds.
func TestUpdateReportSaysNothingBeforeTheFirstCheck(t *testing.T) {
	u := &Updater{}
	if _, _, ok := u.UpdateReport(); ok {
		t.Fatal("a fresh start reports nothing")
	}
}

// moveReportClock moves the report clock by d for the rest of the test.
func moveReportClock(t *testing.T, d time.Duration) {
	at := reportClock().Add(d)
	saved := reportClock
	reportClock = func() time.Time { return at }
	t.Cleanup(func() { reportClock = saved })
}

func TestUpdateReportCarriesTheVerdict(t *testing.T) {
	u := &Updater{}
	u.setState("1.66.0", updateStateUnlogged)
	moveReportClock(t, unloggedReportGrace+time.Minute)
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

// Publish writes the binaries before the statement that records them (review
// B1a): an unlogged verdict is held back for the publish window, so the plane
// does not open a critical incident on every publish, and reported once it
// has stood longer than any publish takes.
func TestAnUnloggedVerdictIsReportedOnlyOnceItHasStood(t *testing.T) {
	u := &Updater{}
	u.setState("1.66.0", updateStateCurrent)
	u.setState("1.67.0", updateStateUnlogged)
	if _, _, ok := u.UpdateReport(); ok {
		t.Fatalf("a fresh unlogged verdict must leave the last answer standing")
	}
	moveReportClock(t, unloggedReportGrace-time.Minute)
	u.setState("1.67.0", updateStateUnlogged) // the next check, same verdict: the clock does not restart
	if _, _, ok := u.UpdateReport(); ok {
		t.Fatalf("still inside the grace")
	}
	moveReportClock(t, 2*time.Minute)
	if _, state, ok := u.UpdateReport(); !ok || state != updateStateUnlogged {
		t.Fatalf("past the grace it must be reported; got %q %v", state, ok)
	}
	u.setState("1.67.0", updateStateCurrent)
	if _, state, ok := u.UpdateReport(); !ok || state != updateStateCurrent {
		t.Fatalf("an install reports at once; got %q %v", state, ok)
	}
}

func TestAnUnloggedBundleIsReportedOnlyOnceItHasStood(t *testing.T) {
	b := &BundleSync{warned: map[string]bool{}}
	b.setState(bundleStateUnlogged)
	if _, ok := b.Report(); ok {
		t.Fatalf("a fresh unlogged bundle must leave the last answer standing")
	}
	moveReportClock(t, unloggedReportGrace+time.Minute)
	if state, ok := b.Report(); !ok || state != bundleStateUnlogged {
		t.Fatalf("past the grace it must be reported; got %q %v", state, ok)
	}
	b.setState(bundleStateVerifyFailed)
	if state, ok := b.Report(); !ok || state != bundleStateVerifyFailed {
		t.Fatalf("a failed verification has no publish window and reports at once; got %q %v", state, ok)
	}
}
