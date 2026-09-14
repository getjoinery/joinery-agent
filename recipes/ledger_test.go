package recipes

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func tempLedger(t *testing.T) func() time.Time {
	t.Helper()
	root := t.TempDir()
	restoreLedger, restoreOut := LedgerDir, OutwardDir
	LedgerDir = filepath.Join(root, "ledger")
	OutwardDir = ""
	t.Cleanup(func() { LedgerDir, OutwardDir = restoreLedger, restoreOut })
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	return func() time.Time { return now }
}

func TestTheLedgerIsCappedAndStillReadsBackAfterATrim(t *testing.T) {
	now := tempLedger(t)
	led, err := openLedger("probe", now)
	if err != nil {
		t.Fatal(err)
	}
	// Enough lines to pass the cap several times over; each is ~150 bytes.
	for i := 0; i < 4000; i++ {
		led.note(Entry{Event: EventCheck, Verdict: Fail, Reason: strings.Repeat("x", 100)})
	}
	id := led.beginAttempt("host_converge", ModeArmed)
	led.endAttempt(id, OutcomeFailed, "still down")
	led.openEscalation("three attempts")

	info, err := os.Stat(led.path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() > LedgerMaxBytes {
		t.Fatalf("the ledger grew to %d bytes, past the %d cap", info.Size(), LedgerMaxBytes)
	}
	raw, _ := os.ReadFile(led.path)
	if !strings.HasPrefix(string(raw), "{") {
		t.Error("a trim should cut on a line boundary, so the file starts with a whole line")
	}

	// A second process reads the newest state back through the trimmed file.
	again, err := openLedger("probe", now)
	if err != nil {
		t.Fatal(err)
	}
	if again.OpenEscalation() == 0 {
		t.Error("the open escalation survived the trim in the file but not the read-back")
	}
	if got := again.AttemptsSince(now().Add(-time.Hour)); len(got) != 1 || got[0].Outcome != OutcomeFailed {
		t.Errorf("the attempt and its outcome should read back, got %+v", got)
	}
	if _, err := os.Stat(led.path + ".tmp"); !os.IsNotExist(err) {
		t.Error("the trim left its temp file behind")
	}
}

func TestADamagedLineIsSkippedNotFatal(t *testing.T) {
	now := tempLedger(t)
	led, err := openLedger("probe", now)
	if err != nil {
		t.Fatal(err)
	}
	id := led.beginAttempt("host_converge", ModeArmed)
	f, _ := os.OpenFile(led.path, os.O_APPEND|os.O_WRONLY, 0o600)
	f.WriteString("this is not json\n{\"half\":\n")
	f.Close()
	led.endAttempt(id, OutcomeRepaired, "")

	again, err := openLedger("probe", now)
	if err != nil {
		t.Fatalf("a damaged line must not stop the ledger reading: %v", err)
	}
	got := again.AttemptsSince(now().Add(-time.Hour))
	if len(got) != 1 || got[0].Outcome != OutcomeRepaired {
		t.Errorf("the lines around the damage should still read, got %+v", got)
	}
}

func TestFreeTextInALineIsBounded(t *testing.T) {
	now := tempLedger(t)
	led, err := openLedger("probe", now)
	if err != nil {
		t.Fatal(err)
	}
	id := led.beginAttempt("host_converge", ModeArmed)
	led.endAttempt(id, OutcomeFailed, strings.Repeat("t", 100*1024))
	info, _ := os.Stat(led.path)
	if info.Size() > 2*maxDetailBytes {
		t.Errorf("a transcript-sized detail reached the ledger: %d bytes", info.Size())
	}
}

func TestAnAttemptIsWrittenBeforeItsOutcome(t *testing.T) {
	// The line exists from the moment the attempt starts, so a repair that
	// kills the agent has already been counted.
	now := tempLedger(t)
	led, err := openLedger("probe", now)
	if err != nil {
		t.Fatal(err)
	}
	led.beginAttempt("host_converge", ModeArmed)
	entries := readEntries(t, led.path)
	if len(entries) != 1 || entries[0].Event != EventAttempt || entries[0].Word != "host_converge" {
		t.Fatalf("the attempt line should be on disk before the repair runs, got %+v", entries)
	}
	again, _ := openLedger("probe", now)
	if n := again.finishInterrupted(); n != 1 {
		t.Errorf("a new process should find one unfinished attempt, found %d", n)
	}
	if again.finishInterrupted() != 0 {
		t.Error("finishing is idempotent")
	}
}

func TestAnEscalationOlderThanTheTrimIsStillOpenOnReadBack(t *testing.T) {
	// An escalation held open for weeks takes a note every failing tick, and
	// the notes alone push its opening line out of the newest half of the
	// cap. The notes carry its id, and an escalation takes notes only while
	// it is open, so the read-back must recover it from them.
	now := tempLedger(t)
	led, err := openLedger("probe", now)
	if err != nil {
		t.Fatal(err)
	}
	id := led.openEscalation("three attempts")
	for i := 0; i < 3000; i++ {
		led.note(Entry{Event: EventEscalationNote, ID: id, Reason: "fail2ban is inactive " + strings.Repeat("x", 80)})
	}
	raw, _ := os.ReadFile(led.path)
	if strings.Contains(string(raw), `"event":"escalation"`) {
		t.Fatal("setup: the opening line should have been trimmed away")
	}

	again, err := openLedger("probe", now)
	if err != nil {
		t.Fatal(err)
	}
	if again.OpenEscalation() != id {
		t.Fatalf("the escalation #%d is still open but read back as %d", id, again.OpenEscalation())
	}

	// And a close still closes it, from the notes' id.
	again.closeEscalation("passes")
	third, _ := openLedger("probe", now)
	if third.OpenEscalation() != 0 {
		t.Error("a closed escalation read back as open")
	}
}
