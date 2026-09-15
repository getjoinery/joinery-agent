package recipes

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// The state machine, one row per rule of the loop (specs/agent_tier1_recipes.md,
// "Rules of the loop" and "Where the bugs will live"), driven by a fake clock
// and a fake check and repair. Nothing here starts a process; the real check
// and repair are wired in fail2ban.go and tested there against a signed tree.

// harness is one recipe under a loop with every dependency faked.
type harness struct {
	t          *testing.T
	now        time.Time
	loop       *Loop
	recipe     Recipe
	verdict    Verdict  // what the check answers
	after      *Verdict // what the verify check right after a repair answers (nil: verdict)
	verifyNext bool
	repairs    int   // how many times Repair ran
	repair     error // what Repair returns
	lock       sync.Mutex
	marks      []string // recipe names the marker was written for
	marked     int      // markers currently open
	logs       []string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	root := t.TempDir()
	restoreLedger, restoreHold, restoreOut := LedgerDir, HoldDir, OutwardDir
	LedgerDir = filepath.Join(root, "ledger")
	HoldDir = filepath.Join(root, "hold")
	OutwardDir = filepath.Join(root, "cache", "recipes")
	t.Cleanup(func() { LedgerDir, HoldDir, OutwardDir = restoreLedger, restoreHold, restoreOut })
	ResetCasesForTests()
	t.Cleanup(ResetCasesForTests)

	h := &harness{t: t, now: time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)}
	h.verdict = Verdict{Pass, "fine"}
	h.recipe = Recipe{
		Name:        "probe",
		MinInterval: TickInterval,
		CheckWord:   "host_report",
		RepairWord:  "host_converge",
		Check: func(context.Context, *Env) Verdict {
			if h.verifyNext {
				h.verifyNext = false
				if h.after != nil {
					return *h.after
				}
			}
			return h.verdict
		},
		Repair: func(context.Context, *Env) (string, error) {
			h.repairs++
			h.verifyNext = true
			if h.marked != 1 {
				t.Errorf("the job marker should be written exactly once for the duration of a repair; %d open", h.marked)
			}
			if h.lock.TryLock() {
				h.lock.Unlock()
				t.Error("the job lock should be held while a repair runs")
			}
			if h.repair != nil {
				return "", h.repair
			}
			return "ran", nil
		},
	}
	h.restart()
	return h
}

// restart builds a fresh loop over the same recipe and ledger: what an agent
// restart does. The in-memory state goes; the ledger stays.
func (h *harness) restart() {
	h.loop = NewLoop([]Recipe{h.recipe}, nil, h.options())
	// The state machine is tested armed; report-only has its own rows below.
	h.loop.reportOnly = false
}

func (h *harness) options() Options {
	return Options{
		Now:  func() time.Time { return h.now },
		Lock: &h.lock,
		MarkRunning: func(name string) func() {
			h.marks = append(h.marks, name)
			h.marked++
			return func() { h.marked-- }
		},
		Logf: func(format string, args ...interface{}) { h.logs = append(h.logs, fmt.Sprintf(format, args...)) },
	}
}

// tick advances the clock one tick interval and runs the loop.
func (h *harness) tick() {
	h.now = h.now.Add(TickInterval)
	h.loop.Tick(context.Background())
}

// ticks runs n ticks.
func (h *harness) ticks(n int) {
	for i := 0; i < n; i++ {
		h.tick()
	}
}

// entries reads the recipe's read-back ledger.
func (h *harness) entries() []Entry {
	return readEntries(h.t, filepath.Join(LedgerDir, h.recipe.Name+".jsonl"))
}

func readEntries(t *testing.T, path string) []Entry {
	t.Helper()
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []Entry
	s := bufio.NewScanner(f)
	for s.Scan() {
		var e Entry
		if err := json.Unmarshal(s.Bytes(), &e); err != nil {
			t.Fatalf("unreadable ledger line %q: %v", s.Text(), err)
		}
		out = append(out, e)
	}
	return out
}

func (h *harness) count(event string) int {
	n := 0
	for _, e := range h.entries() {
		if e.Event == event {
			n++
		}
	}
	return n
}

func (h *harness) outcomes() []string {
	var out []string
	for _, e := range h.entries() {
		if e.Event == EventOutcome {
			out = append(out, e.Outcome)
		}
	}
	return out
}

func (h *harness) logged(substr string) int {
	n := 0
	for _, line := range h.logs {
		if strings.Contains(line, substr) {
			n++
		}
	}
	return n
}

// --- The rows -----------------------------------------------------------------

func TestAPassingCheckNeverRepairs(t *testing.T) {
	h := newHarness(t)
	h.ticks(12)
	if h.repairs != 0 {
		t.Fatalf("a passing recipe repaired %d times", h.repairs)
	}
	if n := h.count(EventCheck); n != 1 {
		t.Errorf("a healthy recipe should write one check line (its first) and then nothing, got %d", n)
	}
}

func TestOneFailingTickDoesNotRepair(t *testing.T) {
	// A transient — an apt upgrade restarting a unit, an operator's reload —
	// is seen once. Nothing acts on one sighting.
	h := newHarness(t)
	h.verdict = Verdict{Fail, "down"}
	h.tick()
	if h.repairs != 0 {
		t.Fatal("repaired on the first failing tick")
	}
	if h.logged("first failing tick") != 1 {
		t.Error("the first failing tick should say it is waiting for a second")
	}
}

func TestTwoConsecutiveFailingTicksRepair(t *testing.T) {
	h := newHarness(t)
	h.verdict = Verdict{Fail, "down"}
	h.after = &Verdict{Pass, "up"}
	h.ticks(2)
	if h.repairs != 1 {
		t.Fatalf("expected one repair after two failing ticks, got %d", h.repairs)
	}
	if got := h.outcomes(); len(got) != 1 || got[0] != OutcomeRepaired {
		t.Errorf("the attempt should be ledgered as repaired, got %v", got)
	}
	if len(h.marks) != 1 || h.marks[0] != "probe" || h.marked != 0 {
		t.Errorf("the job marker should be written for the recipe and cleared after: marks=%v open=%d", h.marks, h.marked)
	}
}

func TestAPassBetweenTwoFailuresResetsTheCount(t *testing.T) {
	h := newHarness(t)
	h.verdict = Verdict{Fail, "down"}
	h.tick()
	h.verdict = Verdict{Pass, "up"}
	h.tick()
	h.verdict = Verdict{Fail, "down"}
	h.tick()
	if h.repairs != 0 {
		t.Fatal("fail, pass, fail is not two consecutive failures")
	}
	h.tick()
	if h.repairs != 1 {
		t.Fatal("the second failure after the pass should repair")
	}
}

func TestUnknownIsLedgeredOnlyWhenTheVerdictChanges(t *testing.T) {
	// A container's fail2ban check answers unknown on every tick of its
	// life; the ledger records that once, and again only when the answer
	// changes. A pass after a pass is silent the same way. A failure is
	// written every tick: it is what the ledger is for.
	h := newHarness(t)
	h.verdict = Verdict{Unknown, "no systemd"}
	h.ticks(5)
	if n := h.count(EventCheck); n != 1 {
		t.Fatalf("five unknown ticks should write one check line, got %d", n)
	}
	h.verdict = Verdict{Pass, "up"}
	h.tick()
	h.tick()
	if n := h.count(EventCheck); n != 2 {
		t.Fatalf("a pass after unknown is a change (one line), a pass after a pass is not; got %d lines", n)
	}
	h.verdict = Verdict{Unknown, "no answer"}
	h.ticks(3)
	if n := h.count(EventCheck); n != 3 {
		t.Fatalf("unknown after pass is a change (one line), unknown after unknown is not; got %d lines", n)
	}
	h.verdict = Verdict{Fail, "down"}
	h.tick()
	h.tick()
	if n := h.count(EventCheck); n != 5 {
		t.Fatalf("every failing tick is written; got %d lines", n)
	}
}

func TestUnknownNeverRepairsAndBreaksTheRun(t *testing.T) {
	h := newHarness(t)
	h.verdict = Verdict{Unknown, "no systemd"}
	h.ticks(5)
	if h.repairs != 0 {
		t.Fatal("unknown repaired")
	}
	// fail, unknown, fail: not consecutive.
	h.verdict = Verdict{Fail, "down"}
	h.tick()
	h.verdict = Verdict{Unknown, "no answer"}
	h.tick()
	h.verdict = Verdict{Fail, "down"}
	h.tick()
	if h.repairs != 0 {
		t.Fatal("an unknown between two failures must not count as a failed tick, and must break the run")
	}
	h.tick()
	if h.repairs != 1 {
		t.Fatal("two failures after the unknown should repair")
	}
}

func TestTheCountStartsAtZeroOnProcessStart(t *testing.T) {
	// A failure recorded before a restart is not the first tick of a new
	// pair: the in-memory count is the only count, and a new loop is a new
	// process.
	h := newHarness(t)
	h.verdict = Verdict{Fail, "down"}
	h.tick()
	// "Restart": a fresh loop over the same ledger.
	h.restart()
	h.tick()
	if h.repairs != 0 {
		t.Fatal("a failure seen by the previous process counted toward this one's pair")
	}
	h.tick()
	if h.repairs != 1 {
		t.Fatal("two failures in the new process should repair")
	}
}

func TestARepairThatDoesNotVerifyIsAFailedAttempt(t *testing.T) {
	h := newHarness(t)
	h.verdict = Verdict{Fail, "down"}
	h.repair = fmt.Errorf("the transcript says WARNING")
	h.ticks(2)
	if got := h.outcomes(); len(got) != 1 || got[0] != OutcomeFailed {
		t.Fatalf("a repair whose word reported failure is a failed attempt, got %v", got)
	}
	// And one whose word reported success but the check still fails.
	h2 := newHarness(t)
	h2.verdict = Verdict{Fail, "down"}
	h2.ticks(2)
	if h2.repairs != 1 {
		t.Fatal("expected a repair")
	}
	// The check answered "down" both before and after the repair.
	if got := h2.outcomes(); len(got) != 1 || got[0] != OutcomeFailed {
		t.Fatalf("a repair the check does not confirm is a failed attempt, got %v", got)
	}
	// And the positive path, for contrast: the word reports ok and the check
	// agrees.
	h3 := newHarness(t)
	h3.verdict = Verdict{Fail, "down"}
	h3.after = &Verdict{Pass, "up"}
	h3.ticks(2)
	if got := h3.outcomes(); len(got) != 1 || got[0] != OutcomeRepaired {
		t.Fatalf("a repair the check confirms is repaired, got %v", got)
	}
}

func TestThreeAttemptsPerRunSpacedByBackoffThenEscalation(t *testing.T) {
	// The loop never repairs three times in a row: after the first attempt
	// the second waits ten minutes, after the second the third waits
	// thirty, and a fourth in the same failing run is an escalation, not an
	// attempt.
	h := newHarness(t)
	h.verdict = Verdict{Fail, "down"}

	h.ticks(2) // t+20: attempt 1
	if h.repairs != 1 {
		t.Fatalf("attempt 1 expected after two failing ticks, got %d", h.repairs)
	}
	h.tick() // t+30: ten minutes since attempt 1 — due
	if h.repairs != 2 {
		t.Fatalf("attempt 2 expected ten minutes after attempt 1, got %d", h.repairs)
	}
	h.ticks(2) // t+40, t+50: inside the thirty-minute wait
	if h.repairs != 2 {
		t.Fatalf("attempt 3 ran inside its thirty-minute backoff (%d repairs)", h.repairs)
	}
	h.tick() // t+60: thirty minutes since attempt 2 — due
	if h.repairs != 3 {
		t.Fatalf("attempt 3 expected thirty minutes after attempt 2, got %d", h.repairs)
	}
	h.ticks(3) // t+70..t+90: three attempts in the run; a fourth is an escalation
	if h.repairs != 3 {
		t.Fatalf("a fourth attempt ran in the same run (%d repairs)", h.repairs)
	}
	if n := h.count(EventEscalation); n != 1 {
		t.Fatalf("expected exactly one escalation, got %d", n)
	}
	if h.logged("ESCALATION") != 1 {
		t.Error("the escalation should be one log line")
	}
	// Further failures append to the same entry: no second escalation, no
	// attempt, and the notes carry the escalation's id.
	h.ticks(6)
	if n := h.count(EventEscalation); n != 1 {
		t.Fatalf("a case storm: %d escalations", n)
	}
	if h.count(EventEscalationNote) < 6 {
		t.Error("failing ticks under an open escalation should append to it")
	}
	if h.repairs != 3 {
		t.Fatal("repaired while escalated")
	}
	id := 0
	for _, e := range h.entries() {
		if e.Event == EventEscalation {
			id = e.ID
		}
		if e.Event == EventEscalationNote && e.ID != id {
			t.Errorf("a note carries id %d, the open escalation is %d", e.ID, id)
		}
	}
}

func TestAnEscalationClosesWhenTheCheckPasses(t *testing.T) {
	h := newHarness(t)
	h.verdict = Verdict{Fail, "down"}
	h.ticks(10) // three attempts and an escalation
	if h.count(EventEscalation) != 1 {
		t.Fatal("setup: expected an escalation")
	}
	h.verdict = Verdict{Pass, "up"}
	h.tick()
	if h.count(EventEscalationClosed) != 1 {
		t.Fatal("the escalation should close on a pass")
	}
	// And it is closed in the read-back ledger too: a new process sees none.
	led, err := openLedger(h.recipe.Name, func() time.Time { return h.now })
	if err != nil || led.OpenEscalation() != 0 {
		t.Fatalf("the ledger still reads an open escalation (%v, %d)", err, led.OpenEscalation())
	}
}

func TestAnOpenEscalationSurvivesARestart(t *testing.T) {
	h := newHarness(t)
	h.verdict = Verdict{Fail, "down"}
	h.ticks(10)
	if h.count(EventEscalation) != 1 {
		t.Fatal("setup: expected an escalation")
	}
	repairsBefore := h.repairs
	// Restart. The new process reads the open escalation back and never
	// repairs, however many consecutive failures it sees.
	h.restart()
	h.now = h.now.Add(2 * time.Hour) // the attempt budget has long since refilled
	h.ticks(4)
	if h.repairs != repairsBefore {
		t.Fatal("a restart let an escalated recipe repair again")
	}
	if h.logged("is open from a previous process") != 1 {
		t.Error("the new process should say it found the escalation open")
	}
}

func TestTheBudgetRefillsWhenTheCheckPasses(t *testing.T) {
	h := newHarness(t)
	h.verdict = Verdict{Fail, "down"}
	h.ticks(6) // attempts at +20, +30, +60
	if h.repairs != 3 {
		t.Fatalf("setup: expected three attempts, got %d", h.repairs)
	}
	// Recover, so no escalation opens: the run is over and the budget is
	// whole again. A new failure is a new run with fresh attempts.
	h.verdict = Verdict{Pass, "up"}
	h.tick() // +70
	if h.count(EventEscalation) != 0 {
		t.Fatal("setup: no escalation expected")
	}
	h.verdict = Verdict{Fail, "down"}
	h.now = h.now.Add(20 * time.Minute) // +90
	h.ticks(2)                          // +100, +110: two failing ticks of a new run
	if h.repairs != 4 {
		t.Fatalf("after a pass the next failing run gets a fresh first attempt, got %d repairs", h.repairs)
	}
	if h.count(EventEscalation) != 0 {
		t.Fatal("the old run's attempts must not count toward the new run")
	}
	// And the same across a restart: the run boundary is read back from the
	// pass line, not remembered by the process.
	h.restart()
	h.tick() // +120: one failing tick in the new process; no attempt yet
	h.tick() // +130: second tick; attempt 2 of the run waits ten minutes after attempt 1 (+110) — due
	if h.repairs != 5 {
		t.Fatalf("the new process should count the run from the pass it read back, got %d repairs", h.repairs)
	}
	if h.count(EventEscalation) != 0 {
		t.Fatal("two attempts in the run is not an escalation")
	}
}

func TestEscalationDoesNotDependOnTheAttemptsFittingAnHour(t *testing.T) {
	// The docker-prod host, 2026-09-15: attempts at 19:22, 19:42, 20:22,
	// 20:52, 21:32, 22:02 and never a case, because the first attempt of the
	// run had aged out of an hour's window before the third landed. The
	// budget counts the run, however it is spread.
	h := newHarness(t)
	h.verdict = Verdict{Fail, "down"}
	h.ticks(3) // attempts at +20 and +30
	if h.repairs != 2 {
		t.Fatalf("setup: expected two attempts, got %d", h.repairs)
	}
	h.now = h.now.Add(70 * time.Minute) // a long busy stretch; attempt 3 lands at +110
	h.tick()
	if h.repairs != 3 {
		t.Fatalf("attempt 3 expected once its wait is over, got %d", h.repairs)
	}
	h.tick() // +120: three attempts in the run and the check still fails
	if h.repairs != 3 {
		t.Fatal("a fourth attempt ran instead of an escalation")
	}
	if n := h.count(EventEscalation); n != 1 {
		t.Fatalf("expected the escalation, got %d; the attempts span more than an hour and that must not matter", n)
	}
}

func TestATickThatLandsEarlyDoesNotCostAWholeWait(t *testing.T) {
	// A systemd-like timer fires a few milliseconds off each tick. Measured
	// against the previous attempt's end, a ten-minute wait then comes out
	// at 9m59.99s and would take a second tick; the attempts drift to
	// twenty and forty minutes apart. A tick within half an interval of the
	// wait is the tick the wait ends on.
	h := newHarness(t)
	h.verdict = Verdict{Fail, "down"}
	early := func() {
		h.now = h.now.Add(TickInterval - 40*time.Millisecond)
		h.loop.Tick(context.Background())
	}
	early()
	early() // attempt 1
	early() // ten minutes less 40ms since attempt 1: due
	if h.repairs != 2 {
		t.Fatalf("attempt 2 should run on the tick its wait ends on, jitter or not; got %d", h.repairs)
	}
	early()
	early()
	early() // thirty minutes less a little since attempt 2: due
	if h.repairs != 3 {
		t.Fatalf("attempt 3 should run on the tick its wait ends on; got %d", h.repairs)
	}
	early()
	if n := h.count(EventEscalation); n != 1 {
		t.Fatalf("expected the escalation on the tick after the third attempt, got %d", n)
	}
}

func TestAHeldRecipeLogsOnEveryFailingTickAndNeverRepairs(t *testing.T) {
	h := newHarness(t)
	if err := os.MkdirAll(HoldDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(HoldDir, "probe"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	h.verdict = Verdict{Fail, "down"}
	h.ticks(5)
	if h.repairs != 0 {
		t.Fatal("a held recipe repaired")
	}
	if h.logged("held by") != 5 {
		t.Errorf("a held recipe must say so on every failing tick, said it %d times in 5", h.logged("held by"))
	}
	if h.count(EventHeld) != 5 {
		t.Errorf("every held failing tick is a ledger line, got %d", h.count(EventHeld))
	}
	// A passing tick under hold says nothing: there is nothing to hold back.
	h.verdict = Verdict{Pass, "up"}
	h.tick()
	if h.logged("held by") != 5 {
		t.Error("a passing tick under hold should not complain")
	}
	// Remove the marker: the next failing pair repairs.
	os.Remove(filepath.Join(HoldDir, "probe"))
	h.verdict = Verdict{Fail, "down"}
	h.ticks(2)
	if h.repairs != 1 {
		t.Fatal("removing the marker should let the recipe repair again")
	}
}

func TestAHoldMarkerInAnUntrustedDirectoryIsIgnoredAndSaidSo(t *testing.T) {
	h := newHarness(t)
	if err := os.MkdirAll(HoldDir, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(HoldDir, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(HoldDir, "probe"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	h.verdict = Verdict{Fail, "down"}
	h.ticks(2)
	if h.repairs != 1 {
		t.Fatal("a marker in a world-writable directory must not hold the recipe")
	}
	if h.count(EventHoldIgnored) == 0 {
		t.Error("the ledger should say the marker was ignored and why")
	}
	if h.logged("writable by group or other") == 0 {
		t.Error("the log should say why the marker was ignored")
	}
}

func TestALostLockIsALedgerLineNotAnAttempt(t *testing.T) {
	h := newHarness(t)
	h.verdict = Verdict{Fail, "down"}
	h.tick()
	h.lock.Lock() // a job is running
	h.tick()
	if h.repairs != 0 {
		t.Fatal("repaired while a job held the lock")
	}
	if h.count(EventBusy) != 1 || h.count(EventAttempt) != 0 {
		t.Errorf("busy should be one ledger line and no attempt: busy=%d attempts=%d", h.count(EventBusy), h.count(EventAttempt))
	}
	if h.logged("a job is running") != 1 {
		t.Error("the log should say a job is running")
	}
	h.lock.Unlock()
	// The consecutive count was not touched by the busy tick: the very next
	// failing tick repairs.
	h.tick()
	if h.repairs != 1 {
		t.Fatal("the tick after the lock freed should repair; the busy tick must not reset the count")
	}
	if h.lock.TryLock() {
		h.lock.Unlock()
	} else {
		t.Fatal("the loop left the job lock held")
	}
}

func TestAnAttemptWithNoOutcomeCountsAgainstTheBudget(t *testing.T) {
	// A repair that kills the agent leaves an attempt line with no outcome.
	// The next process gives it one — interrupted — and counts it, so a
	// restart cannot loop the recipe through a fourth attempt.
	h := newHarness(t)
	h.verdict = Verdict{Fail, "down"}
	h.ticks(3) // two attempts, at +20 and +30
	if h.repairs != 2 {
		t.Fatalf("setup: expected two attempts, got %d", h.repairs)
	}
	// Forge the crash: append an attempt with no outcome, as a process that
	// died mid-repair would have left.
	led, err := openLedger(h.recipe.Name, func() time.Time { return h.now })
	if err != nil {
		t.Fatal(err)
	}
	led.beginAttempt("host_converge", ModeArmed)

	// Restart, and the fault is still there.
	h.restart()
	h.ticks(4)
	if h.repairs != 2 {
		t.Fatalf("the interrupted attempt should have been the third; a further attempt ran (%d)", h.repairs)
	}
	outcomes := h.outcomes()
	if len(outcomes) != 3 || outcomes[2] != OutcomeInterrupted {
		t.Errorf("the unfinished attempt should be completed as interrupted, got %v", outcomes)
	}
	if h.count(EventEscalation) != 1 {
		t.Error("three attempts in the hour, one of them interrupted, is an escalation")
	}
	if h.logged("never recorded an outcome") != 1 {
		t.Error("the new process should say it found an unfinished attempt")
	}
}

func TestReportOnlyLedgersTheAttemptAndRunsNothing(t *testing.T) {
	h := newHarness(t)
	h.loop.reportOnly = true
	h.verdict = Verdict{Fail, "down"}
	h.ticks(10)
	if h.repairs != 0 {
		t.Fatalf("report-only ran the repair %d times", h.repairs)
	}
	// The budget and the escalation count exactly as if it had run: three
	// report-only attempts on the armed loop's schedule, then an escalation.
	outcomes := h.outcomes()
	if len(outcomes) != 3 {
		t.Fatalf("expected three report-only attempts in the hour, got %v", outcomes)
	}
	for _, o := range outcomes {
		if o != OutcomeReportOnly {
			t.Errorf("a report-only attempt's outcome is %q, got %q", OutcomeReportOnly, o)
		}
	}
	if h.count(EventEscalation) != 1 {
		t.Error("report-only attempts should exhaust the budget and escalate like real ones")
	}
	for _, e := range h.entries() {
		if e.Event == EventAttempt && e.Mode != ModeReportOnly {
			t.Errorf("an attempt line should carry the mode, got %q", e.Mode)
		}
	}
	if len(h.marks) != 3 || h.marked != 0 {
		t.Errorf("report-only still takes the marker for the attempt and clears it: marks=%v open=%d", h.marks, h.marked)
	}
}

func TestReportOnlyStillTakesTheLock(t *testing.T) {
	h := newHarness(t)
	h.loop.reportOnly = true
	h.verdict = Verdict{Fail, "down"}
	h.tick()
	h.lock.Lock()
	h.tick()
	h.lock.Unlock()
	if h.count(EventAttempt) != 0 || h.count(EventBusy) != 1 {
		t.Error("a report-only attempt under a held lock is a busy line, not an attempt — the burn-in must show the path the armed loop takes")
	}
}

func TestARecipeWithALongerIntervalIsCheckedLessOften(t *testing.T) {
	h := newHarness(t)
	checks := 0
	h.recipe.MinInterval = 3 * TickInterval
	h.recipe.Check = func(context.Context, *Env) Verdict { checks++; return Verdict{Pass, ""} }
	h.loop = NewLoop([]Recipe{h.recipe}, nil, Options{Now: func() time.Time { return h.now }, Logf: func(string, ...interface{}) {}})
	h.ticks(9)
	if checks != 3 {
		t.Fatalf("a recipe with a 30-minute interval should be checked 3 times in 9 ticks, got %d", checks)
	}
}

func TestAnIntervalEqualToTheTickIsCheckedEveryTick(t *testing.T) {
	// Even when the ticker lands a hair early.
	h := newHarness(t)
	checks := 0
	h.recipe.Check = func(context.Context, *Env) Verdict { checks++; return Verdict{Pass, ""} }
	h.loop = NewLoop([]Recipe{h.recipe}, nil, Options{Now: func() time.Time { return h.now }, Logf: func(string, ...interface{}) {}})
	for i := 0; i < 5; i++ {
		h.now = h.now.Add(TickInterval - 50*time.Millisecond)
		h.loop.Tick(context.Background())
	}
	if checks != 5 {
		t.Fatalf("expected a check on every tick, got %d in 5", checks)
	}
}

func TestAnUntrustedLedgerDirectoryStopsRepairsNotChecks(t *testing.T) {
	h := newHarness(t)
	if err := os.MkdirAll(LedgerDir, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(LedgerDir, 0o777); err != nil {
		t.Fatal(err)
	}
	checks := 0
	h.recipe.Check = func(context.Context, *Env) Verdict { checks++; return Verdict{Fail, "down"} }
	h.restart()
	h.ticks(4)
	if h.repairs != 0 {
		t.Fatal("an attempt that cannot be ledgered must not run")
	}
	if checks != 4 {
		t.Error("the check should keep running")
	}
	if h.logged("ledger is unusable") != 4 {
		t.Errorf("every failing tick should say why nothing is repaired, said it %d times", h.logged("ledger is unusable"))
	}
	if _, err := os.Stat(filepath.Join(LedgerDir, "probe.jsonl")); !os.IsNotExist(err) {
		t.Error("nothing should be written into a directory that is not trusted")
	}
}

func TestTheOutwardCopyIsWrittenAndTheReadBackCopyIsRootOnly(t *testing.T) {
	h := newHarness(t)
	h.verdict = Verdict{Fail, "down"}
	h.ticks(2)
	inward := filepath.Join(LedgerDir, "probe.jsonl")
	outward := filepath.Join(OutwardDir, "probe.jsonl")
	in, err := os.ReadFile(inward)
	if err != nil {
		t.Fatal(err)
	}
	out, err := os.ReadFile(outward)
	if err != nil {
		t.Fatalf("the outward copy should exist under the site's cache directory: %v", err)
	}
	if string(in) != string(out) {
		t.Error("the outward copy should carry the same lines")
	}
	if info, _ := os.Stat(inward); info.Mode().Perm() != 0o600 {
		t.Errorf("the read-back ledger should be 0600, is %04o", info.Mode().Perm())
	}
	if info, _ := os.Stat(LedgerDir); info.Mode().Perm() != 0o700 {
		t.Errorf("the ledger directory should be 0700, is %04o", info.Mode().Perm())
	}
	if info, _ := os.Stat(outward); info.Mode().Perm()&0o044 != 0o044 {
		t.Errorf("the outward copy should be readable by the site, is %04o", info.Mode().Perm())
	}

	// And a forged outward copy changes nothing: the loop reads only LedgerDir.
	if err := os.WriteFile(outward, []byte(`{"time":"2026-09-14T12:00:00Z","recipe":"probe","event":"escalation","id":99}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	h.restart()
	h.now = h.now.Add(2 * time.Hour)
	h.ticks(2)
	if h.repairs != 2 {
		t.Fatal("a forged escalation in the outward copy stopped a repair — the outward ledger must never be read")
	}
}

func TestTwoRecipesKeepSeparateState(t *testing.T) {
	h := newHarness(t)
	otherRepairs := 0
	other := Recipe{
		Name: "other", MinInterval: TickInterval, CheckWord: "host_report", RepairWord: "host_converge",
		Check:  func(context.Context, *Env) Verdict { return Verdict{Pass, "fine"} },
		Repair: func(context.Context, *Env) (string, error) { otherRepairs++; return "", nil },
	}
	h.loop = NewLoop([]Recipe{other, h.recipe}, nil, Options{Now: func() time.Time { return h.now }, Lock: &h.lock,
		MarkRunning: func(string) func() { h.marked++; return func() { h.marked-- } },
		Logf:        func(string, ...interface{}) {}})
	h.loop.reportOnly = false
	h.verdict = Verdict{Fail, "down"}
	h.ticks(2)
	if h.repairs != 1 || otherRepairs != 0 {
		t.Fatalf("the failing recipe repairs (%d) and the passing one does not (%d)", h.repairs, otherRepairs)
	}
	if _, err := os.Stat(filepath.Join(LedgerDir, "other.jsonl")); err != nil {
		t.Error("each recipe has its own ledger file")
	}
}
