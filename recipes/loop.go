package recipes

import (
	"context"
	"fmt"
	"log"
	"time"
)

// The check loop: one state machine per recipe, driven by a tick.
//
// The retry policy, as constants, so the whole of it is in one place a
// reviewer can read against settled question Q1 of
// specs/agent_tier1_recipes.md:
//
//   - a repair only after two consecutive failing ticks (no pass and no
//     unknown between them; the count starts at zero on process start);
//   - three attempts per failing run — the attempts since the check last
//     passed, a repair last verified or the escalation closed — the second
//     ten minutes after the first, the third thirty minutes after the
//     second, never three in a row; each is due on the first tick at or
//     after its wait, and a tick that lands a little early still counts
//     (backoffTolerance), because a timer's jitter must not cost a whole
//     tick and push the attempts apart;
//   - a fourth is an escalation, not an attempt: one open per recipe, held
//     until the check passes, and while it is open the recipe checks and
//     never repairs.
const (
	consecutiveFailsToRepair = 2
	attemptBudget            = 3
	// A wait is over when less than this much of it remains at a tick: ticks
	// are TickInterval apart give or take the timer's jitter, so a wait of
	// exactly one interval measured against the previous tick comes out a
	// few milliseconds short and would otherwise take two.
	backoffTolerance = TickInterval / 2
)

// backoffBefore[n] is how long the loop waits after the previous attempt
// before the n-th attempt of the run (1-based). Index 0 is unused.
var backoffBefore = [attemptBudget + 1]time.Duration{0, 0, 10 * time.Minute, 30 * time.Minute}

// Locker is the shared job lock: the mutex a plane job holds while it runs
// and the self-updater refuses to swap the binary without. An attempt takes
// it with TryLock, never Lock: a lost lock is a ledger line, not a wait.
type Locker interface {
	TryLock() bool
	Unlock()
}

// Options is what the loop is built with. Every field has a default so a
// caller that wants the real clock, the real log and no lock at all (tests)
// can leave it out.
type Options struct {
	// Now is the clock. Default time.Now.
	Now func() time.Time
	// Lock is the shared job lock. Default: a lock that is always free.
	Lock Locker
	// MarkRunning writes the job marker for the duration of an attempt and
	// returns the function that clears it (markRecipeRunning in the parent
	// package). Default: nothing.
	MarkRunning func(recipe string) func()
	// Logf is the agent's log. Default log.Printf.
	Logf func(format string, args ...interface{})
	// Paired reports whether a management node is polling this agent, so
	// the rendered case says which delivery it has. Default: not paired.
	Paired func() bool

	// InContainer overrides the package answer for a test. Nil means the
	// real one.
	InContainer func() bool
	// HasSite overrides the package answer for a test. Nil means the real
	// one.
	HasSite func() bool
}

// Loop runs every registered recipe on the tick.
type Loop struct {
	recipes     []Recipe
	env         *Env
	now         func() time.Time
	lock        Locker
	markRunning func(recipe string) func()
	logf        func(format string, args ...interface{})
	paired      func() bool
	inContainer func() bool
	hasSite     func() bool

	// reportOnly is ReportOnly, held in a field so the state machine's tests
	// can exercise both the armed and the report-only paths. Nothing outside
	// the tests sets it.
	reportOnly bool

	state map[string]*recipeState
}

// recipeState is the in-memory half of one recipe's state. The ledger holds
// the other half (attempts, the open escalation); this half starts fresh
// with every process, on purpose: a failure recorded before a restart is not
// the first tick of a new pair.
type recipeState struct {
	lastCheck   time.Time
	lastVerdict Kind
	consecutive int
	escalation  int // id of the open escalation, mirrored from the ledger
	replayed    bool
}

type freeLock struct{}

func (freeLock) TryLock() bool { return true }
func (freeLock) Unlock()       {}

// NewLoop builds a loop over the given recipes. Production passes All();
// tests pass a recipe with a fake check and repair.
func NewLoop(recipes []Recipe, env *Env, opts Options) *Loop {
	l := &Loop{
		recipes:     recipes,
		env:         env,
		now:         opts.Now,
		lock:        opts.Lock,
		markRunning: opts.MarkRunning,
		logf:        opts.Logf,
		paired:      opts.Paired,
		inContainer: opts.InContainer,
		hasSite:     opts.HasSite,
		reportOnly:  ReportOnly,
		state:       map[string]*recipeState{},
	}
	if l.now == nil {
		l.now = time.Now
	}
	if l.lock == nil {
		l.lock = freeLock{}
	}
	if l.markRunning == nil {
		l.markRunning = func(string) func() { return func() {} }
	}
	if l.logf == nil {
		l.logf = log.Printf
	}
	if l.paired == nil {
		l.paired = func() bool { return false }
	}
	return l
}

// postCase puts a recipe's case on the board for the next claim and writes
// the rendered copy outward. A nil body keeps the body the board already
// holds for the same id (a note or a close never recomposes it).
func (l *Loop) postCase(r Recipe, c Case, body *CaseBody) {
	board.post(c, body)
	board.mu.Lock()
	kept := board.entries[c.Source].body
	board.mu.Unlock()
	writeOutwardCase(r.Name, c, kept, l.paired(), l.now())
}

// Run ticks every TickInterval until the context ends. The first tick is one
// interval after start, not immediately: an agent restarting in a loop must
// not run checks in a loop.
func (l *Loop) Run(ctx context.Context) {
	l.logf("recipes: %d compiled in (%s), mode %s, checking every %s", len(l.recipes), describe(l.recipes), Mode(), TickInterval)
	l.noteInapplicable()
	ticker := time.NewTicker(TickInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			l.Tick(ctx)
		}
	}
}

// applicable is Applicable(r) through the loop's own posture answers.
func (l *Loop) applicable(r Recipe) bool {
	in := l.inContainer
	if in == nil {
		in = InContainer
	}
	site := l.hasSite
	if site == nil {
		site = HasSite
	}
	return applicableWith(r, in, site)
}

// noteInapplicable says once per process, in the journal and the ledger,
// which host-scoped recipes this agent cannot see the subject of. One line,
// not one every tick: a container's ledger used to fill with "unknown" every
// ten minutes and trim itself in seventeen days with nothing in it worth
// keeping.
func (l *Loop) noteInapplicable() {
	for _, r := range l.recipes {
		if l.applicable(r) {
			continue
		}
		reason := inapplicableReason(r)
		if r.Scope == ScopeSite {
			l.logf("recipe %s: not applicable on a machine with no site (%s); not checked here", r.Name, reason)
		} else {
			l.logf("recipe %s: not applicable in a container (its subject is the host); not checked here", r.Name)
		}
		if led, err := openLedger(r.Name, l.now); err == nil && led != nil {
			led.note(Entry{Event: EventNotApplicable, Reason: reason})
		}
	}
}

func describe(recipes []Recipe) string {
	if len(recipes) == 0 {
		return "none"
	}
	s := ""
	for i, r := range recipes {
		if i > 0 {
			s += ", "
		}
		s += r.Name
	}
	return s
}

// Tick runs every recipe that is due, once, in name order.
func (l *Loop) Tick(ctx context.Context) {
	for _, r := range l.recipes {
		l.tickOne(ctx, r)
	}
}

func (l *Loop) stateFor(name string) *recipeState {
	st, ok := l.state[name]
	if !ok {
		st = &recipeState{}
		l.state[name] = st
	}
	return st
}

// tickOne is the state machine for one recipe on one tick.
func (l *Loop) tickOne(ctx context.Context, r Recipe) {
	if !l.applicable(r) {
		return // said once at start; nothing to check from here
	}
	st := l.stateFor(r.Name)
	now := l.now()

	// Due? A recipe whose minimum interval is longer than the tick is checked
	// on the first tick at or past it. Half a tick of slack, so an interval
	// equal to the tick is due on every tick and not every other one when the
	// ticker lands a millisecond early.
	if !st.lastCheck.IsZero() && now.Sub(st.lastCheck)+TickInterval/2 < r.MinInterval {
		return
	}
	st.lastCheck = now

	// The ledger, read back. On the first tick of this process any attempt
	// the previous process started and never finished is given its outcome.
	led, ledErr := openLedger(r.Name, l.now)
	if led != nil && !st.replayed {
		st.replayed = true
		if n := led.finishInterrupted(); n > 0 {
			l.logf("recipe %s: %d attempt(s) from a previous agent process never recorded an outcome; counted as failed", r.Name, n)
		}
		st.escalation = led.OpenEscalation()
		if st.escalation != 0 {
			l.logf("recipe %s: escalation #%d is open from a previous process; checking only until the check passes", r.Name, st.escalation)
		}
		// The case is the escalation, and the plane may not have heard it: an
		// open one is composed again and rides with its body; a closed one
		// rides as a summary until the next escalation replaces it, so the
		// close reaches a plane that was not listening when it happened.
		if latest := led.Latest(); latest != nil {
			var body *CaseBody
			if latest.open() {
				body = l.composeBody(ctx, r, led, latest.Opened)
			}
			l.postCase(r, caseOf(r, *latest), body)
		}
	}

	verdict := r.Check(ctx, l.env)
	previous := st.lastVerdict
	st.lastVerdict = verdict.Kind
	noteVerdict(r.Name, verdict.Kind) // what the next claim says beside the mode
	// A check line is written when the check fails or the verdict changed.
	// A pass after a pass says nothing, and so does an unknown after an
	// unknown: a machine whose check cannot answer would otherwise write a
	// line every ten minutes for the rest of its life, and reach the trim
	// with nothing in it worth keeping. The first tick of a process is
	// always a change, so a restart is visible in the ledger.
	if led != nil && (verdict.Kind == Fail || verdict.Kind != previous) {
		led.note(Entry{Event: EventCheck, Verdict: verdict.Kind, Reason: verdict.Reason})
	}

	switch verdict.Kind {
	case Pass:
		st.consecutive = 0
		if st.escalation != 0 {
			l.logf("recipe %s: check passes again; escalation #%d closed", r.Name, st.escalation)
			if led != nil {
				led.closeEscalation("the check passes: " + verdict.Reason)
				if latest := led.Latest(); latest != nil {
					l.postCase(r, caseOf(r, *latest), nil)
				}
			}
			st.escalation = 0
		}
		return
	case Unknown:
		// Not a failure, and not nothing: two failures with an unknown between
		// them are not consecutive, so the count starts over.
		st.consecutive = 0
		l.logf("recipe %s: check could not answer (%s); not counted as a failure, nothing repaired", r.Name, verdict.Reason)
		return
	}

	// Fail.
	st.consecutive++

	if led == nil {
		// Fail closed. An attempt that cannot be ledgered cannot be budgeted,
		// so it does not happen; the log says why on every failing tick.
		l.logf("recipe %s: check fails (%s) but the ledger is unusable, so nothing will be repaired: %v", r.Name, verdict.Reason, ledErr)
		return
	}

	held, ignored := holdState(r.Name)
	if ignored != "" {
		led.note(Entry{Event: EventHoldIgnored, Reason: ignored})
		l.logf("recipe %s: %s", r.Name, ignored)
	}
	if held {
		led.note(Entry{Event: EventHeld, Reason: verdict.Reason})
		l.logf("recipe %s: held by %s; check fails (%s) and nothing will be repaired until the marker is removed",
			r.Name, HoldPath(r.Name), verdict.Reason)
		return
	}

	if st.escalation != 0 {
		// One open case per recipe: a failing tick while it is open is a note
		// appended by id, never a second escalation and never a second case.
		led.noteEscalation(verdict.Reason)
		if latest := led.Latest(); latest != nil {
			l.postCase(r, caseOf(r, *latest), nil)
		}
		return
	}

	if st.consecutive < consecutiveFailsToRepair {
		l.logf("recipe %s: check fails (%s); first failing tick, waiting for a second before repairing", r.Name, verdict.Reason)
		return
	}

	attempts := led.AttemptsInRun()
	if len(attempts) >= attemptBudget {
		reason := fmt.Sprintf("%d attempts since the check last passed and it still fails (%s); no more until a person looks or the check passes",
			len(attempts), verdict.Reason)
		st.escalation = led.openEscalation(reason)
		l.logf("recipe %s: ESCALATION #%d: %s", r.Name, st.escalation, reason)
		// The escalation is a case: composed now, with a fresh host_report,
		// and on the board for the next claim (case.go).
		if latest := led.Latest(); latest != nil {
			l.postCase(r, caseOf(r, *latest), l.composeBody(ctx, r, led, latest.Opened))
			l.logf("recipe %s: case #%d opened (%s); it rides the next poll and closes when the check passes", r.Name, st.escalation, CaseSourceRecipe+r.Name)
		}
		return
	}
	if n := len(attempts); n > 0 {
		last := attempts[n-1]
		since := last.Started
		if !last.Ended.IsZero() {
			since = last.Ended
		}
		if wait := backoffBefore[n+1]; wait-now.Sub(since) > backoffTolerance {
			l.logf("recipe %s: check fails (%s); attempt %d waits %s after the last one (%s more)",
				r.Name, verdict.Reason, n+1, wait, (wait - now.Sub(since)).Round(time.Second))
			return
		}
	}

	if !l.lock.TryLock() {
		led.note(Entry{Event: EventBusy, Reason: "a job is running; not an attempt"})
		l.logf("recipe %s: check fails (%s) but a job is running; trying next tick", r.Name, verdict.Reason)
		return
	}
	defer l.lock.Unlock()

	clearMarker := l.markRunning(r.Name)
	defer clearMarker()

	mode := ModeArmed
	if l.reportOnly {
		mode = ModeReportOnly
	}
	id := led.beginAttempt(r.RepairWord, mode)

	if l.reportOnly {
		led.endAttempt(id, OutcomeReportOnly, "would have run "+r.RepairWord+" (report-only release); the check said: "+verdict.Reason)
		l.logf("recipe %s: attempt #%d report-only — would have run %s; nothing was changed", r.Name, id, r.RepairWord)
		return
	}

	l.logf("recipe %s: attempt #%d running %s", r.Name, id, r.RepairWord)
	detail, err := r.Repair(ctx, l.env)
	if err != nil {
		led.endAttempt(id, OutcomeFailed, err.Error())
		l.logf("recipe %s: attempt #%d failed: %v", r.Name, id, err)
		return
	}
	verify := r.Check(ctx, l.env)
	if verify.Kind != Pass {
		led.endAttempt(id, OutcomeFailed, fmt.Sprintf("%s reported success (%s) but the check afterwards says %s: %s",
			r.RepairWord, detail, verify.Kind, verify.Reason))
		l.logf("recipe %s: attempt #%d: %s reported success but the check still says %s (%s)", r.Name, id, r.RepairWord, verify.Kind, verify.Reason)
		return
	}
	led.endAttempt(id, OutcomeRepaired, detail)
	st.consecutive = 0
	st.lastVerdict = Pass
	noteVerdict(r.Name, Pass) // the check after the repair said so
	l.logf("recipe %s: attempt #%d repaired (%s)", r.Name, id, detail)
}
