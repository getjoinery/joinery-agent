package recipes

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// The two ledgers (specs/agent_tier1_recipes.md, "Rules of the loop").
//
// LedgerDir holds the one the loop READS BACK: one append-only JSON-lines file
// per recipe, root-only, capped. It answers two questions and only two — how
// many attempts in the last hour, and is an escalation open — and both answers
// only ever narrow the loop, so a forged file could stop repairs but never add
// one. The directory is required to be owned by this process's user and
// unwritable by anyone else, or the loop refuses to ledger and therefore to
// repair (see trustedDir).
//
// OutwardDir holds the copy the site renders: the same lines, world-readable
// under the site's cache directory, written and never read, because the web
// user can write there and a forged "no attempts yet" would widen the agent
// from a file on disk. Empty on a machine with no site.
//
// Both are package vars rather than constants so tests point them at a temp
// directory, the way jobMarkerPath is in the parent package; nothing at
// runtime writes to either.
var (
	LedgerDir  = "/etc/joinery-agent/ledger"
	OutwardDir = ""
)

// LedgerMaxBytes caps each file. When an append would take a file past it, the
// oldest lines go until the newest half of the cap remains: a ledger is a
// record of the recent past, and the recent past is what the loop reads.
const LedgerMaxBytes = 256 * 1024

// maxDetailBytes bounds any free text a line carries. A transcript belongs in
// a job result, not in a file the loop rewrites on every tick.
const maxDetailBytes = 2048

// Event names. Each line carries exactly one.
const (
	// An attempt started. Carries id and mode; its outcome is a later line
	// with the same id. An attempt with no outcome line is one the agent did
	// not live to finish, and counts as failed.
	EventAttempt = "attempt"
	// An attempt ended. Outcome is one of the Outcome* constants.
	EventOutcome = "outcome"
	// A check that did not pass, or the first pass after one that did not.
	EventCheck = "check"
	// The recipe was held by its marker on a failing tick.
	EventHeld = "held"
	// A hold marker exists but its directory is not root's alone, so it was
	// ignored. Reason says why.
	EventHoldIgnored = "hold_ignored"
	// The job lock was held by something else when an attempt was due: a job
	// or a self-update. Not an attempt.
	EventBusy = "busy"
	// EventNotApplicable: once per process, a host-scoped recipe this agent
	// cannot see the subject of (a container). Never counts, never repairs.
	EventNotApplicable = "not_applicable"
	// The budget ran out. Carries id; held open until the check passes.
	EventEscalation = "escalation"
	// A failing tick while an escalation is open, appended to it by id.
	EventEscalationNote = "escalation_note"
	// The check passed while an escalation was open; it is closed by id.
	EventEscalationClosed = "escalation_closed"
)

// Outcomes of an attempt.
const (
	OutcomeRepaired    = "repaired"
	OutcomeFailed      = "failed"
	OutcomeReportOnly  = "report-only"
	OutcomeInterrupted = "interrupted"
)

// Entry is one ledger line. Every field is optional except Time, Recipe and
// Event; which of the rest a line carries depends on the event.
type Entry struct {
	Time    time.Time `json:"time"`
	Recipe  string    `json:"recipe"`
	Event   string    `json:"event"`
	ID      int       `json:"id,omitempty"`
	Mode    string    `json:"mode,omitempty"`
	Word    string    `json:"word,omitempty"`
	Verdict Kind      `json:"verdict,omitempty"`
	Outcome string    `json:"outcome,omitempty"`
	Reason  string    `json:"reason,omitempty"`
	Detail  string    `json:"detail,omitempty"`
}

// Attempt is an attempt as read back: when it started, which word it ran in
// which mode, and how and when it ended, if the ledger says.
type Attempt struct {
	ID      int
	Started time.Time
	Word    string
	Mode    string
	Outcome string
	Ended   time.Time
	Detail  string
}

// Escalation is the most recent escalation as read back, open or closed: the
// one fact the case is built from (case.go). Opened is the time of its opening
// line, or of its oldest surviving note when the opening line has been
// trimmed. Notes counts the failing ticks appended to it.
type Escalation struct {
	ID           int
	Opened       time.Time
	Reason       string
	Notes        int
	LastNote     string
	LastNoteTime time.Time
	Closed       time.Time
	CloseReason  string
}

// open reports whether the escalation has no closing line.
func (e Escalation) open() bool { return e.ID != 0 && e.Closed.IsZero() }

// finished reports whether the attempt has an outcome line.
func (a Attempt) finished() bool { return a.Outcome != "" }

// AttemptLedger is one recipe's read-back ledger, opened for one tick. It
// is distinct from primitives/ledger.go, which records restores.
type AttemptLedger struct {
	recipe string
	path   string
	now    func() time.Time

	attempts     []Attempt
	openEscalate int // id of the open escalation, 0 for none
	latest       *Escalation
	nextID       int
	// lastPass is when the failing run last ended: the newest passing check,
	// verified repair or closed escalation. The attempts after it are the
	// run the budget counts (AttemptsInRun); zero when the ledger holds none.
	lastPass time.Time
}

// openLedger reads a recipe's ledger back, creating the directory when it is
// absent. It refuses — returns an error and no ledger — when the directory
// exists and is not this user's alone, because a ledger anyone else could
// write is a budget anyone else could spend.
func openLedger(recipe string, now func() time.Time) (*AttemptLedger, error) {
	if err := os.MkdirAll(LedgerDir, 0o700); err != nil {
		return nil, fmt.Errorf("ledger directory %s: %v", LedgerDir, err)
	}
	if err := trustedDir(LedgerDir); err != nil {
		return nil, fmt.Errorf("ledger directory %s is not trusted: %v", LedgerDir, err)
	}
	l := &AttemptLedger{
		recipe: recipe,
		path:   filepath.Join(LedgerDir, recipe+".jsonl"),
		now:    now,
		nextID: 1,
	}
	if err := l.readBack(); err != nil {
		return nil, err
	}
	return l, nil
}

// readBack replays the file into attempts and the open escalation. A line
// that does not parse is skipped, never fatal: the ledger is the agent's own
// record and a damaged line is a lost line, not a reason to stop checking.
func (l *AttemptLedger) readBack() error {
	f, err := os.Open(l.path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("ledger %s: %v", l.path, err)
	}
	defer f.Close()

	byID := map[int]int{} // attempt id -> index in l.attempts
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		var e Entry
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
			continue
		}
		if e.ID >= l.nextID {
			l.nextID = e.ID + 1
		}
		switch e.Event {
		case EventCheck:
			if e.Verdict == Pass {
				l.lastPass = e.Time
			}
		case EventAttempt:
			byID[e.ID] = len(l.attempts)
			l.attempts = append(l.attempts, Attempt{ID: e.ID, Started: e.Time, Word: e.Word, Mode: e.Mode})
		case EventOutcome:
			if i, ok := byID[e.ID]; ok {
				l.attempts[i].Outcome = e.Outcome
				l.attempts[i].Ended = e.Time
				l.attempts[i].Detail = e.Detail
			}
			if e.Outcome == OutcomeRepaired {
				l.lastPass = e.Time
			}
		case EventEscalation:
			l.openEscalate = e.ID
			l.latest = &Escalation{ID: e.ID, Opened: e.Time, Reason: e.Reason}
		case EventEscalationNote:
			// A note carries the id of the escalation it was appended to, and
			// an escalation only takes notes while it is open. So a note is
			// evidence the escalation is open — and it is the only evidence
			// that survives a trim once the opening line has aged out of the
			// newest half of the cap (an escalation held open for weeks
			// outlives its own first line).
			l.openEscalate = e.ID
			if l.latest == nil || l.latest.ID != e.ID {
				l.latest = &Escalation{ID: e.ID, Opened: e.Time, Reason: e.Reason}
			}
			l.latest.Notes++
			l.latest.LastNote = e.Reason
			l.latest.LastNoteTime = e.Time
		case EventEscalationClosed:
			if l.openEscalate == e.ID {
				l.openEscalate = 0
			}
			if l.latest != nil && l.latest.ID == e.ID {
				l.latest.Closed = e.Time
				l.latest.CloseReason = e.Reason
			}
			l.lastPass = e.Time
		}
	}
	return scanner.Err()
}

// finishInterrupted gives every attempt that has no outcome the outcome
// "interrupted": the agent that started it did not live to record how it
// ended, so it is a failed attempt against the budget. Called once, when the
// loop first opens a recipe's ledger in this process; within a process every
// attempt is completed by the tick that started it.
func (l *AttemptLedger) finishInterrupted() int {
	n := 0
	for i := range l.attempts {
		if l.attempts[i].finished() {
			continue
		}
		l.attempts[i].Outcome = OutcomeInterrupted
		l.attempts[i].Ended = l.now()
		l.write(Entry{
			Event:   EventOutcome,
			ID:      l.attempts[i].ID,
			Outcome: OutcomeInterrupted,
			Reason:  "the agent stopped before this attempt recorded an outcome; counted as failed",
		})
		n++
	}
	return n
}

// AttemptsSince returns the attempts started at or after t, oldest first.
// Every attempt counts — repaired, failed, report-only and interrupted alike.
func (l *AttemptLedger) AttemptsSince(t time.Time) []Attempt {
	var out []Attempt
	for _, a := range l.attempts {
		if !a.Started.Before(t) {
			out = append(out, a)
		}
	}
	return out
}

// AttemptsInRun returns the attempts of the current failing run: those
// started since the check last passed, a repair last verified, or the last
// escalation closed — whichever is newest — oldest first. The budget counts
// these, not the attempts of the last hour: with ten-minute ticks and waits
// of ten and thirty minutes, the first attempt of a run is older than an
// hour by the time the third one lands, so an hour's window could never
// hold three and the escalation was unreachable on a real clock (docker-prod
// host, 2026-09-15: six report-only attempts, no case).
func (l *AttemptLedger) AttemptsInRun() []Attempt {
	var out []Attempt
	for _, a := range l.attempts {
		if a.Started.After(l.lastPass) {
			out = append(out, a)
		}
	}
	return out
}

// OpenEscalation is the id of the open escalation, or 0.
func (l *AttemptLedger) OpenEscalation() int { return l.openEscalate }

// Latest is the most recent escalation the ledger records, open or closed, or
// nil when it records none. A copy: the case built from it is a snapshot.
func (l *AttemptLedger) Latest() *Escalation {
	if l.latest == nil {
		return nil
	}
	e := *l.latest
	return &e
}

// beginAttempt appends the attempt line and returns its id.
func (l *AttemptLedger) beginAttempt(word, mode string) int {
	id := l.nextID
	l.nextID++
	l.attempts = append(l.attempts, Attempt{ID: id, Started: l.now(), Word: word, Mode: mode})
	l.write(Entry{Event: EventAttempt, ID: id, Word: word, Mode: mode})
	return id
}

// endAttempt appends the outcome line for id.
func (l *AttemptLedger) endAttempt(id int, outcome, detail string) {
	for i := range l.attempts {
		if l.attempts[i].ID == id {
			l.attempts[i].Outcome = outcome
			l.attempts[i].Ended = l.now()
			l.attempts[i].Detail = bounded(detail)
		}
	}
	if outcome == OutcomeRepaired {
		l.lastPass = l.now()
	}
	l.write(Entry{Event: EventOutcome, ID: id, Outcome: outcome, Detail: detail})
}

// openEscalation appends the escalation line and returns its id.
func (l *AttemptLedger) openEscalation(reason string) int {
	id := l.nextID
	l.nextID++
	l.openEscalate = id
	l.latest = &Escalation{ID: id, Opened: l.now().UTC(), Reason: bounded(reason)}
	l.write(Entry{Event: EventEscalation, ID: id, Reason: reason})
	return id
}

// noteEscalation appends a failing tick to the open escalation by id.
func (l *AttemptLedger) noteEscalation(reason string) {
	if l.openEscalate == 0 {
		return
	}
	if l.latest != nil && l.latest.ID == l.openEscalate {
		l.latest.Notes++
		l.latest.LastNote = bounded(reason)
		l.latest.LastNoteTime = l.now().UTC()
	}
	l.write(Entry{Event: EventEscalationNote, ID: l.openEscalate, Reason: reason})
}

// closeEscalation appends the closing line for the open escalation.
func (l *AttemptLedger) closeEscalation(reason string) {
	if l.openEscalate == 0 {
		return
	}
	if l.latest != nil && l.latest.ID == l.openEscalate {
		l.latest.Closed = l.now().UTC()
		l.latest.CloseReason = bounded(reason)
	}
	l.write(Entry{Event: EventEscalationClosed, ID: l.openEscalate, Reason: reason})
	l.openEscalate = 0
	l.lastPass = l.now()
}

// note appends any other line: a check, a held tick, a busy tick, an
// escalation note. A passing check ends the run.
func (l *AttemptLedger) note(e Entry) {
	if e.Event == EventCheck && e.Verdict == Pass {
		l.lastPass = l.now()
	}
	l.write(e)
}

// write appends one line to the read-back file and to the outward copy. Time
// and recipe are filled here so no caller can write a line for another
// recipe or at another time.
func (l *AttemptLedger) write(e Entry) {
	e.Time = l.now().UTC()
	e.Recipe = l.recipe
	e.Reason = bounded(e.Reason)
	e.Detail = bounded(e.Detail)
	line, err := json.Marshal(e)
	if err != nil {
		return
	}
	line = append(line, '\n')

	appendCapped(l.path, line, 0o600)
	if OutwardDir != "" {
		if err := os.MkdirAll(OutwardDir, 0o755); err == nil {
			appendCapped(filepath.Join(OutwardDir, l.recipe+".jsonl"), line, 0o644)
		}
	}
}

// appendCapped appends line to path, first trimming the file to the newest
// half of LedgerMaxBytes when the append would take it past the cap. The trim
// is a rewrite through a temp file and a rename, so a reader never sees a
// half-written ledger. Errors are dropped: the ledger is best-effort on the
// write side; it is the READ side that fails closed (openLedger).
func appendCapped(path string, line []byte, perm os.FileMode) {
	if info, err := os.Stat(path); err == nil && info.Size()+int64(len(line)) > LedgerMaxBytes {
		trimToNewest(path, LedgerMaxBytes/2, perm)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, perm)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(line)
}

// trimToNewest keeps the newest whole lines of path that fit in keep bytes.
func trimToNewest(path string, keep int, perm os.FileMode) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return
	}
	if len(raw) > keep {
		raw = raw[len(raw)-keep:]
		if i := bytes.IndexByte(raw, '\n'); i >= 0 {
			raw = raw[i+1:]
		}
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, perm); err != nil {
		return
	}
	_ = os.Rename(tmp, path)
}

// bounded caps a free-text field.
func bounded(s string) string {
	if len(s) <= maxDetailBytes {
		return s
	}
	return s[:maxDetailBytes] + "…"
}

// trustedDir reports whether path is a directory that only this process's
// user could have written into: owned by that user (root, in production)
// and with no write bit for group or other. The same test LoadPolicy applies
// to the policy file, for the same reason: data on disk may narrow the agent,
// and only root's data may.
func trustedDir(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("not a directory")
	}
	if perm := info.Mode().Perm(); perm&0o022 != 0 {
		return fmt.Errorf("writable by group or other (mode %04o)", perm)
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Getuid() {
		return fmt.Errorf("owned by uid %d, not uid %d", st.Uid, os.Getuid())
	}
	return nil
}
