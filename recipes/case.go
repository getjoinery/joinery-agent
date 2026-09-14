package recipes

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"joinery-agent/primitives"
)

// The case (specs/agent_tier1_recipes.md, "The case" and settled Q3).
//
// A case IS the ledger's escalation, given a body and a delivery. It has no
// id of its own and no open/closed state of its own: the id is the
// escalation's node-minted id, it is open while the escalation has no closing
// line, and the recipe's check passing again is the one thing that closes it.
// The plane is told; the plane never tells the node a fault is gone.
//
// What rides the claim is the node's own statement of fact, in the same
// spirit as the vocabulary and the recipe list: for each source, the most
// recent escalation — open or closed — as a small summary the plane can
// compare against what it stored, plus the body once. The body (the attempts
// that spent the budget, a fresh host_report, the vocabulary and recipe list)
// is composed when the escalation opens and sent until a claim carrying it
// succeeds; a restarted agent composes it again and the plane treats a body
// on a known id as a refresh. The summary of a closed case rides on every
// claim until the next escalation replaces it, so a close is never lost to a
// plane that was not listening when it happened, and nothing here needs a
// delivery record on disk.
//
// One open case per recipe is a property of the loop, not of this file: a
// second escalation cannot open while one is open (loop.go), so a failing
// tick while a case is open is a note appended by id, never a new case.
//
// Every field is capped here, before it leaves, because the channel caps the
// claim body at 256 KiB and a claim carrying two cases beside the usual
// extras must fit with room.
//
// The source field names who opened the case. A recipe's case is
// "recipe:<name>". The unexplained-root classifier
// (specs/node_unexplained_root.md) is not built; the case it will open is
// this same object with its own source, so the field is a string and not a
// recipe name.

// Wire caps. A case is at most maxCaseBytes as JSON; the whole cases field is
// at most maxCasesBytes. When the field would exceed that, bodies are dropped
// (newest case first) until it fits: the summaries always ride.
const (
	maxCaseAttempts        = 10
	maxCaseAttemptDetail   = 1024
	maxCaseReasonBytes     = 512
	maxCaseHostReportBytes = 8 * 1024
	maxCaseBytes           = 32 * 1024
	maxCasesBytes          = 64 * 1024
)

// CaseStatus is open or closed, and nothing else.
type CaseStatus string

const (
	CaseOpen   CaseStatus = "open"
	CaseClosed CaseStatus = "closed"
)

// CaseSourceRecipe prefixes a recipe's source: "recipe:fail2ban".
const CaseSourceRecipe = "recipe:"

// CaseAttempt is one attempt from the ledger as it rides in a case. Times are
// RFC 3339 strings so an absent one is absent rather than the zero time.
type CaseAttempt struct {
	ID      int    `json:"id"`
	Started string `json:"started"`
	Word    string `json:"word"`
	Mode    string `json:"mode,omitempty"`
	Outcome string `json:"outcome"`
	Ended   string `json:"ended,omitempty"`
	Detail  string `json:"detail,omitempty"`
}

// CaseBody is the part of a case that is composed once, when the escalation
// opens: what the recipe tried, what the machine looked like, what this
// agent can do.
type CaseBody struct {
	Mode string `json:"mode"`
	// Attempts are the attempts that spent the budget: those started within
	// one budget window before the escalation opened, and any after. Newest
	// maxCaseAttempts.
	Attempts []CaseAttempt `json:"attempts"`
	// HostReport is the host_report word's object, run fresh when the body is
	// composed, or a JSON string beginning "unknown:" when the word could not
	// answer, or "omitted:" when its answer was over the cap.
	HostReport json.RawMessage `json:"host_report"`
	Vocabulary string          `json:"vocabulary"`
	Recipes    string          `json:"recipes"`
}

// Case is one case as it rides the claim and as it is rendered outward.
type Case struct {
	ID           int        `json:"id"`
	Source       string     `json:"source"`
	Recipe       string     `json:"recipe,omitempty"`
	Status       CaseStatus `json:"status"`
	Opened       string     `json:"opened"`
	Reason       string     `json:"reason"`
	Notes        int        `json:"notes"`
	LastNote     string     `json:"last_note,omitempty"`
	LastNoteTime string     `json:"last_note_time,omitempty"`
	Closed       string     `json:"closed,omitempty"`
	CloseReason  string     `json:"close_reason,omitempty"`
	Body         *CaseBody  `json:"body,omitempty"`
}

// caseOf builds the summary of an escalation for a recipe.
func caseOf(r Recipe, e Escalation) Case {
	c := Case{
		ID:     e.ID,
		Source: CaseSourceRecipe + r.Name,
		Recipe: r.Name,
		Status: CaseOpen,
		Opened: wireTime(e.Opened),
		Reason: capText(e.Reason, maxCaseReasonBytes),
		Notes:  e.Notes,
	}
	if e.Notes > 0 {
		c.LastNote = capText(e.LastNote, maxCaseReasonBytes)
		c.LastNoteTime = wireTime(e.LastNoteTime)
	}
	if !e.open() {
		c.Status = CaseClosed
		c.Closed = wireTime(e.Closed)
		c.CloseReason = capText(e.CloseReason, maxCaseReasonBytes)
	}
	return c
}

func wireTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func capText(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// composeBody builds the body of a case for recipe r whose escalation opened
// at opened: the attempts around it from the ledger, a fresh host_report
// through the recipe's own environment, and this agent's lists.
func (l *Loop) composeBody(ctx context.Context, r Recipe, led *AttemptLedger, opened time.Time) *CaseBody {
	mode := ModeArmed
	if l.reportOnly {
		mode = ModeReportOnly
	}
	body := &CaseBody{
		Mode:       mode,
		Attempts:   []CaseAttempt{},
		HostReport: freshHostReport(ctx, l.env),
		Vocabulary: strings.Join(primitives.Names(), ","),
		Recipes:    Report(),
	}
	attempts := led.AttemptsSince(opened.Add(-budgetWindow))
	if len(attempts) > maxCaseAttempts {
		attempts = attempts[len(attempts)-maxCaseAttempts:]
	}
	for _, a := range attempts {
		body.Attempts = append(body.Attempts, CaseAttempt{
			ID:      a.ID,
			Started: wireTime(a.Started),
			Word:    a.Word,
			Mode:    a.Mode,
			Outcome: a.Outcome,
			Ended:   wireTime(a.Ended),
			Detail:  capText(a.Detail, maxCaseAttemptDetail),
		})
	}
	return body
}

// freshHostReport runs host_report and returns its object, capped, or a JSON
// string saying why there is none. It goes through the same Env.Run every
// check does, so a policy that refuses the word refuses it here too.
func freshHostReport(ctx context.Context, env *Env) json.RawMessage {
	result, err := env.Run(ctx, "host_report")
	return hostReportFromResult(result, err)
}

// hostReportFromResult reads a host_report result into the case's field.
func hostReportFromResult(result map[string]interface{}, err error) json.RawMessage {
	unknown := func(why string) json.RawMessage {
		raw, _ := json.Marshal(capText("unknown: "+why, maxCaseReasonBytes))
		return raw
	}
	if err != nil {
		return unknown(err.Error())
	}
	output, _ := result["output"].(string)
	output = strings.TrimSpace(output)
	if !json.Valid([]byte(output)) || !strings.HasPrefix(output, "{") {
		return unknown("host_report did not answer with a JSON object")
	}
	if len(output) > maxCaseHostReportBytes {
		raw, _ := json.Marshal(fmt.Sprintf("omitted: the host report is %d bytes, over the %d-byte cap", len(output), maxCaseHostReportBytes))
		return raw
	}
	return json.RawMessage(output)
}

// caseBoard is what the claim reads: per source, the most recent case, with
// its body until a claim carrying the body has succeeded. Written by the loop
// on its ticks, read by the remote source on its polls, so it locks.
type caseBoard struct {
	mu      sync.Mutex
	entries map[string]*boardEntry
}

type boardEntry struct {
	c             Case
	body          *CaseBody
	bodyDelivered bool
}

// board is the one board in the process. Package-level because the loop and
// the remote source are built in different places and neither owns the other;
// tests swap it with useTestBoard.
var board = &caseBoard{entries: map[string]*boardEntry{}}

// post replaces the board's case for c.Source. A body, when given, rides the
// next claims until one succeeds; a nil body keeps the body already on the
// board for the same id, so a note or a close does not resend it.
func (b *caseBoard) post(c Case, body *CaseBody) {
	b.mu.Lock()
	defer b.mu.Unlock()
	prev := b.entries[c.Source]
	entry := &boardEntry{c: c, body: body}
	if body == nil && prev != nil && prev.c.ID == c.ID {
		entry.body = prev.body
		entry.bodyDelivered = prev.bodyDelivered
	}
	b.entries[c.Source] = entry
}

// forClaim is the cases field for one claim: JSON keyed by source, or nil
// when there is nothing to say. The returned function is called by the
// claimer once the claim has succeeded, and marks the bodies it carried as
// delivered; a claim that failed calls nothing and the next one carries them
// again.
func (b *caseBoard) forClaim() (json.RawMessage, func()) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.entries) == 0 {
		return nil, func() {}
	}
	sources := make([]string, 0, len(b.entries))
	for s := range b.entries {
		sources = append(sources, s)
	}
	sort.Strings(sources)

	// Newest case first, so that when the field must shed bodies to fit, the
	// oldest case loses its body first.
	sort.SliceStable(sources, func(i, j int) bool {
		return b.entries[sources[i]].c.Opened > b.entries[sources[j]].c.Opened
	})

	out := map[string]Case{}
	carried := map[string]int{} // source -> id whose body this claim carries
	for _, s := range sources {
		e := b.entries[s]
		c := e.c
		if e.body != nil && !e.bodyDelivered {
			c.Body = e.body
			if raw, err := json.Marshal(c); err != nil || len(raw) > maxCaseBytes {
				// Over the per-case cap even after every component was capped
				// at composition; a lie in the ledger or the host report.
				// The summary still rides.
				c.Body = nil
			} else {
				carried[s] = c.ID
			}
		}
		out[s] = c
	}
	raw, err := json.Marshal(out)
	if err != nil {
		return nil, func() {}
	}
	for i := len(sources) - 1; i >= 0 && len(raw) > maxCasesBytes; i-- {
		s := sources[i]
		if out[s].Body == nil {
			continue
		}
		c := out[s]
		c.Body = nil
		out[s] = c
		delete(carried, s)
		raw, _ = json.Marshal(out)
	}
	return raw, func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		for s, id := range carried {
			if e, ok := b.entries[s]; ok && e.c.ID == id {
				e.bodyDelivered = true
			}
		}
	}
}

// ClaimCases is the cases field for the next claim, or nil when this agent
// has no case to report, and the acknowledgement to call once the claim
// carrying it has succeeded.
func ClaimCases() (json.RawMessage, func()) {
	return board.forClaim()
}

// ResetCasesForTests empties the board. Tests only: a process has one board
// and a test that opened a case must not hand it to the next.
func ResetCasesForTests() {
	board.mu.Lock()
	defer board.mu.Unlock()
	board.entries = map[string]*boardEntry{}
}

// OpenCases lists the sources with an open case, for logs and tests.
func OpenCases() []string {
	board.mu.Lock()
	defer board.mu.Unlock()
	var out []string
	for s, e := range board.entries {
		if e.c.Status == CaseOpen {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// renderedCase is the record written outward: the case with its body, and
// how it is delivered, so the site's notice can say whether a management
// node has it too.
type renderedCase struct {
	Case
	Delivery string `json:"delivery"`
	Rendered string `json:"rendered"`
}

// Deliveries a rendered case names.
const (
	DeliveryPlane = "management node"
	DeliveryLocal = "local"
)

// writeOutwardCase writes the rendered copy of a recipe's case under the
// site's cache directory, beside the outward ledger: readable by the web
// user, never read back. The site renders its notice and its one daily mail
// from it (specs/agent_tier1_recipes.md, Q3 "Unpaired"). Written whole
// through a temp file and a rename, so a reader never sees half a record.
func writeOutwardCase(recipe string, c Case, body *CaseBody, paired bool, now time.Time) {
	if OutwardDir == "" {
		return
	}
	if err := os.MkdirAll(OutwardDir, 0o755); err != nil {
		return
	}
	c.Body = body
	rec := renderedCase{Case: c, Delivery: DeliveryLocal, Rendered: wireTime(now)}
	if paired {
		rec.Delivery = DeliveryPlane
	}
	raw, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return
	}
	path := OutwardCasePath(recipe)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(raw, '\n'), 0o644); err != nil {
		return
	}
	_ = os.Rename(tmp, path)
}

// OutwardCasePath is where a recipe's rendered case lands.
func OutwardCasePath(recipe string) string {
	return filepath.Join(OutwardDir, recipe+".case.json")
}
