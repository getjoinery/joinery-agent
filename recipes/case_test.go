package recipes

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// The case (specs/agent_tier1_recipes.md, "The case", settled Q3, and the
// case-storm row of "Where the bugs will live"). A case is the ledger's
// escalation with a body and a delivery: same id, same open/closed state,
// closed by the node's own check and by nothing else.

// claimed decodes the cases field as the plane would receive it.
func claimed(t *testing.T) (map[string]Case, func()) {
	t.Helper()
	raw, ack := ClaimCases()
	if raw == nil {
		return nil, ack
	}
	var out map[string]Case
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("the cases field is not the JSON object the plane validates: %v", err)
	}
	return out, ack
}

// escalate drives the harness to its first escalation (three report-only or
// armed attempts inside the hour, then a fourth failing tick).
func (h *harness) escalate() {
	before := h.count(EventEscalation)
	h.verdict = Verdict{Fail, "down"}
	h.ticks(7)
	if h.count(EventEscalation) != before+1 {
		h.t.Fatalf("setup: expected one more escalation after seven failing ticks, got %d", h.count(EventEscalation)-before)
	}
}

func TestAnEscalationIsACaseWithTheSameId(t *testing.T) {
	h := newHarness(t)
	if cases, _ := claimed(t); cases != nil {
		t.Fatal("a recipe that has never escalated has no case to report")
	}
	h.escalate()

	id := 0
	for _, e := range h.entries() {
		if e.Event == EventEscalation {
			id = e.ID
		}
	}
	cases, _ := claimed(t)
	c, ok := cases["recipe:probe"]
	if !ok || len(cases) != 1 {
		t.Fatalf("expected exactly the case recipe:probe, got %v", cases)
	}
	if c.ID != id {
		t.Fatalf("the case id is the escalation's id %d, got %d", id, c.ID)
	}
	if c.Status != CaseOpen || c.Source != "recipe:probe" || c.Recipe != "probe" || c.Opened == "" || c.Reason == "" {
		t.Errorf("the case summary is incomplete: %+v", c)
	}
	if c.Body == nil {
		t.Fatal("the first claim after an escalation carries the body")
	}
	if c.Body.Mode != ModeArmed {
		t.Errorf("the body says which mode the loop ran in, got %q", c.Body.Mode)
	}
	if len(c.Body.Attempts) != 3 {
		t.Fatalf("the body carries the three attempts that spent the budget, got %d", len(c.Body.Attempts))
	}
	for _, a := range c.Body.Attempts {
		if a.Word != "host_converge" || a.Outcome == "" || a.Started == "" || a.Ended == "" {
			t.Errorf("an attempt in the body carries time, word and result: %+v", a)
		}
	}
	var hr string
	if err := json.Unmarshal(c.Body.HostReport, &hr); err != nil || !strings.HasPrefix(hr, "unknown:") {
		t.Errorf("with no execution environment the host report is an unknown string, got %s", c.Body.HostReport)
	}
	if !strings.Contains(","+c.Body.Vocabulary+",", ",host_report,") || c.Body.Recipes != Report() {
		t.Errorf("the body carries this agent's vocabulary and recipe list, got %q / %q", c.Body.Vocabulary, c.Body.Recipes)
	}
	if h.logged("case #") != 1 {
		t.Error("opening a case is one log line")
	}
}

func TestOneOpenCasePerRecipeAndAFailingTickIsANote(t *testing.T) {
	// The case storm: one broken thing must not open a case every tick.
	h := newHarness(t)
	h.escalate()
	first, _ := claimed(t)
	before := first["recipe:probe"]

	h.ticks(20)
	if n := h.count(EventEscalation); n != 1 {
		t.Fatalf("a case storm: %d escalations for one fault", n)
	}
	cases, _ := claimed(t)
	if len(cases) != 1 {
		t.Fatalf("one open case per recipe; the claim carries %d", len(cases))
	}
	c := cases["recipe:probe"]
	if c.ID != before.ID {
		t.Fatalf("the case id changed from %d to %d while the fault persisted", before.ID, c.ID)
	}
	if c.Notes != 20 || c.LastNote == "" || c.LastNoteTime == "" {
		t.Errorf("twenty failing ticks under an open case are twenty notes on it, got %d (%q at %q)", c.Notes, c.LastNote, c.LastNoteTime)
	}
	if c.Status != CaseOpen {
		t.Error("the case stays open while the check fails")
	}
	if len(OpenCases()) != 1 {
		t.Errorf("OpenCases: %v", OpenCases())
	}
}

func TestTheBodyRidesUntilAClaimCarryingItSucceeds(t *testing.T) {
	h := newHarness(t)
	h.escalate()

	first, ack := claimed(t)
	if first["recipe:probe"].Body == nil {
		t.Fatal("the body rides the first claim")
	}
	// The claim failed (the ack was never called): the body rides again.
	again, ack := claimed(t)
	if again["recipe:probe"].Body == nil {
		t.Fatal("a claim that did not succeed leaves the body to ride again")
	}
	ack()
	third, _ := claimed(t)
	if third["recipe:probe"].Body != nil {
		t.Fatal("once a claim carrying the body succeeded, the summary rides alone")
	}
	// A note changes the summary, not the body: still no body.
	h.tick()
	fourth, _ := claimed(t)
	if fourth["recipe:probe"].Body != nil || fourth["recipe:probe"].Notes != 1 {
		t.Errorf("a note updates the summary without resending the body: %+v", fourth["recipe:probe"])
	}
}

func TestTheNodeClosesTheCaseAndTheCloseRidesEveryClaimAfter(t *testing.T) {
	h := newHarness(t)
	h.escalate()
	_, ack := claimed(t)
	ack()

	h.verdict = Verdict{Pass, "up"}
	h.tick()
	cases, _ := claimed(t)
	c := cases["recipe:probe"]
	if c.Status != CaseClosed || c.Closed == "" || !strings.Contains(c.CloseReason, "passes") {
		t.Fatalf("the check passing closes the case: %+v", c)
	}
	if c.Body != nil {
		t.Error("a close carries no body")
	}
	if len(OpenCases()) != 0 {
		t.Error("a closed case is not open")
	}
	// Ten passing ticks later the close is still stated: a plane that was not
	// listening when it happened hears it on its next successful claim.
	h.ticks(10)
	later, _ := claimed(t)
	if later["recipe:probe"].Status != CaseClosed || later["recipe:probe"].ID != c.ID {
		t.Errorf("the closed summary should ride until the next escalation replaces it: %+v", later["recipe:probe"])
	}
}

func TestTheNextEscalationReplacesTheClosedCase(t *testing.T) {
	h := newHarness(t)
	h.escalate()
	h.verdict = Verdict{Pass, "up"}
	h.tick()
	closedID := 0
	if cases, _ := claimed(t); cases["recipe:probe"].Status != CaseClosed {
		t.Fatal("setup: expected the case closed")
	} else {
		closedID = cases["recipe:probe"].ID
	}
	h.now = h.now.Add(2 * time.Hour) // the budget refills
	h.escalate()
	cases, _ := claimed(t)
	c := cases["recipe:probe"]
	if c.ID <= closedID || c.Status != CaseOpen || c.Body == nil {
		t.Fatalf("a new escalation is a new case with a higher id and its own body: %+v (closed was %d)", c, closedID)
	}
	if len(cases) != 1 {
		t.Error("still one case per recipe")
	}
}

func TestARestartComposesAnOpenCaseAgainAndKeepsItsId(t *testing.T) {
	h := newHarness(t)
	h.escalate()
	before, ack := claimed(t)
	ack()

	// A new process: the board is empty, the ledger is not.
	ResetCasesForTests()
	h.restart()
	if cases, _ := claimed(t); cases != nil {
		t.Fatal("setup: a fresh process has nothing on the board until its first tick")
	}
	h.tick()
	cases, _ := claimed(t)
	c := cases["recipe:probe"]
	if c.ID != before["recipe:probe"].ID {
		t.Fatalf("the restarted process invented a new case id %d for escalation %d", c.ID, before["recipe:probe"].ID)
	}
	if c.Status != CaseOpen || c.Body == nil || len(c.Body.Attempts) != 3 {
		t.Errorf("the restarted process composes the body again, with the attempts from the ledger: %+v", c)
	}
	if c.Notes != 1 {
		t.Errorf("the first tick after the restart failed, so it is a note: %d", c.Notes)
	}
}

func TestARestartAfterACloseStillReportsTheClose(t *testing.T) {
	h := newHarness(t)
	h.escalate()
	h.verdict = Verdict{Pass, "up"}
	h.tick() // closed in the ledger; suppose the agent restarts before a claim
	ResetCasesForTests()
	h.restart()
	h.tick()
	cases, _ := claimed(t)
	c := cases["recipe:probe"]
	if c.Status != CaseClosed || c.Closed == "" {
		t.Fatalf("a close recorded before a restart still rides after it: %+v", c)
	}
	if c.Body != nil {
		t.Error("a closed case found at start has no body to send")
	}
}

func TestReportOnlyEscalationsOpenCasesJustTheSame(t *testing.T) {
	// The burn-in's product: a report-only loop that opened a case is a loop
	// that would have given up, on a node that shows it.
	h := newHarness(t)
	h.loop.reportOnly = true
	h.escalate()
	if h.repairs != 0 {
		t.Fatal("report-only ran a repair")
	}
	cases, _ := claimed(t)
	c := cases["recipe:probe"]
	if c.Status != CaseOpen || c.Body == nil || c.Body.Mode != ModeReportOnly {
		t.Fatalf("a report-only escalation is an open case that says report-only: %+v", c)
	}
	for _, a := range c.Body.Attempts {
		if a.Outcome != OutcomeReportOnly {
			t.Errorf("every attempt in a report-only case says so: %+v", a)
		}
	}
}

func TestEveryFieldOfACaseIsCappedBeforeItLeaves(t *testing.T) {
	h := newHarness(t)
	h.verdict = Verdict{Fail, strings.Repeat("r", 10*1024)}
	h.repair = errors.New(strings.Repeat("d", 100*1024))
	h.ticks(7)
	cases, _ := claimed(t)
	c := cases["recipe:probe"]
	raw, _ := json.Marshal(c)
	if len(raw) > maxCaseBytes {
		t.Fatalf("a case is %d bytes on the wire, over the %d cap", len(raw), maxCaseBytes)
	}
	if len(c.Reason) > maxCaseReasonBytes+3 || len(c.LastNote) > maxCaseReasonBytes+3 {
		t.Error("the reason and the last note are capped")
	}
	for _, a := range c.Body.Attempts {
		if len(a.Detail) > maxCaseAttemptDetail+3 {
			t.Errorf("an attempt's detail is capped: %d bytes", len(a.Detail))
		}
	}
}

func TestTheHostReportInACaseIsTheObjectOrASayingWhyNot(t *testing.T) {
	object := `{"expected_units":{"fail2ban":"active"},"fail2ban_jails":[{"name":"sshd","banned":3}]}`
	cases := []struct {
		label  string
		result map[string]interface{}
		err    error
		want   string // prefix of the JSON string, or "" for the object
	}{
		{"the word's object rides as it is", map[string]interface{}{"output": object}, nil, ""},
		{"a refused word is unknown", nil, errors.New("policy refuses"), `"unknown: policy refuses`},
		{"a non-JSON answer is unknown", map[string]interface{}{"output": "not json"}, nil, `"unknown: host_report did not`},
		{"a JSON array is not the object", map[string]interface{}{"output": "[1,2]"}, nil, `"unknown: host_report did not`},
		{"an over-cap object is omitted, not sent", map[string]interface{}{"output": `{"x":"` + strings.Repeat("y", maxCaseHostReportBytes) + `"}`}, nil, `"omitted:`},
	}
	for _, tc := range cases {
		got := hostReportFromResult(tc.result, tc.err)
		if !json.Valid(got) {
			t.Errorf("%s: the field must be valid JSON, got %s", tc.label, got)
			continue
		}
		if tc.want == "" {
			if string(got) != object {
				t.Errorf("%s: got %s", tc.label, got)
			}
		} else if !strings.HasPrefix(string(got), tc.want) {
			t.Errorf("%s: got %s, want prefix %s", tc.label, got, tc.want)
		}
		if len(got) > maxCaseHostReportBytes {
			t.Errorf("%s: %d bytes, over the cap", tc.label, len(got))
		}
	}
}

func TestTheCasesFieldShedsBodiesToFitTheChannel(t *testing.T) {
	ResetCasesForTests()
	t.Cleanup(ResetCasesForTests)
	big := &CaseBody{Mode: ModeArmed, HostReport: json.RawMessage(`"` + strings.Repeat("h", maxCaseHostReportBytes-2) + `"`)}
	for i := 0; i < maxCaseAttempts; i++ {
		big.Attempts = append(big.Attempts, CaseAttempt{ID: i + 1, Word: "host_converge", Outcome: OutcomeFailed, Detail: strings.Repeat("d", maxCaseAttemptDetail)})
	}
	for i := 0; i < 4; i++ {
		c := Case{ID: i + 1, Source: "recipe:r" + string(rune('a'+i)), Status: CaseOpen, Opened: time.Date(2026, 9, 14, 12, i, 0, 0, time.UTC).Format(time.RFC3339), Reason: "x"}
		board.post(c, big)
	}
	raw, ack := ClaimCases()
	if len(raw) > maxCasesBytes {
		t.Fatalf("the cases field is %d bytes, over the %d cap", len(raw), maxCasesBytes)
	}
	var out map[string]Case
	json.Unmarshal(raw, &out)
	if len(out) != 4 {
		t.Fatal("every summary rides even when bodies are shed")
	}
	withBody, without := 0, 0
	for _, c := range out {
		if c.Body != nil {
			withBody++
		} else {
			without++
		}
	}
	if withBody == 0 || without == 0 {
		t.Errorf("expected some bodies shed and some kept, got %d with and %d without", withBody, without)
	}
	if out["recipe:rd"].Body == nil {
		t.Error("the newest case keeps its body; the oldest sheds first")
	}
	// Once that claim succeeds, the bodies it carried are done and the shed
	// one rides next.
	ack()
	raw, _ = ClaimCases()
	json.Unmarshal(raw, &out)
	for s, c := range out {
		if s == "recipe:ra" {
			if c.Body == nil {
				t.Error("recipe:ra's body was shed, so it rides the next claim")
			}
			continue
		}
		if c.Body != nil {
			t.Errorf("%s: its body was carried by a claim that succeeded and rides no more", s)
		}
	}
}

func TestTheRenderedCaseIsWrittenOutwardAndNeverReadBack(t *testing.T) {
	h := newHarness(t)
	h.escalate()
	raw, err := os.ReadFile(OutwardCasePath("probe"))
	if err != nil {
		t.Fatalf("the rendered case should be under the site's cache directory: %v", err)
	}
	var rec renderedCase
	if err := json.Unmarshal(raw, &rec); err != nil {
		t.Fatal(err)
	}
	if rec.Status != CaseOpen || rec.Body == nil || rec.Delivery != DeliveryLocal || rec.Rendered == "" {
		t.Errorf("the rendered case carries the whole record and its delivery: %+v", rec)
	}
	if info, _ := os.Stat(OutwardCasePath("probe")); info.Mode().Perm()&0o044 != 0o044 {
		t.Error("the rendered case is readable by the site")
	}
	if _, err := os.Stat(OutwardCasePath("probe") + ".tmp"); !os.IsNotExist(err) {
		t.Error("the write left its temp file behind")
	}

	// A note rewrites it with the same body; a close rewrites it closed.
	h.tick()
	raw, _ = os.ReadFile(OutwardCasePath("probe"))
	json.Unmarshal(raw, &rec)
	if rec.Notes != 1 || rec.Body == nil {
		t.Errorf("a note rewrites the rendered case with the body kept: %+v", rec)
	}
	h.verdict = Verdict{Pass, "up"}
	h.tick()
	raw, _ = os.ReadFile(OutwardCasePath("probe"))
	json.Unmarshal(raw, &rec)
	if rec.Status != CaseClosed {
		t.Errorf("a close rewrites the rendered case closed: %+v", rec)
	}

	// A forged rendered case changes nothing the node believes or claims.
	forged := `{"id":99,"source":"recipe:probe","status":"open","opened":"2026-01-01T00:00:00Z","reason":"forged","delivery":"local"}`
	if err := os.WriteFile(OutwardCasePath("probe"), []byte(forged), 0o644); err != nil {
		t.Fatal(err)
	}
	ResetCasesForTests()
	h.restart()
	h.tick()
	cases, _ := claimed(t)
	if cases["recipe:probe"].ID == 99 || cases["recipe:probe"].Status != CaseClosed {
		t.Errorf("the outward record must never be read: %+v", cases["recipe:probe"])
	}
}

func TestTheRenderedCaseSaysWhenAManagementNodeHasIt(t *testing.T) {
	h := newHarness(t)
	opts := h.options()
	opts.Paired = func() bool { return true }
	h.loop = NewLoop([]Recipe{h.recipe}, nil, opts)
	h.loop.reportOnly = false
	h.escalate()
	raw, _ := os.ReadFile(OutwardCasePath("probe"))
	var rec renderedCase
	json.Unmarshal(raw, &rec)
	if rec.Delivery != DeliveryPlane {
		t.Errorf("a paired node's rendered case says the management node has it, got %q", rec.Delivery)
	}
}
