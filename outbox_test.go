package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// Every test in this package that posts a result writes to the outbox, so the
// whole package points it at a temporary directory: no test may touch the real
// /etc/joinery-agent.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "agent-outbox-")
	if err != nil {
		panic(err)
	}
	resultOutboxDir = filepath.Join(dir, "outbox")
	// No test may ask the real systemd what the machine is doing.
	detachedWorkRunning = func(context.Context) bool { return false }
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// useOutbox gives one test an empty outbox of its own.
func useOutbox(t *testing.T) string {
	t.Helper()
	restore := resultOutboxDir
	resultOutboxDir = filepath.Join(t.TempDir(), "outbox")
	t.Cleanup(func() { resultOutboxDir = restore })
	return resultOutboxDir
}

// fakePlane answers results with the status the test sets, and records what
// reached each path.
type fakePlane struct {
	mu           sync.Mutex
	resultStatus int
	results      []map[string]interface{}
	claims       []map[string]interface{}
}

func (p *fakePlane) server(t *testing.T) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		raw, _ := io.ReadAll(req.Body)
		var body map[string]interface{}
		_ = json.Unmarshal(raw, &body)
		p.mu.Lock()
		defer p.mu.Unlock()
		switch req.URL.Path {
		case pathResult:
			p.results = append(p.results, body)
			switch {
			case p.resultStatus == 0 || p.resultStatus == 200:
				w.Write([]byte(`{"api_version":"1.0","data":{"recorded":true}}`))
			case p.resultStatus >= 500:
				// What getjoinery answered while B47 had broken it: an error page.
				w.WriteHeader(p.resultStatus)
				w.Write([]byte(`<html>An Error Occurred</html>`))
			default:
				w.WriteHeader(p.resultStatus)
				w.Write([]byte(`{"error":"That job is not currently claimed by this node."}`))
			}
		case pathClaim:
			p.claims = append(p.claims, body)
			w.Write([]byte(`{"api_version":"1.0","data":{"job":null}}`))
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(s.Close)
	return s
}

func (p *fakePlane) set(status int) {
	p.mu.Lock()
	p.resultStatus = status
	p.mu.Unlock()
}

func kept(t *testing.T) []keptResult {
	t.Helper()
	return keptResults()
}

// The case that wedged getjoinery: the job finished, its one post landed on a
// management node that answered with an error page. The result must survive,
// and the next poll must deliver it before claiming anything.
func TestAResultTheManagementNodeCannotTakeNowIsKeptAndDeliveredBeforeTheNextClaim(t *testing.T) {
	useOutbox(t)
	plane := &fakePlane{}
	plane.set(500)
	src := testSource(t, testIdentity(t, plane.server(t).URL, 7))

	src.postResult(context.Background(), 536, "completed", map[string]interface{}{"moved": true}, "done", "")
	if k := kept(t); len(k) != 1 || k[0].JobID != 536 {
		t.Fatalf("a result the management node could not take must be kept, got %v", k)
	}

	// Still broken: the poll delivers nothing and claims nothing.
	src.pollOnce(context.Background())
	if len(plane.claims) != 0 {
		t.Fatal("an agent that still owes a result must not claim: its claim would say idle while it is not")
	}
	if len(kept(t)) != 1 {
		t.Fatal("an undelivered result must stay kept")
	}

	// Mended: the poll delivers first, then claims, and says idle.
	plane.set(200)
	src.backoff = 0
	src.pollOnce(context.Background())
	if len(kept(t)) != 0 {
		t.Fatal("a delivered result must be removed from the outbox")
	}
	if len(plane.results) < 3 || plane.results[len(plane.results)-1]["job_id"] != float64(536) ||
		plane.results[len(plane.results)-1]["status"] != "completed" {
		t.Fatalf("the kept result must reach the management node as it was, got %v", plane.results)
	}
	if len(plane.claims) != 1 || plane.claims[0]["idle"] != true {
		t.Fatalf("the claim after delivery must say idle, got %v", plane.claims)
	}
}

// A restart (or a reboot) between the failed post and the next poll: a new
// process finds the result on disk and delivers it.
func TestAKeptResultOutlivesTheProcessThatKeptIt(t *testing.T) {
	useOutbox(t)
	plane := &fakePlane{}
	plane.set(503)
	url := plane.server(t).URL
	first := testSource(t, testIdentity(t, url, 7))
	first.postResult(context.Background(), 41, "failed", nil, "", "it broke")

	plane.set(200)
	second := testSource(t, testIdentity(t, url, 7))
	if !second.deliverKeptResults(context.Background()) {
		t.Fatal("a new process must deliver the result the last one kept")
	}
	if len(kept(t)) != 0 {
		t.Fatal("and then forget it")
	}
	last := plane.results[len(plane.results)-1]
	if last["job_id"] != float64(41) || last["status"] != "failed" || last["refusal_reason"] != "it broke" {
		t.Fatalf("the kept result must be the one posted, got %v", last)
	}
}

// A 4xx is the management node saying never: the job is not this node's, or
// not running, or the body is refused. Sending the same bytes again cannot
// change that, and keeping it would stop this agent claiming for good.
func TestAResultRefusedForGoodIsNotKept(t *testing.T) {
	for _, status := range []int{400, 404, 409} {
		useOutbox(t)
		plane := &fakePlane{}
		plane.set(status)
		src := testSource(t, testIdentity(t, plane.server(t).URL, 7))
		src.postResult(context.Background(), 12, "completed", nil, "", "")
		if k := kept(t); len(k) != 0 {
			t.Errorf("HTTP %d: a result refused for good must not be kept, got %v", status, k)
		}
	}
}

// And one already kept that turns out refused for good is dropped on delivery,
// so the poll goes on to claim.
func TestAKeptResultRefusedForGoodIsDroppedAndThePollClaims(t *testing.T) {
	useOutbox(t)
	plane := &fakePlane{}
	plane.set(502)
	src := testSource(t, testIdentity(t, plane.server(t).URL, 7))
	src.postResult(context.Background(), 77, "completed", nil, "", "")

	plane.set(409)
	src.backoff = 0
	src.pollOnce(context.Background())
	if len(kept(t)) != 0 {
		t.Fatal("a kept result the management node refuses for good must be dropped")
	}
	if len(plane.claims) != 1 {
		t.Fatal("and the poll must go on to claim")
	}
}

// A delivered result leaves nothing behind.
func TestADeliveredResultLeavesTheOutboxEmpty(t *testing.T) {
	useOutbox(t)
	plane := &fakePlane{}
	src := testSource(t, testIdentity(t, plane.server(t).URL, 7))
	src.postResult(context.Background(), 5, "completed", nil, "", "")
	if k := kept(t); len(k) != 0 {
		t.Fatalf("a delivered result must not stay in the outbox, got %v", k)
	}
}

// A file the agent did not write, or one cut off mid-write, can never stop the
// poll: it is removed and said.
func TestAStrayOrBrokenOutboxFileIsRemovedNotObeyed(t *testing.T) {
	dir := useOutbox(t)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "not-a-job.json"), []byte("{}"), 0o600)
	os.WriteFile(filepath.Join(dir, "9.json"), nil, 0o600)
	os.WriteFile(filepath.Join(dir, "10.json.tmp"), []byte("{"), 0o600)

	plane := &fakePlane{}
	src := testSource(t, testIdentity(t, plane.server(t).URL, 7))
	src.pollOnce(context.Background())
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatalf("stray and broken files must be removed, %d left", len(entries))
	}
	if len(plane.results) != 0 {
		t.Fatal("nothing from them may be sent")
	}
	if len(plane.claims) != 1 {
		t.Fatal("and the poll must still claim")
	}
}

// Idle is said only on a claim made with the job lock held and the outbox
// delivered — that is what makes it true. pollOnce is the only caller.
func TestTheClaimSaysIdle(t *testing.T) {
	useOutbox(t)
	plane := &fakePlane{}
	src := testSource(t, testIdentity(t, plane.server(t).URL, 7))
	src.pollOnce(context.Background())
	if len(plane.claims) != 1 || plane.claims[0]["idle"] != true {
		t.Fatalf("a claim must say idle, got %v", plane.claims)
	}
}

// A poll that finds the job lock held — a job is running — claims nothing,
// so idle is never said while a job runs.
func TestNoClaimWhileAJobHoldsTheLock(t *testing.T) {
	useOutbox(t)
	plane := &fakePlane{}
	src := testSource(t, testIdentity(t, plane.server(t).URL, 7))
	src.jobLock.Lock()
	src.pollOnce(context.Background())
	src.jobLock.Unlock()
	if len(plane.claims) != 0 {
		t.Fatal("a poll while a job holds the lock must not claim")
	}
}

func TestOnlyA4xxIsAnAnswerForGood(t *testing.T) {
	cases := map[int]bool{0: false, 200: false, 400: true, 401: true, 404: true, 409: true, 429: false, 500: false, 502: false, 503: false}
	for status, want := range cases {
		if got := planeAnsweredForGood(&planeStatusError{Status: status, msg: "plane returned HTTP x"}); got != want {
			t.Errorf("status %d: answered for good = %v, want %v", status, got, want)
		}
	}
	if planeAnsweredForGood(io.EOF) {
		t.Error("a network error is never an answer for good")
	}
	// A clock refusal is about the moment: the same bytes land once the clock moves.
	skew := &planeStatusError{Status: 401, msg: "plane returned HTTP 401 for x: That request is too far from this plane's clock. Check the node's time."}
	if planeAnsweredForGood(skew) {
		t.Error("a request refused for the clock must be sent again, not dropped")
	}
	// An identity refusal is final: it is how a result from an old identity is shed.
	stale := &planeStatusError{Status: 401, msg: "plane returned HTTP 401 for x: That request did not verify against this node's agent key."}
	if !planeAnsweredForGood(stale) {
		t.Error("an identity refusal must be final")
	}
}

// reviewer2 F1: a take_node_id result whose post failed must not be kept. The
// machine has discarded its staged identity; delivered later, the result would
// have the management node swap the rows while this machine signs as the copy.
func TestAFailedTakePostKeepsNothing(t *testing.T) {
	useOutbox(t)
	plane := &fakePlane{}
	plane.set(502)
	src := testSource(t, testIdentity(t, plane.server(t).URL, 7))
	answer, err := src.postResult(context.Background(), 88, "completed", map[string]interface{}{"staged": true, "node_id": 3}, "", "")
	if err == nil {
		t.Fatal("the post was meant to fail")
	}
	if len(kept(t)) != 1 {
		t.Fatal("an ordinary failed post keeps its result (precondition)")
	}
	if src.settleIdentityTake(88, 3, answer, err) {
		t.Fatal("a failed take must not change this machine's identity")
	}
	if k := kept(t); len(k) != 0 {
		t.Fatalf("a failed take's result must not outlive its staged identity, kept %v", k)
	}
}

// reviewer2 F3: a body nothing will take must not stop the node claiming for
// good. Past keptShedAfter it goes as its outcome alone; past keptDropAfter it
// is dropped.
func TestAnUndeliverableResultIsShedThenDropped(t *testing.T) {
	useOutbox(t)
	plane := &fakePlane{}
	plane.set(503)
	src := testSource(t, testIdentity(t, plane.server(t).URL, 7))
	src.postResult(context.Background(), 61, "completed", map[string]interface{}{"big": "facts"}, "a log", "")

	// An hour and a bit old: still refused, but now sent as the outcome alone.
	old := time.Now().Add(-keptShedAfter - time.Minute)
	os.Chtimes(outboxPath(61), old, old)
	src.backoff = 0
	src.pollOnce(context.Background())
	last := plane.results[len(plane.results)-1]
	if _, has := last["data"]; has || last["log"] != "" || last["status"] != "completed" {
		t.Fatalf("past the shed bound the result must go as its outcome alone, got %v", last)
	}
	k := kept(t)
	if len(k) != 1 || !k[0].Kept.Before(time.Now().Add(-keptShedAfter)) {
		t.Fatal("the shed result stays kept, and keeps the time it was first kept")
	}
	if len(plane.claims) != 0 {
		t.Fatal("still undelivered, so still no claim")
	}

	// A day old: dropped, and the poll goes on to claim.
	ancient := time.Now().Add(-keptDropAfter - time.Minute)
	os.Chtimes(outboxPath(61), ancient, ancient)
	src.backoff = 0
	src.pollOnce(context.Background())
	if len(kept(t)) != 0 {
		t.Fatal("past the drop bound the result must be dropped")
	}
	if len(plane.claims) != 1 {
		t.Fatal("and the node claims again")
	}
}

// reviewer2 F7: a unit a primitive started outlives this process (the data root
// move). While it runs, the machine is still doing that job's work, and the
// claim must not say idle.
func TestNoIdleWhileDetachedWorkRuns(t *testing.T) {
	useOutbox(t)
	restore := detachedWorkRunning
	detachedWorkRunning = func(context.Context) bool { return true }
	t.Cleanup(func() { detachedWorkRunning = restore })
	plane := &fakePlane{}
	src := testSource(t, testIdentity(t, plane.server(t).URL, 7))
	src.pollOnce(context.Background())
	if len(plane.claims) != 1 {
		t.Fatal("the node still claims")
	}
	if _, said := plane.claims[0]["idle"]; said {
		t.Fatal("but must not say idle while a move it started is still running")
	}
}
