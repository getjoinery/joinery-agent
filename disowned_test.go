package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func resetDisowned() { noteDisowned("", "") }

// Only the management node's own answer that it does not know this machine
// counts: its 401 with its words. No answer, a 5xx, a clock refusal or
// another refusal says nothing about whether the machine is still managed.
func TestOnlyTheManagementNodesOwnAnswerDisowns(t *testing.T) {
	for name, c := range map[string]struct {
		err  error
		want bool
	}{
		"its node holds no agent key": {&planeStatusError{Status: 401, msg: "plane returned HTTP 401 for x: This node has not paired an agent with this plane."}, true},
		"its node is gone":            {&planeStatusError{Status: 401, msg: "plane returned HTTP 401 for x: Unknown node."}, true},
		"a clock refusal":             {&planeStatusError{Status: 401, msg: "plane returned HTTP 401 for x: too far from this plane's clock"}, false},
		"the same words on a 500":     {&planeStatusError{Status: 500, msg: "Unknown node."}, false},
		"not its own answer":          {&planeStatusError{Status: 0, msg: "plane response is not valid JSON (HTTP 401) Unknown node."}, false},
		"no answer at all":            {errors.New("dial tcp: connection refused"), false},
	} {
		if got := planeDisowns(c.err) != ""; got != c.want {
			t.Fatalf("%s: disowned=%v, want %v", name, got, c.want)
		}
	}
}

// The connection is still reported as connected, with what the management
// node says and since when; an ordinary answer clears it.
func TestTheReportedConnectionCarriesTheAnswerAndKeepsTheConnection(t *testing.T) {
	t.Setenv("AGENT_IDENTITY_PATH", filepath.Join(t.TempDir(), "node_identity.json"))
	t.Cleanup(resetDisowned)
	resetDisowned()
	id := connectedTo(t, "https://dev.example.com", 33)

	if st := connectionState(id); st["disowned_time"] != nil {
		t.Fatalf("a machine its management node knows reports nothing of the kind: %+v", st)
	}
	if !noteDisowned(disownedAnswers[0], "") {
		t.Fatalf("the first such answer is a change")
	}
	if noteDisowned(disownedAnswers[0], "") {
		t.Fatalf("the same answer again changes nothing, so nothing is rewritten")
	}
	st := connectionState(id)
	since, _ := st["disowned_time"].(string)
	if st["status"] != "connected" || since == "" || st["disowned_reason"] != disownedAnswers[0] {
		t.Fatalf("still connected, with the answer and its time: %+v", st)
	}
	body, _ := json.Marshal(st)
	if connectionReportStale("", string(body), id) {
		t.Fatalf("that report is this connection's, not a stale one")
	}
	if got := disownedSinceIn(string(body), id); got != since {
		t.Fatalf("the time on record is read back for a restart: %q, want %q", got, since)
	}
	other := connectedTo(t, "https://other.example.com", 34)
	if got := disownedSinceIn(string(body), other); got != "" {
		t.Fatalf("another connection's time is not taken over: %q", got)
	}

	if !noteDisowned("", "") {
		t.Fatalf("an ordinary answer after it is a change")
	}
	if st := connectionState(id); st["disowned_time"] != nil || st["disowned_reason"] != nil {
		t.Fatalf("cleared once the management node answers as usual: %+v", st)
	}
	if noteDisowned("", "") {
		t.Fatalf("ordinary answers change nothing")
	}
}

// After a restart the time already reported is kept.
func TestARestartKeepsTheTimeOnRecord(t *testing.T) {
	t.Cleanup(resetDisowned)
	resetDisowned()
	noteDisowned(disownedAnswers[1], "2026-11-21 21:48:08")
	if since, reason := disownedNow(); since != "2026-11-21 21:48:08" || reason != disownedAnswers[1] {
		t.Fatalf("got %q %q", since, reason)
	}
}

// The poll tells its hook what each answer says: the words on the management
// node's 401, nothing on a 500, "" once it answers as usual.
func TestThePollReportsWhatTheManagementNodeAnswers(t *testing.T) {
	useOutbox(t)
	status, words := 401, disownedAnswers[0]
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if status != 200 {
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"error": words, "errortype": "AuthenticationError"})
			return
		}
		planeReply(w, map[string]interface{}{"job": nil})
	}))
	t.Cleanup(srv.Close)
	src := testSource(t, testIdentity(t, srv.URL, 7))
	var told []string
	src.planeAnswered = func(w string) { told = append(told, w) }

	src.pollOnce(context.Background())
	status = 500
	src.pollOnce(context.Background())
	status = 200
	src.pollOnce(context.Background())
	if len(told) != 2 || told[0] != disownedAnswers[0] || told[1] != "" {
		t.Fatalf("told %q; want the words once, nothing for the 500, then the all-clear", told)
	}
}
