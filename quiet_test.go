package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The run switch and the going-quiet goodbye. Two properties are load-bearing:
// the marker must be readable by things that have no database, and switching off
// must complete whether or not the management node is reachable.

func TestTheMarkerIsReadWithoutADatabase(t *testing.T) {
	t.Setenv("AGENT_STATE_DIR", t.TempDir())

	if err := projectSwitch(true); err != nil {
		t.Fatalf("project on: %v", err)
	}
	if !markerSaysRun() {
		t.Fatal("a projected on must read as on")
	}

	if err := projectSwitch(false); err != nil {
		t.Fatalf("project off: %v", err)
	}
	if markerSaysRun() {
		t.Fatal("a projected off must read as off")
	}
}

func TestAMissingMarkerReadsAsOn(t *testing.T) {
	// An agent installed before the marker existed is running legitimately.
	// Reading absence as off would switch off every working agent at upgrade.
	t.Setenv("AGENT_STATE_DIR", t.TempDir())

	if !markerSaysRun() {
		t.Fatal("no marker must not mean stop")
	}
}

func TestTheProjectionIsOneWay(t *testing.T) {
	// Nothing reads the marker back into the setting. The database stays the
	// operator's truth; the file is only ever its shadow.
	dir := t.TempDir()
	t.Setenv("AGENT_STATE_DIR", dir)

	if err := projectSwitch(false); err != nil {
		t.Fatalf("project: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "enabled"))
	if err != nil {
		t.Fatalf("marker unreadable: %v", err)
	}
	if strings.TrimSpace(string(data)) != "0" {
		t.Fatalf("marker should hold the projected value, got %q", data)
	}
}

func TestTheAgentReadsTheSwitchTheSameWayEveryoneElseDoes(t *testing.T) {
	// Same spellings as install_agent.sh and the admin page. Three readers of
	// one setting is how a machine ends up disagreeing with the page that
	// configured it; installer_contract_test pins the other two against these.
	for _, on := range []string{"1", "true", "TRUE", "True", "yes", "on", " on "} {
		if !switchOn(on) {
			t.Errorf("%q should read as on", on)
		}
	}
	for _, off := range []string{"0", "", "no", "off", "o n", "nonsense"} {
		if switchOn(off) {
			t.Errorf("%q should read as off", off)
		}
	}
}

// quietServer stands in for the management node, recording what arrived and
// answering however the test wants.
func quietServer(t *testing.T, respond func(w http.ResponseWriter)) (*httptest.Server, *int, *string) {
	t.Helper()
	calls := 0
	lastTime := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var body struct {
			QuietTime string `json:"quiet_time"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		lastTime = body.QuietTime
		respond(w)
	}))
	t.Cleanup(srv.Close)
	return srv, &calls, &lastTime
}

func ackOK(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"success":true,"data":{"acknowledged":true}}`))
}

func TestAnAcknowledgedGoodbyeLeavesNothingBehind(t *testing.T) {
	t.Setenv("AGENT_STATE_DIR", t.TempDir())
	srv, calls, gotTime := quietServer(t, ackOK)
	id := testIdentity(t, srv.URL, 42)

	if err := postGoingQuiet(context.Background(), srv.Client(), id, "2026-08-26 22:00:00"); err != nil {
		t.Fatalf("goodbye should have been delivered: %v", err)
	}
	if *calls != 1 {
		t.Fatalf("expected one call, got %d", *calls)
	}
	if *gotTime != "2026-08-26 22:00:00" {
		t.Fatalf("the node's own timestamp must travel with it, got %q", *gotTime)
	}
}

func TestATransportSuccessWithoutAnAcknowledgementIsNotDelivery(t *testing.T) {
	// Something answered at that address. That is not the same as the management
	// node having recorded anything, and treating it as delivery would drop the
	// fact on the floor.
	srv, _, _ := quietServer(t, func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"success":true,"data":{}}`))
	})
	id := testIdentity(t, srv.URL, 42)

	err := postGoingQuiet(context.Background(), srv.Client(), id, "2026-08-26 22:00:00")
	if err == nil {
		t.Fatal("an unacknowledged response must not count as delivered")
	}
}

func TestSwitchingOffCompletesWhenThePlaneIsUnreachable(t *testing.T) {
	// The operator asked. A management node that cannot be reached does not get
	// a vote — but the fact is recorded so it can be replayed rather than lost.
	dir := t.TempDir()
	t.Setenv("AGENT_STATE_DIR", dir)

	srv, _, _ := quietServer(t, ackOK)
	id := testIdentity(t, srv.URL, 42)
	srv.Close() // nothing is listening now

	w := &SwitchWatcher{identity: id}
	// A window this short keeps the test quick; the shape is what matters.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	w.sayGoingQuiet(ctx)

	data, err := os.ReadFile(filepath.Join(dir, "quiet_undelivered"))
	if err != nil {
		t.Fatalf("an undelivered goodbye must be recorded: %v", err)
	}
	if strings.TrimSpace(string(data)) == "" {
		t.Fatal("the record must carry the time the node went quiet")
	}
}

func TestAnUndeliveredGoodbyeIsReplayedOnNextContact(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AGENT_STATE_DIR", dir)
	if err := os.WriteFile(filepath.Join(dir, "quiet_undelivered"), []byte("2026-08-26 21:00:00\n"), 0600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	srv, calls, gotTime := quietServer(t, ackOK)
	id := testIdentity(t, srv.URL, 42)

	w := &SwitchWatcher{identity: id}
	w.replayUndeliveredQuiet(context.Background())

	if *calls != 1 {
		t.Fatalf("the replay should have been sent, got %d calls", *calls)
	}
	if *gotTime != "2026-08-26 21:00:00" {
		t.Fatalf("the replay must carry the ORIGINAL time, got %q", *gotTime)
	}
	if _, err := os.Stat(filepath.Join(dir, "quiet_undelivered")); !os.IsNotExist(err) {
		t.Fatal("a delivered replay must clear its record")
	}
}

func TestAFailedReplayKeepsTheRecordForNextTime(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AGENT_STATE_DIR", dir)
	if err := os.WriteFile(filepath.Join(dir, "quiet_undelivered"), []byte("2026-08-26 21:00:00\n"), 0600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	srv, _, _ := quietServer(t, ackOK)
	id := testIdentity(t, srv.URL, 42)
	srv.Close()

	w := &SwitchWatcher{identity: id}
	w.replayUndeliveredQuiet(context.Background())

	if _, err := os.Stat(filepath.Join(dir, "quiet_undelivered")); err != nil {
		t.Fatal("a replay that failed must leave the record in place")
	}
}

func TestAnUnpairedAgentHasNobodyToSayGoodbyeTo(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AGENT_STATE_DIR", dir)

	w := &SwitchWatcher{identity: nil}
	w.replayUndeliveredQuiet(context.Background())

	if _, err := os.Stat(filepath.Join(dir, "quiet_undelivered")); !os.IsNotExist(err) {
		t.Fatal("an unpaired agent should not invent a goodbye record")
	}
}
