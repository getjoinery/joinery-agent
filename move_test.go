package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// connectedTo stores an identity for planeURL as this machine's own, the way
// an approved join leaves one, and returns it.
func connectedTo(t *testing.T, planeURL string, nodeID int64) *NodeIdentity {
	t.Helper()
	pub, priv, err := GenerateIdentityKeys()
	if err != nil {
		t.Fatal(err)
	}
	id, err := identityFromApproval(planeURL, &stagedIdentity{PublicKey: pub, PrivateKey: priv},
		&joinStatusResponse{Status: "approved", NodeID: nodeID, NodeSlug: "docker-prod"}, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := id.Save(IdentityPath()); err != nil {
		t.Fatal(err)
	}
	return id
}

// The management node asks; the machine files the join with the new one under
// the name it was given, and keeps its current connection until that is
// approved.
func TestMoveToPlaneFilesTheJoinAndKeepsTheConnection(t *testing.T) {
	t.Setenv("AGENT_IDENTITY_PATH", filepath.Join(t.TempDir(), "node_identity.json"))

	var mu sync.Mutex
	var claimed string
	joins := 0
	newPlane := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		var in map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&in)
		if r.URL.Path == pathJoin {
			joins++
			claimed, _ = in["claimed_name"].(string)
		}
		planeReply(w, map[string]interface{}{"status": "pending", "fingerprint": "x"})
	}))
	defer newPlane.Close()

	move := moveToPlaneFor(&Config{Siteless: true, PlaneTLSInsecure: true})
	ctx := context.Background()

	if _, err := move(ctx, newPlane.URL, "docker-prod"); err == nil || !strings.Contains(err.Error(), "not connected") {
		t.Fatalf("a machine with no connection has nothing to move; got %v", err)
	}

	old := connectedTo(t, "https://old.example.com", 38103)

	if _, err := move(ctx, "http://plain.example.com", "docker-prod"); err == nil {
		t.Fatalf("a move to a plain-http address must be refused")
	}
	if _, err := move(ctx, "https://old.example.com/", "docker-prod"); err == nil || !strings.Contains(err.Error(), "already managed") {
		t.Fatalf("a move to the management node already in use must be refused; got %v", err)
	}

	out, err := move(ctx, newPlane.URL, "docker-prod")
	if err != nil {
		t.Fatalf("move: %v", err)
	}
	if joins != 1 || claimed != "docker-prod" {
		t.Fatalf("expected one join claiming docker-prod, got %d claiming %q", joins, claimed)
	}
	staged := loadStagedIdentity()
	if staged == nil || !staged.Moving || staged.PlaneURL != newPlane.URL {
		t.Fatalf("the ask must be staged as a move to the new management node: %+v", staged)
	}
	if fp, _ := stagedFingerprint(staged); out["fingerprint"] != fp {
		t.Fatalf("the answer must carry the staged key's fingerprint for the operator to compare: %v vs %s", out["fingerprint"], fp)
	}
	if current, _ := LoadIdentity(IdentityPath()); current == nil || current.PlaneURL != old.PlaneURL || current.NodeID != old.NodeID {
		t.Fatalf("the current connection must stand until the move is approved: %+v", current)
	}

	// Asking again keeps the same key, so the fingerprint the operator is
	// comparing does not change under them.
	again, err := move(ctx, newPlane.URL, "docker-prod")
	if err != nil || again["fingerprint"] != out["fingerprint"] {
		t.Fatalf("asking again must present the same fingerprint: %v / %v", again["fingerprint"], err)
	}
}

// On approval the new credential replaces the old one, the old management
// node is told goodbye with the old key, and the process ends so the
// supervisor restarts it onto the new one.
func TestMoveWatcherSwapsTheCredentialOnApproval(t *testing.T) {
	t.Setenv("AGENT_IDENTITY_PATH", filepath.Join(t.TempDir(), "node_identity.json"))

	var mu sync.Mutex
	polls := 0
	newPlane := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		polls++
		if polls < 2 {
			planeReply(w, map[string]interface{}{"status": "pending", "fingerprint": "x"})
			return
		}
		planeReply(w, map[string]interface{}{"status": "approved", "fingerprint": "x", "node_id": 7, "node_slug": "docker-prod"})
	}))
	defer newPlane.Close()

	goodbyes := 0
	oldPlane := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.URL.Path == pathLeave {
			goodbyes++
		}
		planeReply(w, map[string]interface{}{"ok": true})
	}))
	defer oldPlane.Close()

	old := connectedTo(t, oldPlane.URL, 38103)
	pub, priv, err := GenerateIdentityKeys()
	if err != nil {
		t.Fatal(err)
	}
	staged := &stagedIdentity{PlaneURL: newPlane.URL, PublicKey: pub, PrivateKey: priv, ClaimedName: "docker-prod", Moving: true}
	if err := staged.save(); err != nil {
		t.Fatal(err)
	}

	exited := 0
	var lock sync.Mutex
	w := &MoveWatcher{
		cfg:          &Config{Siteless: true, PlaneTLSInsecure: true},
		jobLock:      &lock,
		agentVersion: "test",
		identity:     old,
		interval:     5 * time.Millisecond,
		exit:         func() { exited++ },
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	w.Run(ctx)

	current, err := LoadIdentity(IdentityPath())
	if err != nil || current == nil || current.PlaneURL != newPlane.URL || current.NodeID != 7 || current.PublicKey != pub {
		t.Fatalf("the stored credential must be the new management node's: %+v %v", current, err)
	}
	if loadStagedIdentity() != nil {
		t.Fatalf("the staged keypair must be discarded once the move is finished")
	}
	if goodbyes != 1 {
		t.Fatalf("the old management node must be told goodbye once, got %d", goodbyes)
	}
	if exited != 1 {
		t.Fatalf("the process must end once so it restarts onto the new credential, got %d", exited)
	}
}

// A staged ask that is not a move (a CLI join to some plane) is not the move
// watcher's to finish.
func TestMoveWatcherLeavesAPlainJoinAlone(t *testing.T) {
	t.Setenv("AGENT_IDENTITY_PATH", filepath.Join(t.TempDir(), "node_identity.json"))

	asked := 0
	plane := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked++
		planeReply(w, map[string]interface{}{"status": "approved", "node_id": 9})
	}))
	defer plane.Close()

	old := connectedTo(t, "https://old.example.com", 1)
	pub, priv, _ := GenerateIdentityKeys()
	if err := (&stagedIdentity{PlaneURL: plane.URL, PublicKey: pub, PrivateKey: priv}).save(); err != nil {
		t.Fatal(err)
	}
	var lock sync.Mutex
	w := &MoveWatcher{cfg: &Config{PlaneTLSInsecure: true}, jobLock: &lock, agentVersion: "test", identity: old,
		interval: 5 * time.Millisecond, exit: func() { t.Fatalf("a plain join must not end the process") }}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	w.Run(ctx)
	if asked != 0 {
		t.Fatalf("the move watcher must not ask about a staged join that is not a move")
	}
}

// A connection that began mid-process (a join approved while the agent ran,
// which is how every freshly installed machine connects) must run the move
// watcher too, not only one that booted connected. Before startConnectedWatchers,
// such a machine took move_to_plane, was approved on the new plane, and never
// asked again (wp5node2-host, 2026-10-09).
func TestEveryConnectionRunsTheMoveWatcher(t *testing.T) {
	t.Setenv("AGENT_IDENTITY_PATH", filepath.Join(t.TempDir(), "node_identity.json"))

	newPlane := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		planeReply(w, map[string]interface{}{"status": "approved", "fingerprint": "x", "node_id": 3, "node_slug": "wp5node2-host"})
	}))
	defer newPlane.Close()
	oldPlane := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		planeReply(w, map[string]interface{}{"ok": true})
	}))
	defer oldPlane.Close()

	old := connectedTo(t, oldPlane.URL, 122256)
	pub, priv, _ := GenerateIdentityKeys()
	if err := (&stagedIdentity{PlaneURL: newPlane.URL, PublicKey: pub, PrivateKey: priv, ClaimedName: "wp5node2-host", Moving: true}).save(); err != nil {
		t.Fatal(err)
	}

	exited := make(chan struct{}, 1)
	savedInterval, savedExit := moveWatcherInterval, moveWatcherExit
	moveWatcherInterval = 5 * time.Millisecond
	moveWatcherExit = func() { exited <- struct{}{} }
	defer func() { moveWatcherInterval, moveWatcherExit = savedInterval, savedExit }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var lock sync.Mutex
	startConnectedWatchers(ctx, &Config{Siteless: true, PlaneTLSInsecure: true}, nil, &lock, "test", old)

	select {
	case <-exited:
	case <-time.After(5 * time.Second):
		t.Fatalf("the move watcher a connection starts never finished an approved move")
	}
	if current, _ := LoadIdentity(IdentityPath()); current == nil || current.PlaneURL != newPlane.URL || current.NodeID != 3 {
		t.Fatalf("the credential must be the new plane's after the move: %+v", current)
	}
}
