package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// planeReply answers the way the plane does: inside the API envelope.
func planeReply(w http.ResponseWriter, data map[string]interface{}) {
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"api_version": "1.0", "data": data})
}

// A siteless machine whose CLI join returned before approval must still end
// up connected: the running agent watches the staged keypair, sees the
// approval, stores the credential, and starts the remote source itself.
func TestASitelessMachineFinishesItsOwnJoin(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AGENT_IDENTITY_PATH", filepath.Join(dir, "node_identity.json"))

	var mu sync.Mutex
	polls, joins := 0, 0
	var claimed string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		var in map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&in)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case pathJoin:
			joins++
			claimed, _ = in["claimed_name"].(string)
			planeReply(w, map[string]interface{}{"status": "pending", "fingerprint": "x"})
		case pathJoinStatus:
			polls++
			if polls < 3 {
				planeReply(w, map[string]interface{}{"status": "pending", "fingerprint": "x"})
				return
			}
			planeReply(w, map[string]interface{}{
				"status": "approved", "fingerprint": "x", "node_id": 42, "node_slug": "keyless1-host", "poll_interval": 30,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	pub, priv, err := GenerateIdentityKeys()
	if err != nil {
		t.Fatal(err)
	}
	staged := &stagedIdentity{PlaneURL: srv.URL, PublicKey: pub, PrivateKey: priv, ClaimedName: "keyless1-host"}
	if err := staged.save(); err != nil {
		t.Fatal(err)
	}

	started := 0
	w := &StagedJoinWatcher{
		cfg:          &Config{Siteless: true},
		agentVersion: "test",
		interval:     5 * time.Millisecond,
		start:        func() { started++ },
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	w.Run(ctx)

	identity, err := LoadIdentity(IdentityPath())
	if err != nil || identity == nil {
		t.Fatalf("expected a stored credential after approval, got identity=%v err=%v", identity, err)
	}
	if identity.NodeID != 42 || identity.NodeSlug != "keyless1-host" || identity.PlaneURL != srv.URL {
		t.Fatalf("credential carries the wrong approval: %+v", identity)
	}
	if loadStagedIdentity() != nil {
		t.Fatalf("the staged keypair must be discarded once the credential exists")
	}
	if started != 1 {
		t.Fatalf("the remote source must be started exactly once, got %d", started)
	}
	mu.Lock()
	defer mu.Unlock()
	if joins != 0 {
		t.Fatalf("a pending ask must not be re-sent (%d joins); only status polls (%d)", joins, polls)
	}
	if claimed != "" {
		t.Fatalf("no join was expected, but one claimed %q", claimed)
	}
}

// A plane that has forgotten the ask (expired) gets the same key again, under
// the name the CLI recorded — so the fingerprint on the operator's screen is
// still the one that will be approved.
func TestAnExpiredAskIsRenewedWithTheSameKeyAndName(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AGENT_IDENTITY_PATH", filepath.Join(dir, "node_identity.json"))

	var mu sync.Mutex
	var claimed, joinedKey string
	expiredOnce := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		var in map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&in)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case pathJoin:
			claimed, _ = in["claimed_name"].(string)
			joinedKey, _ = in["agent_public_key"].(string)
			planeReply(w, map[string]interface{}{"status": "pending", "fingerprint": "x"})
		case pathJoinStatus:
			if !expiredOnce {
				expiredOnce = true
				planeReply(w, map[string]interface{}{"status": "expired", "fingerprint": "x"})
				return
			}
			planeReply(w, map[string]interface{}{
				"status": "approved", "fingerprint": "x", "node_id": 7, "node_slug": "h", "poll_interval": 30,
			})
		}
	}))
	defer srv.Close()

	pub, priv, _ := GenerateIdentityKeys()
	staged := &stagedIdentity{PlaneURL: srv.URL, PublicKey: pub, PrivateKey: priv, ClaimedName: "named-host"}
	_ = staged.save()

	w := &StagedJoinWatcher{cfg: &Config{Siteless: true}, agentVersion: "test", interval: 5 * time.Millisecond, start: func() {}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	w.Run(ctx)

	mu.Lock()
	defer mu.Unlock()
	if claimed != "named-host" {
		t.Fatalf("renewal must carry the recorded name, got %q", claimed)
	}
	if joinedKey != pub {
		t.Fatalf("renewal must present the same key")
	}
	if id, _ := LoadIdentity(IdentityPath()); id == nil || id.NodeID != 7 {
		t.Fatalf("the renewed ask must still complete, got %+v", id)
	}
}

// A management node pairs to itself with `joinery-agent join` on a machine that
// HAS a site. The watcher is the same one, and it must not depend on the
// machine being siteless: found live on dev, where the CLI's five-minute wait
// ran out, the approval landed afterwards, and nothing in the running agent
// noticed until it was restarted.
func TestASitedMachineFinishesItsOwnCLIJoin(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AGENT_IDENTITY_PATH", filepath.Join(dir, "node_identity.json"))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path != pathJoinStatus {
			http.NotFound(w, r)
			return
		}
		planeReply(w, map[string]interface{}{
			"status": "approved", "fingerprint": "x", "node_id": 24776, "node_slug": "dev-getjoinery-com", "poll_interval": 30,
		})
	}))
	defer srv.Close()

	pub, priv, err := GenerateIdentityKeys()
	if err != nil {
		t.Fatal(err)
	}
	staged := &stagedIdentity{PlaneURL: srv.URL, PublicKey: pub, PrivateKey: priv, ClaimedName: "dev.getjoinery.com"}
	if err := staged.save(); err != nil {
		t.Fatal(err)
	}

	started := 0
	w := &StagedJoinWatcher{
		cfg:          &Config{Siteless: false, SiteRoot: "/var/www/html/joinerytest"},
		agentVersion: "test",
		interval:     5 * time.Millisecond,
		start:        func() { started++ },
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	w.Run(ctx)

	identity, err := LoadIdentity(IdentityPath())
	if err != nil || identity == nil {
		t.Fatalf("a sited machine must store the credential its CLI join was approved for, got identity=%v err=%v", identity, err)
	}
	if identity.NodeID != 24776 {
		t.Fatalf("credential carries the wrong approval: %+v", identity)
	}
	if started != 1 {
		t.Fatalf("the remote source must be started exactly once, got %d", started)
	}
}

// A credential the CLI stored while the operator waited must also start the
// source on a sited machine — the case dev actually hit.
func TestACredentialTheCLIFinishedStartsTheSourceOnASitedMachine(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AGENT_IDENTITY_PATH", filepath.Join(dir, "node_identity.json"))

	pub, priv, err := GenerateIdentityKeys()
	if err != nil {
		t.Fatal(err)
	}
	identity := &NodeIdentity{PlaneURL: "https://dev.getjoinery.com", NodeID: 24776, NodeSlug: "dev-getjoinery-com",
		PublicKey: pub, PrivateKey: priv, PairedTime: nowRFC3339(), PollSeconds: 30}
	if err := identity.Save(IdentityPath()); err != nil {
		t.Fatal(err)
	}

	started := 0
	w := &StagedJoinWatcher{
		cfg:          &Config{Siteless: false},
		agentVersion: "test",
		interval:     5 * time.Millisecond,
		start:        func() { started++ },
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	w.Run(ctx)

	if started != 1 {
		t.Fatalf("a stored credential must start the remote source once, got %d", started)
	}
}

// Two watchers can each finish a join on a site machine. The second to arrive
// must find the source already running rather than start another one.
func TestTheRemoteSourceStartsAtMostOncePerProcess(t *testing.T) {
	remoteStart.mu.Lock()
	previous := remoteStart.source
	remoteStart.source = &RemoteSource{}
	remoteStart.mu.Unlock()
	t.Cleanup(func() {
		remoteStart.mu.Lock()
		remoteStart.source = previous
		remoteStart.mu.Unlock()
	})

	// No identity file, no policy, no database: a first start would fail on
	// all three. Getting the running source back proves the guard answered
	// before any of that was consulted.
	dir := t.TempDir()
	t.Setenv("AGENT_IDENTITY_PATH", filepath.Join(dir, "node_identity.json"))
	got := startRemoteSource(&Config{Siteless: true}, nil, &sync.Mutex{}, "test")
	if got == nil {
		t.Fatal("a running remote source must be returned to a second starter, not nil")
	}
}
