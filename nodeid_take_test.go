package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// The job loop's half of take_node_id: the staged identity becomes the live one
// only when the management node's answer confirms the swap, and is deleted
// otherwise.

func identityFixture(t *testing.T, nodeID int64) *NodeIdentity {
	t.Helper()
	t.Setenv("AGENT_IDENTITY_PATH", filepath.Join(t.TempDir(), "node_identity.json"))
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := &NodeIdentity{
		PlaneURL:   "https://plane.example",
		NodeID:     nodeID,
		NodeSlug:   "copytest-copy",
		PublicKey:  base64.StdEncoding.EncodeToString(pub),
		PrivateKey: base64.StdEncoding.EncodeToString(priv),
	}
	if err := id.hydrate(); err != nil {
		t.Fatal(err)
	}
	if err := id.Save(IdentityPath()); err != nil {
		t.Fatal(err)
	}
	return id
}

func liveNodeID(t *testing.T) int64 {
	t.Helper()
	id, err := LoadIdentity(IdentityPath())
	if err != nil || id == nil {
		t.Fatalf("live identity: %v", err)
	}
	return id.NodeID
}

func TestAConfirmedTakeBecomesTheLiveIdentity(t *testing.T) {
	live := identityFixture(t, 57)
	if err := stageNodeID(41, "copytest"); err != nil {
		t.Fatalf("stage: %v", err)
	}
	if liveNodeID(t) != 57 {
		t.Fatal("staging changed the live identity")
	}
	r := &RemoteSource{identity: live}
	answer := json.RawMessage(`{"recorded":true,"node_id_taken":41}`)
	if !r.finishIdentityTake(41, answer, nil) {
		t.Fatal("a confirmed take was not promoted")
	}
	got, _ := LoadIdentity(IdentityPath())
	if got.NodeID != 41 || got.NodeSlug != "copytest" || got.PublicKey != live.PublicKey {
		t.Errorf("live identity is node %d (%s), key kept %v", got.NodeID, got.NodeSlug, got.PublicKey == live.PublicKey)
	}
	if _, err := os.Stat(PendingIdentityPath()); !os.IsNotExist(err) {
		t.Error("the staged file is still there")
	}
}

func TestAnUnconfirmedTakeLeavesTheMachineAsItWas(t *testing.T) {
	for name, c := range map[string]struct {
		answer json.RawMessage
		err    error
	}{
		"post failed":     {nil, errors.New("connection reset")},
		"not confirmed":   {json.RawMessage(`{"recorded":true}`), nil},
		"another node id": {json.RawMessage(`{"recorded":true,"node_id_taken":42}`), nil},
		"not json":        {json.RawMessage(`nonsense`), nil},
	} {
		live := identityFixture(t, 57)
		if err := stageNodeID(41, "copytest"); err != nil {
			t.Fatal(err)
		}
		r := &RemoteSource{identity: live}
		if r.finishIdentityTake(41, c.answer, c.err) {
			t.Errorf("%s: the take was promoted", name)
		}
		if liveNodeID(t) != 57 {
			t.Errorf("%s: the live identity changed", name)
		}
		if _, err := os.Stat(PendingIdentityPath()); !os.IsNotExist(err) {
			t.Errorf("%s: the staged file was kept", name)
		}
	}
}

func TestAStagedIdentityWithAnotherKeyIsNotPromoted(t *testing.T) {
	live := identityFixture(t, 57)
	other := identityFixture(t, 57)
	// Stage under the second fixture's path and key, then point back at the first.
	staged := *other
	staged.NodeID = 41
	t.Setenv("AGENT_IDENTITY_PATH", filepath.Join(t.TempDir(), "node_identity.json"))
	if err := live.Save(IdentityPath()); err != nil {
		t.Fatal(err)
	}
	if err := staged.Save(PendingIdentityPath()); err != nil {
		t.Fatal(err)
	}
	r := &RemoteSource{identity: live}
	if r.finishIdentityTake(41, json.RawMessage(`{"node_id_taken":41}`), nil) {
		t.Error("an identity carrying another key was promoted")
	}
	if liveNodeID(t) != 57 {
		t.Error("the live identity changed")
	}
}
