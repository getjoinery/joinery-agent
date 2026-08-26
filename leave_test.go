package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// Leaving is unilateral: the disconnect the local admin asked for happens on
// this machine whatever the plane does. The goodbye is a courtesy that lets the
// plane forget the key immediately instead of watching the agent go silent.

func TestLeaveSendsOneSignedGoodbyeAndDeletesTheIdentity(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AGENT_IDENTITY_PATH", filepath.Join(dir, "node_identity.json"))

	var gotPath, gotNode, gotSig, gotTimestamp, gotNonce string
	var gotBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		gotPath = req.URL.Path
		gotNode = req.Header.Get("X-Joinery-Agent-Node")
		gotSig = req.Header.Get("X-Joinery-Agent-Signature")
		gotTimestamp = req.Header.Get("X-Joinery-Agent-Timestamp")
		gotNonce = req.Header.Get("X-Joinery-Agent-Nonce")
		gotBody, _ = io.ReadAll(req.Body)
		w.Write([]byte(`{"api_version":"1.0","data":{"left":true}}`))
	}))
	defer server.Close()

	id := testIdentity(t, server.URL, 42)
	if err := id.Save(IdentityPath()); err != nil {
		t.Fatal(err)
	}

	if err := performLeave(context.Background(), server.Client(), id); err != nil {
		t.Fatalf("leave: %v", err)
	}

	if gotPath != pathLeave {
		t.Errorf("goodbye went to %q, want %q", gotPath, pathLeave)
	}
	if gotNode != "42" {
		t.Errorf("goodbye names node %q, want 42", gotNode)
	}

	// The goodbye is a real signed request — the plane must be able to verify
	// only the key holder said it, or anyone could disconnect anyone.
	sum := sha256.Sum256(gotBody)
	message := SigningMessage("POST", pathLeave, 42, gotTimestamp, gotNonce, hex.EncodeToString(sum[:]))
	sig, err := base64.StdEncoding.DecodeString(gotSig)
	if err != nil {
		t.Fatal(err)
	}
	rawPub, _ := base64.StdEncoding.DecodeString(id.PublicKey)
	if !ed25519.Verify(ed25519.PublicKey(rawPub), []byte(message), sig) {
		t.Fatal("the goodbye's signature does not verify against the node's public half")
	}

	if _, err := os.Stat(IdentityPath()); !os.IsNotExist(err) {
		t.Fatal("the identity survived the leave — a restart would reconnect to a plane the admin just left")
	}
}

func TestLeaveIsUnilateralWhenThePlaneIsUnreachable(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AGENT_IDENTITY_PATH", filepath.Join(dir, "node_identity.json"))

	// A server that is already gone: the goodbye cannot be delivered.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {}))
	planeURL := server.URL
	server.Close()

	id := testIdentity(t, planeURL, 7)
	if err := id.Save(IdentityPath()); err != nil {
		t.Fatal(err)
	}

	if err := performLeave(context.Background(), &http.Client{}, id); err != nil {
		t.Fatalf("leave must not depend on the plane's cooperation: %v", err)
	}
	if _, err := os.Stat(IdentityPath()); !os.IsNotExist(err) {
		t.Fatal("the identity survived a leave the plane never heard")
	}
}

func TestLeaveDiscardsAStagedKeypairToo(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AGENT_IDENTITY_PATH", filepath.Join(dir, "node_identity.json"))

	id := testIdentity(t, "http://127.0.0.1:1", 9)
	if err := id.Save(IdentityPath()); err != nil {
		t.Fatal(err)
	}
	staged := &stagedIdentity{PlaneURL: "http://127.0.0.1:1", PublicKey: "p", PrivateKey: "k"}
	if err := staged.save(); err != nil {
		t.Fatal(err)
	}

	if err := performLeave(context.Background(), &http.Client{}, id); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stagedIdentityPath()); !os.IsNotExist(err) {
		t.Fatal("a staged keypair survived the leave")
	}
}
