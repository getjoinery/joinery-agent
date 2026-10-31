package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"joinery-agent/primitives"
)

// The machine's X-Wing key reported at poll (specs/post_quantum_sealing.md
// R6): minted on the first claim without one, saved with the identity, and
// sent with the identity key's signature, which the plane and a copy's
// source verify.
func TestClaimReportsTheSignedKEMKey(t *testing.T) {
	var claimed map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		json.NewDecoder(req.Body).Decode(&claimed)
		w.Write([]byte(`{"api_version":"1.0","data":{"job":null}}`))
	}))
	defer server.Close()

	id := testIdentity(t, server.URL, 7)
	src := testSource(t, id)
	if _, err := src.claim(context.Background()); err != nil {
		t.Fatal(err)
	}
	pub, _ := claimed["kem_public_key"].(string)
	sig, _ := claimed["kem_signature"].(string)
	if _, err := primitives.VerifiedAgentKEM(id.private.Public().(ed25519.PublicKey), pub, sig); err != nil {
		t.Fatalf("the claim's KEM key does not verify against the agent key: %v", err)
	}
	saved, err := os.ReadFile(IdentityPath())
	if err != nil {
		t.Fatalf("the minted key was not saved with the identity: %v", err)
	}
	var back NodeIdentity
	if err := json.Unmarshal(saved, &back); err != nil || back.KEMSeed != id.KEMSeed || back.KEMSeed == "" {
		t.Fatal("the identity file does not hold the KEM seed the claim reported")
	}

	// The next claim reports the same key: it is minted once.
	first := pub
	if _, err := src.claim(context.Background()); err != nil {
		t.Fatal(err)
	}
	if claimed["kem_public_key"] != first {
		t.Error("a second claim reported another KEM key")
	}
}

// A statement made from fixed seeds, pinned in testdata/agent_kem_statement.json
// and in the platform's plugins/server_manager/tests/fixtures/ copy, which
// agent_kem_key_test.php verifies with AgentChannelEndpoint::verified_kem_key:
// the Go signer and the PHP verifier are held to the same bytes (Ed25519
// signatures are deterministic). JOINERY_KEM_FIXTURE=path writes it.
func TestKEMStatementFixture(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	kemSeed := make([]byte, 32)
	for i := range kemSeed {
		kemSeed[i] = byte(0xa0 + i)
	}
	id := &NodeIdentity{PrivateKey: base64.StdEncoding.EncodeToString(priv), KEMSeed: base64.StdEncoding.EncodeToString(kemSeed)}
	if err := id.hydrate(); err != nil {
		t.Fatal(err)
	}
	pub, sig, err := id.KEMStatement()
	if err != nil {
		t.Fatal(err)
	}
	got, _ := json.MarshalIndent(map[string]string{
		"_about":           "An agent's KEM statement from fixed seeds (kem_statement_test.go): agent_public_key signs kem_public_key under joinery-agent-kem-v1.",
		"agent_public_key": base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey)),
		"kem_public_key":   pub,
		"kem_signature":    sig,
	}, "", "\t")
	got = append(got, '\n')
	if out := os.Getenv("JOINERY_KEM_FIXTURE"); out != "" {
		if err := os.WriteFile(out, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile("testdata/agent_kem_statement.json")
	if err != nil {
		t.Fatalf("the pinned statement: %v", err)
	}
	if string(want) != string(got) {
		t.Fatal("KEMStatement no longer makes the pinned bytes (testdata/agent_kem_statement.json)")
	}
}
