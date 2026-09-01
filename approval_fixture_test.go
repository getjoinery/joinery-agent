package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"golang.org/x/crypto/curve25519"
)

// A challenge this agent sealed, written out so the BROWSER CODE can be asked to
// open it.
//
// This is the one seam in the approval mechanism where two implementations have
// to agree byte for byte and neither can check the other at runtime. The agent
// seals in Go; the person approving opens it in JavaScript, in their own
// browser, at the moment a restore is waiting. If those two ever disagree, the
// failure is silent until someone needs a restore, and it presents as "my
// recovery key does not work" — which is the single most alarming thing this
// platform could tell somebody.
//
// So the gate (tests/backups/approval_challenge_parity_gate.sh) runs this to
// produce a real sealed challenge, and hands it to the shipped browser code to
// open. It writes nothing unless asked, so an ordinary `go test` run is
// unaffected.
func TestApprovalChallengeFixture(t *testing.T) {
	out := os.Getenv("JOINERY_APPROVAL_FIXTURE")
	if out == "" {
		t.Skip("set JOINERY_APPROVAL_FIXTURE to write a browser-parity fixture")
	}

	// A recovery keypair of the shape the platform's own is: a raw 32-byte
	// X25519 scalar, which is what an operator pastes out of their password
	// manager and what WebCrypto is handed after a PKCS#8 wrapper is put around
	// it. Both sides clamp at use, so no clamping happens here — and that is
	// worth exercising rather than working around, because it is what the real
	// key does.
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		t.Fatal(err)
	}
	public, err := curve25519.X25519(secret[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}

	// The REAL plaintext, built by the same function Require uses — not a second
	// copy of the format that could drift from it. This is what makes the gate
	// prove the whole loop rather than only the crypto: the agent seals this,
	// the browser recovers it, and this is the byte string the agent will
	// compare an answer against.
	plaintext := approvalPlaintext([]byte("a-one-time-secret-value-32-bytes"), 4242, strings.Repeat("ab", 32))

	challenge, err := sealToRecoveryKey(approvalInfoPrefix, public, plaintext)
	if err != nil {
		t.Fatal(err)
	}

	body, err := json.MarshalIndent(map[string]string{
		"challenge":  challenge,
		"privateKey": base64.StdEncoding.EncodeToString(secret[:]),
		"publicKey":  base64.StdEncoding.EncodeToString(public),
		"infoPrefix": approvalInfoPrefix,
		// What the browser must recover, AND what the agent compares against.
		// The same string, deliberately: the gate asserts they are one thing.
		"expected": plaintext,
	}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, body, 0o600); err != nil {
		t.Fatal(err)
	}
}
