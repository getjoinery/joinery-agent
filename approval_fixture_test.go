package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"joinery-agent/primitives"
	"joinery-agent/xwing"
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

	// A recovery keypair of the shape the platform's own is: a 32-byte X-Wing
	// seed, which is what an operator pastes out of their password manager,
	// and the 1216-byte public key it makes.
	secret, err := xwing.NewSeed()
	if err != nil {
		t.Fatal(err)
	}
	public, err := xwing.PublicKey(secret)
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

	// A backup key box (B20): a chain key sealed to the same recovery key, as
	// a backup another server made seals it (a v2 dek box). The browser works
	// out the value that opens it (VaultCrypto.halfOpenKeyBox: the box's
	// dek-scope key); the agent finishes it with that value. The expected
	// value is checked to open the box here, so the gate's comparison is
	// against a value known to work.
	sealedKey, err := xwing.Seal([]byte("the chain's data key"), public, xwing.ScopeDEK)
	if err != nil {
		t.Fatal(err)
	}
	ss, err := xwing.Decapsulate(secret, sealedKey[:xwing.CiphertextBytes])
	if err != nil {
		t.Fatal(err)
	}
	shared, err := xwing.Key(ss, xwing.ScopeDEK)
	if err != nil {
		t.Fatal(err)
	}
	if opened, err := primitives.OpenRecoverySealed(sealedKey, shared, public); err != nil || string(opened) != "the chain's data key" {
		t.Fatalf("the expected value does not open the box: %v", err)
	}
	fp := sha256.Sum256(public)

	body, err := json.MarshalIndent(map[string]string{
		"challenge":  challenge,
		"privateKey": base64.StdEncoding.EncodeToString(secret),
		"publicKey":  base64.StdEncoding.EncodeToString(public),
		"infoPrefix": approvalInfoPrefix,
		// What the browser must recover, AND what the agent compares against.
		// The same string, deliberately: the gate asserts they are one thing.
		"expected": plaintext,
		// The key box: what the page is shown, and what it must work out.
		"boxCiphertext":  base64.StdEncoding.EncodeToString(sealedKey[:xwing.CiphertextBytes]),
		"boxFingerprint": hex.EncodeToString(fp[:]),
		"boxShared":      base64.StdEncoding.EncodeToString(shared),
	}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, body, 0o600); err != nil {
		t.Fatal(err)
	}
}
