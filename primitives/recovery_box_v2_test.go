package primitives

import (
	"bytes"
	"encoding/base64"
	"testing"

	"joinery-agent/xwing"
)

// A box sealed to an X-Wing recovery key (specs/post_quantum_sealing.md R2):
// the page shows its ciphertext, posts the box's dek-scope key, and the agent
// opens it with that and nothing else.
func TestAVersionTwoRecoveryBoxOpensWithItsDekScopeKeyOnly(t *testing.T) {
	seed, _ := xwing.NewSeed()
	pub, err := xwing.PublicKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := xwing.Seal([]byte("the chain's data key"), pub, xwing.ScopeDEK)
	if err != nil {
		t.Fatal(err)
	}

	ct, ok := recoveryBoxParts(sealed, "xwing")
	if !ok || ct != base64.StdEncoding.EncodeToString(sealed[:xwing.CiphertextBytes]) {
		t.Fatalf("a v2 box is not shown to the page as its ciphertext: %v", ok)
	}
	if _, ok := recoveryBoxParts(sealed, "something-else"); ok {
		t.Fatal("a box naming an alg nobody knows was taken")
	}
	// A recipient with no alg, a libsodium sealed box to an old X25519 key,
	// is refused: nothing opens one.
	if _, ok := recoveryBoxParts(sealed[:80], ""); ok {
		t.Fatal("a box with no alg was shown to the page")
	}
	if _, ok := recoveryBoxParts(sealed, ""); ok {
		t.Fatal("a box with no alg was shown to the page")
	}

	ss, _ := xwing.Decapsulate(seed, sealed[:xwing.CiphertextBytes])
	dek, _ := xwing.Key(ss, xwing.ScopeDEK)
	opened, err := openRecoverySealed(sealed, dek, pub)
	if err != nil || !bytes.Equal(opened, []byte("the chain's data key")) {
		t.Fatalf("the dek-scope key does not open the box: %v", err)
	}
	if _, err := openRecoverySealed(sealed, dek, pub[:32]); err == nil {
		t.Fatal("a 32-byte recipient key was taken")
	}
	if _, err := openRecoverySealed(sealed, ss, pub); err == nil {
		t.Fatal("the X-Wing shared secret itself opened the box: a page could post it for any scope")
	}
	other, _ := xwing.Key(ss, "joinery-restore-approval:")
	if _, err := openRecoverySealed(sealed, other, pub); err == nil {
		t.Fatal("another scope's key opened a dek box")
	}
}
