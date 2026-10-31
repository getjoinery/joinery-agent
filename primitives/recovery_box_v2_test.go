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

	ct, eph, ok := recoveryBoxParts(sealed, "xwing")
	if !ok || eph != "" || ct != base64.StdEncoding.EncodeToString(sealed[:xwing.CiphertextBytes]) {
		t.Fatalf("a v2 box is not shown to the page as its ciphertext: %v %q", ok, eph)
	}
	if _, _, ok := recoveryBoxParts(sealed, "something-else"); ok {
		t.Fatal("a box naming an alg nobody knows was taken")
	}
	if _, eph, ok := recoveryBoxParts(sealed[:80], ""); !ok || eph == "" {
		t.Fatal("a v1 box is not shown to the page as its ephemeral key")
	}

	ss, _ := xwing.Decapsulate(seed, sealed[:xwing.CiphertextBytes])
	dek, _ := xwing.Key(ss, xwing.ScopeDEK)
	opened, err := openRecoverySealed(sealed, dek, pub)
	if err != nil || !bytes.Equal(opened, []byte("the chain's data key")) {
		t.Fatalf("the dek-scope key does not open the box: %v", err)
	}
	if _, err := openRecoverySealed(sealed, ss, pub); err == nil {
		t.Fatal("the X-Wing shared secret itself opened the box: a page could post it for any scope")
	}
	other, _ := xwing.Key(ss, "joinery-restore-approval:")
	if _, err := openRecoverySealed(sealed, other, pub); err == nil {
		t.Fatal("another scope's key opened a dek box")
	}
}
