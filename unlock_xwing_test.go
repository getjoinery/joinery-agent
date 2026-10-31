package main

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// The unlock page inlines the platform's vendored X-Wing module; the embedded
// copy must be the pinned file (assets/vendor/noble/README.md), or a box's
// browser would run code nobody reviewed.
func TestEmbeddedXWingIsThePinnedModule(t *testing.T) {
	sum := sha256.Sum256([]byte(embeddedXWing))
	if hex.EncodeToString(sum[:]) != unlockXWingSHA256 {
		t.Fatalf("unlock_xwing.min.js is not the pinned module: sha256 %x", sum)
	}
}
