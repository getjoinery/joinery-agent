package primitives

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

// The seal an agent before 1.99.0 made, to the copy's Ed25519 key converted
// to X25519. Nothing writes it any more (a bundle is sealed to the copy's
// X-Wing key); a copy still opens one (OpenSealedToAgentKey), and these tests
// make one to prove it.

// sealToAgentKey seals plaintext so only the holder of the Ed25519 private
// key behind recipient can open it: ephemeralPublic[32] || iv[12] ||
// ciphertext || tag[16].
func sealToAgentKey(recipient ed25519.PublicKey, plaintext []byte) ([]byte, error) {
	rx, err := ed25519PublicToX25519(recipient)
	if err != nil {
		return nil, err
	}
	eph := make([]byte, 32)
	if _, err := rand.Read(eph); err != nil {
		return nil, err
	}
	defer zero(eph)
	ephPublic, err := curve25519.X25519(eph, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	// X25519 refuses an all-zero result: a low-order recipient key, whose
	// shared secret would be the same for anyone.
	shared, err := curve25519.X25519(eph, rx)
	if err != nil {
		return nil, fmt.Errorf("the target key cannot be sealed to: %w", err)
	}
	key, err := sealKey(shared, ephPublic, rx)
	zero(shared)
	if err != nil {
		return nil, err
	}
	gcm, err := newGCM(key)
	zero(key)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	out := append(append([]byte{}, ephPublic...), iv...)
	return gcm.Seal(out, iv, plaintext, nil), nil
}
