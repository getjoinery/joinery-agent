// Package xwing is X-Wing (draft-connolly-cfrg-xwing-kem-11: X25519 +
// ML-KEM-768) and the Joinery v2 seal over it (the platform's
// specs/post_quantum_sealing.md R1, R2), standard library only. The same bytes
// as the platform's includes/XWing.php, SealedBox::sealV2 and
// assets/js/vault-crypto.js, held to testdata/xwing_vector.json (a copy of the
// platform's tests/vault/fixtures/xwing_vector.json).
//
//	public key : pk_M[1184] ‖ pk_X[32]                       (1216 bytes)
//	secret     : a 32-byte seed; SHAKE256(seed, 96) = d ‖ z ‖ sk_X
//	ciphertext : ct_M[1088] ‖ ct_X[32]                       (1120 bytes)
//	shared     : SHA3-256(ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ "\.//^\")
//	v2 seal    : ct[1120] ‖ IV[12] ‖ AES-256-GCM(plaintext) ‖ tag[16], no AAD,
//	             key = HKDF-SHA256(shared, salt empty, "joinery-seal:v2:" ‖ scope)
package xwing

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha3"
	"errors"
	"fmt"
	"io"
)

const (
	SeedBytes       = 32
	PublicKeyBytes  = 1216
	CiphertextBytes = 1120
	mlkemPublic     = 1184
	mlkemCipher     = 1088
	info            = "joinery-seal:v2:"
	// ScopeDEK is the scope of every key seal (a data key, a wrapped secret, a
	// sidecar recipient); a challenge uses its own label.
	ScopeDEK = "dek"
	ivBytes  = 12
	// Overhead is what a v2 seal adds to its plaintext.
	Overhead = CiphertextBytes + ivBytes + 16
)

var label = []byte{0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c}

// MLKEMEncapsulate is the ML-KEM half of an encapsulation. Production draws
// fresh randomness; a vector test supplies its own (crypto/mlkem/mlkemtest).
type MLKEMEncapsulate func(ek *mlkem.EncapsulationKey768) (sharedKey, ciphertext []byte, err error)

func randomMLKEM(ek *mlkem.EncapsulationKey768) ([]byte, []byte, error) {
	ss, ct := ek.Encapsulate()
	return ss, ct, nil
}

func expand(seed []byte) (*mlkem.DecapsulationKey768, *ecdh.PrivateKey, error) {
	if len(seed) != SeedBytes {
		return nil, nil, fmt.Errorf("an X-Wing secret is a %d-byte seed, got %d bytes", SeedBytes, len(seed))
	}
	expanded := sha3.SumSHAKE256(seed, 96)
	defer Zero(expanded)
	dk, err := mlkem.NewDecapsulationKey768(expanded[:64])
	if err != nil {
		return nil, nil, err
	}
	skX, err := ecdh.X25519().NewPrivateKey(expanded[64:96])
	if err != nil {
		return nil, nil, err
	}
	return dk, skX, nil
}

// PublicKey is the 1216-byte public key of a seed.
func PublicKey(seed []byte) ([]byte, error) {
	dk, skX, err := expand(seed)
	if err != nil {
		return nil, err
	}
	return append(dk.EncapsulationKey().Bytes(), skX.PublicKey().Bytes()...), nil
}

// NewSeed draws a fresh 32-byte secret.
func NewSeed() ([]byte, error) {
	seed := make([]byte, SeedBytes)
	if _, err := io.ReadFull(rand.Reader, seed); err != nil {
		return nil, err
	}
	return seed, nil
}

func combine(ssM, ssX, ctX, pkX []byte) []byte {
	h := sha3.New256()
	h.Write(ssM)
	h.Write(ssX)
	h.Write(ctX)
	h.Write(pkX)
	h.Write(label)
	return h.Sum(nil)
}

// EncapsulateWith encapsulates to pk with the X25519 ephemeral secret ekX and
// the ML-KEM half from encap. Returns (shared, ciphertext).
func EncapsulateWith(pk, ekX []byte, encap MLKEMEncapsulate) ([]byte, []byte, error) {
	if len(pk) != PublicKeyBytes {
		return nil, nil, fmt.Errorf("an X-Wing public key is %d bytes, got %d", PublicKeyBytes, len(pk))
	}
	ekM, err := mlkem.NewEncapsulationKey768(pk[:mlkemPublic])
	if err != nil {
		return nil, nil, fmt.Errorf("X-Wing public key: %w", err)
	}
	pkX, err := ecdh.X25519().NewPublicKey(pk[mlkemPublic:])
	if err != nil {
		return nil, nil, err
	}
	eph, err := ecdh.X25519().NewPrivateKey(ekX)
	if err != nil {
		return nil, nil, err
	}
	ctX := eph.PublicKey().Bytes()
	ssX, err := eph.ECDH(pkX)
	if err != nil {
		return nil, nil, fmt.Errorf("X25519 refused the key: %w", err)
	}
	defer Zero(ssX)
	ssM, ctM, err := encap(ekM)
	if err != nil {
		return nil, nil, err
	}
	defer Zero(ssM)
	return combine(ssM, ssX, ctX, pk[mlkemPublic:]), append(ctM, ctX...), nil
}

// Decapsulate recovers the shared secret of ct with the seed.
func Decapsulate(seed, ct []byte) ([]byte, error) {
	if len(ct) != CiphertextBytes {
		return nil, fmt.Errorf("an X-Wing ciphertext is %d bytes, got %d", CiphertextBytes, len(ct))
	}
	dk, skX, err := expand(seed)
	if err != nil {
		return nil, err
	}
	ssM, err := dk.Decapsulate(ct[:mlkemCipher])
	if err != nil {
		return nil, err
	}
	defer Zero(ssM)
	ctX := ct[mlkemCipher:]
	peer, err := ecdh.X25519().NewPublicKey(ctX)
	if err != nil {
		return nil, err
	}
	ssX, err := skX.ECDH(peer)
	if err != nil {
		return nil, errors.New("X25519 refused the ciphertext")
	}
	defer Zero(ssX)
	return combine(ssM, ssX, ctX, skX.PublicKey().Bytes()), nil
}

// Key is the AES-256 key of a v2 seal under scope. For scope dek it is what a
// browser posts for a box it half-opens (SealedBox::v2Key): it opens only
// that scope's boxes, never the X-Wing shared secret itself.
func Key(shared []byte, scope string) ([]byte, error) {
	return hkdf.Key(sha256.New, shared, nil, info+scope, 32)
}

// Seal seals plaintext to a 1216-byte public key under scope.
func Seal(plaintext, pk []byte, scope string) ([]byte, error) {
	ekX := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, ekX); err != nil {
		return nil, err
	}
	defer Zero(ekX)
	iv := make([]byte, ivBytes)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	return SealWith(plaintext, pk, scope, ekX, iv, randomMLKEM)
}

// SealWith is Seal with its randomness supplied (the vector fixes it).
func SealWith(plaintext, pk []byte, scope string, ekX, iv []byte, encap MLKEMEncapsulate) ([]byte, error) {
	shared, ct, err := EncapsulateWith(pk, ekX, encap)
	if err != nil {
		return nil, err
	}
	defer Zero(shared)
	key, err := Key(shared, scope)
	if err != nil {
		return nil, err
	}
	defer Zero(key)
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	out := append(ct, iv...)
	return gcm.Seal(out, iv, plaintext, nil), nil
}

// Open opens a v2 seal with the 32-byte seed under scope.
func Open(raw, seed []byte, scope string) ([]byte, error) {
	if len(raw) < Overhead {
		return nil, errors.New("not a v2 sealed blob")
	}
	shared, err := Decapsulate(seed, raw[:CiphertextBytes])
	if err != nil {
		return nil, err
	}
	defer Zero(shared)
	key, err := Key(shared, scope)
	if err != nil {
		return nil, err
	}
	defer Zero(key)
	return OpenWithKey(raw, key)
}

// OpenWithKey opens a v2 seal with its scope's AES key (Key), the value a
// browser hands over for a box it half-opened.
func OpenWithKey(raw, key []byte) ([]byte, error) {
	if len(raw) < Overhead {
		return nil, errors.New("not a v2 sealed blob")
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	iv := raw[CiphertextBytes : CiphertextBytes+ivBytes]
	return gcm.Open(nil, iv, raw[CiphertextBytes+ivBytes:], nil)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("AES-256-GCM key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Zero overwrites b.
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
