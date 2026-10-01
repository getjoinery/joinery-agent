package primitives

// The cryptography of a site copy's export (specs/site_copy.md WP4).
//
// The source S hands its copy T the secrets T cannot make for itself: each
// chain's data key, the certificate and its account, the DKIM keys. They
// travel through the management node, which the design assumes may be
// compromised, so two things hold whatever it does:
//
//   - ONLY T CAN READ THE BUNDLE. It is sealed to T's agent key: the key the
//     owner approved T's join by, and the fingerprint the export approval on
//     S names (Q8). S seals to exactly the key the owner saw; a management
//     node that substituted its own key would have to make the owner approve
//     a fingerprint that is not on T's own page.
//   - ONLY S CAN HAVE WRITTEN IT. It is signed with S's agent key under its
//     own domain prefix, and T trusts the one S key its dormant install
//     recorded (Q7).
//
// ONE KEY, TWO JOBS. The agent key is Ed25519, made for signing. Sealing to
// it converts it to X25519 — the public half by the birational map from the
// Edwards curve, the private half by the scalar Ed25519 itself derives from
// the seed. That pairing is studied and in wide use (age seals to ssh-ed25519
// keys the same way). What keeps the two jobs apart is domain separation: the
// seal's HKDF context and the signature's prefix are this file's own, and
// neither is ever the agent's request signature (identity.go signs messages
// that begin "joinery-agent-v1").
//
// NOT libsodium's sealed box, and nothing outside this agent opens it: the
// construction is the one sealToRecoveryKey uses — ephemeral X25519,
// HKDF-SHA256, AES-256-GCM — with curve25519.X25519, which refuses a
// low-order recipient whose shared secret anyone could compute.

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// CopyExportDomain names everything an export is: its signature prefix, its
// seal's HKDF context, and the format field T checks first.
const CopyExportDomain = "joinery-copy-export-v1"

// copyExportLifetime is how long T accepts a bundle after S issued it. An
// export is imported minutes after it is made — at the final copy, inside
// the downtime — so this bounds how long a bundle sitting in a job row on
// the management node stays usable, not how long anyone waits.
const copyExportLifetime = 6 * time.Hour

// copyExportClockSkew is how far ahead of T's clock S's may be. Further than
// this and the bundle's issue time would raise T's high-water mark past
// every honest bundle S makes for the next while.
const copyExportClockSkew = 15 * time.Minute

// copyExportMaxBundle bounds the bundle as it travels: S's job result must
// carry it (the result cap is 256 KiB) and so must T's job params. A copy
// whose certificates and keys do not fit is refused at S, naming the size.
const copyExportMaxBundle = 200 * 1024

// copyExportMaxPayload bounds what an opened bundle may decompress to.
const copyExportMaxPayload = 4 * 1024 * 1024

// fieldPrime is 2^255 - 19, the prime both curves are defined over.
var fieldPrime = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))

// ed25519PublicToX25519 maps an Ed25519 public key to the X25519 public key
// of the same secret: u = (1 + y) / (1 - y) mod p, where y is the Edwards
// point's y-coordinate (the key's little-endian bytes, sign bit cleared).
func ed25519PublicToX25519(pub ed25519.PublicKey) ([]byte, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("not an Ed25519 public key")
	}
	le := make([]byte, 32)
	copy(le, pub)
	le[31] &= 0x7f
	y := new(big.Int).SetBytes(reverse(le))
	if y.Cmp(fieldPrime) >= 0 {
		return nil, errors.New("not a canonical Ed25519 public key")
	}
	one := big.NewInt(1)
	den := new(big.Int).Sub(one, y)
	den.Mod(den, fieldPrime)
	if den.Sign() == 0 {
		return nil, errors.New("an Ed25519 public key with no X25519 counterpart")
	}
	num := new(big.Int).Add(one, y)
	u := num.Mul(num, den.ModInverse(den, fieldPrime))
	u.Mod(u, fieldPrime)

	out := make([]byte, 32)
	u.FillBytes(out)
	return reverse(out), nil
}

// ed25519PrivateToX25519 is the X25519 secret of an Ed25519 private key: the
// first half of SHA-512 over the seed, which is the scalar Ed25519 signs with
// (curve25519.X25519 clamps it).
func ed25519PrivateToX25519(priv ed25519.PrivateKey) []byte {
	h := sha512.Sum512(priv.Seed())
	out := make([]byte, 32)
	copy(out, h[:32])
	zero(h[:])
	return out
}

func reverse(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[len(b)-1-i] = b[i]
	}
	return out
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// sealKey derives the AES key for one seal from the shared secret, bound to
// both public keys.
func sealKey(shared, ephPublic, recipient []byte) ([]byte, error) {
	info := append([]byte(CopyExportDomain+":seal:"), ephPublic...)
	info = append(info, recipient...)
	key := make([]byte, 32)
	if _, err := hkdf.New(sha256.New, shared, nil, info).Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

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

// OpenSealedToAgentKey opens what sealToAgentKey sealed, with the Ed25519
// private key it was sealed to. Exported for the agent's identity, which
// holds the key; nothing in this package does.
func OpenSealedToAgentKey(priv ed25519.PrivateKey, blob []byte) ([]byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, errors.New("not an Ed25519 private key")
	}
	if len(blob) < 32+12+16 {
		return nil, errors.New("the sealed part is too short to be a seal")
	}
	secret := ed25519PrivateToX25519(priv)
	defer zero(secret)
	own, err := curve25519.X25519(secret, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	ephPublic, iv, sealed := blob[:32], blob[32:44], blob[44:]
	shared, err := curve25519.X25519(secret, ephPublic)
	if err != nil {
		return nil, errors.New("the sealed part does not open with this machine's key")
	}
	key, err := sealKey(shared, ephPublic, own)
	zero(shared)
	if err != nil {
		return nil, err
	}
	gcm, err := newGCM(key)
	zero(key)
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil, iv, sealed, nil)
	if err != nil {
		return nil, errors.New("the sealed part does not open with this machine's key: it was sealed to another, or changed on the way")
	}
	return plain, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// copyExportSigned is the message S signs and T verifies: the domain, a
// newline, then the body's exact bytes. The body travels base64-encoded, so
// what is verified is what was signed, with no JSON re-encoding between.
func copyExportSigned(body []byte) []byte {
	return append([]byte(CopyExportDomain+"\n"), body...)
}

// copyBundle is the bundle on the wire: a body and S's signature over it.
type copyBundle struct {
	Body      string `json:"body"`
	Signature string `json:"signature"`
}

// copyBundleBody is what S signs. Everything T checks before it opens the
// seal is here, in the clear and under the signature.
type copyBundleBody struct {
	Format       string `json:"format"`
	SourceNodeID int64  `json:"source_node_id"`
	SourceKey    string `json:"source_key"`
	TargetKey    string `json:"target_key"`
	Issued       string `json:"issued"`
	Expires      string `json:"expires"`
	Sealed       string `json:"sealed"`
}

// copyPayload is what the seal holds, gzipped.
type copyPayload struct {
	Chains []copyChain    `json:"chains"`
	Files  []copyHostFile `json:"files"`
}

// copyChain is one chain T may apply: its data key, and the manifest
// versions S vouches for.
type copyChain struct {
	ChainID   string   `json:"chain_id"`
	DataKey   string   `json:"data_key"`
	Manifests []string `json:"manifests"`
}

// copyHostFile is one entry of the host bundle (D5): a directory, a file
// with its bytes, or a symlink with its target. Its place is a root by name
// ("letsencrypt" or "dkim", copyHostRoots) and a path inside it, so neither
// side ever reads an absolute path off the other. Owner and group travel by
// name; T maps them to its own ids.
type copyHostFile struct {
	Root  string `json:"root"`
	Path  string `json:"path"`
	Kind  string `json:"kind"` // "dir", "file" or "link"
	Mode  uint32 `json:"mode,omitempty"`
	Owner string `json:"owner,omitempty"`
	Group string `json:"group,omitempty"`
	Data  string `json:"data,omitempty"`
	Link  string `json:"link,omitempty"`
}

// signCopyBundle builds the wire bundle from a body, signing with sign.
func signCopyBundle(body copyBundleBody, sign func([]byte) ([]byte, error)) (string, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	sig, err := sign(copyExportSigned(raw))
	if err != nil {
		return "", err
	}
	out, err := json.Marshal(copyBundle{
		Body:      base64.StdEncoding.EncodeToString(raw),
		Signature: base64.StdEncoding.EncodeToString(sig),
	})
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// verifyCopyBundle checks the signature against the one S key T trusts and
// returns the body. Nothing in the body is read before this passes.
func verifyCopyBundle(wire string, source ed25519.PublicKey) (copyBundleBody, error) {
	var b copyBundle
	var body copyBundleBody
	dec := json.NewDecoder(bytes.NewReader([]byte(wire)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		return body, errors.New("the bundle is not an export bundle")
	}
	raw, err1 := base64.StdEncoding.DecodeString(b.Body)
	sig, err2 := base64.StdEncoding.DecodeString(b.Signature)
	if err1 != nil || err2 != nil || len(sig) != ed25519.SignatureSize {
		return body, errors.New("the bundle is not an export bundle")
	}
	if !ed25519.Verify(source, copyExportSigned(raw), sig) {
		return body, errors.New("the bundle's signature is not the source's: it was made by another key, or changed on the way")
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return body, errors.New("the signed body is not an export body")
	}
	if body.Format != CopyExportDomain {
		return body, fmt.Errorf("the bundle is in format %q, and this agent reads %q", body.Format, CopyExportDomain)
	}
	return body, nil
}
