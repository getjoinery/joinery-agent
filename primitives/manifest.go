package primitives

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ManifestVerifier answers one question: is this file on disk byte-for-byte
// the file the publisher signed?
//
// It exists because the site tree is writable by the web user while the agent
// runs as root. A script-invoking primitive that execs a web-tree file without
// this check would turn a web-layer compromise into root — the exact discipline
// the self-update path already applies to the agent binary, generalised (§3.2).
type ManifestVerifier interface {
	// Verify returns nil only when path is present in the signed manifest and
	// its contents hash to the recorded value. Every other outcome is an error,
	// including "nothing can be verified here" — see UnavailableVerifier.
	Verify(path string) error
}

// ErrNoReleaseKey is the refusal of an agent built without the release key
// (a hand build that skipped -ldflags "-X main.updatePubKeyB64=..."). With no
// key there is nothing to check a manifest's signature against, so every
// script-invoking primitive is unavailable rather than unverified. It names
// the build, not the release: the remedy is to rebuild the agent, and a
// manifest delivered to that node would change nothing.
//
// The wording is the plane's contract: NodeMonitorHealth::classify_script_trust
// matches "can be verified before running as root" and must keep doing so.
var ErrNoReleaseKey = errors.New(
	"this agent build has no release key, so no script can be verified before running as root; rebuild the agent with the release key")

// ErrBadReleaseKey is the same refusal for a build whose baked release key
// does not decode as an Ed25519 public key.
var ErrBadReleaseKey = errors.New(
	"this agent build's release key is malformed, so no script can be verified before running as root; rebuild the agent with the release key")

// ErrNoSiteTree is the refusal of an agent with no site tree configured:
// there is no manifest to read, because there is no tree for one to describe.
var ErrNoSiteTree = errors.New(
	"this agent has no site tree configured, so no script can be verified before running as root")

// UnavailableVerifier refuses every file, with the reason it was built for.
// It is what an agent runs with when it cannot verify anything at all; a
// missing or unverifiable manifest on a configured tree is ArtifactManifests'
// refusal, not this one. The zero value refuses with ErrNoSiteTree.
type UnavailableVerifier struct {
	Reason error
}

// Verify always refuses.
func (u UnavailableVerifier) Verify(path string) error {
	if u.Reason != nil {
		return u.Reason
	}
	return ErrNoSiteTree
}

// NotInManifestError is the one refusal a verifier makes about a file it was
// never told about: absent from the signed manifest, as opposed to listed and
// altered. The two are different facts and are kept apart as types because a
// caller reads them differently. On a site tree an unlisted file is a stranger
// in a root-run path. On a machine running from the support bundle it is
// usually a script the bundle was never meant to carry, and the runner names
// that posture instead of reporting a file mismatch the plane would then chase
// (docker-prod, 2026-09-15: a site-only report primitive dispatched to the host
// coloured the node as tampered with).
//
// The wording is the plane's contract: NodeMonitorHealth::classify_script_trust
// matches "is not in the signed release manifest" and must keep doing so.
type NotInManifestError struct {
	// Rel is the tree-relative path, slash-separated, as the manifest would list it.
	Rel string
}

func (e *NotInManifestError) Error() string {
	return "file is not in the signed release manifest: " + e.Rel
}

// SignedTreeVerifier verifies files against a signed per-file manifest. It is
// the shape component G fills: the manifest maps a tree-relative path to a
// sha256, and the whole manifest carries one Ed25519 signature made with the
// release key whose public half is compiled into this binary. Verification
// makes no network call — forging it means forging Ed25519, not spoofing a host.
type SignedTreeVerifier struct {
	// Root is the tree the manifest's paths are relative to.
	Root string
	// Hashes maps a tree-relative path to its lowercase hex sha256.
	Hashes map[string]string
	// Key is the release key the manifest's signature verified against.
	Key ed25519.PublicKey
}

// NewSignedTreeVerifier checks the manifest's own signature before trusting a
// single hash in it, then returns a verifier over its contents.
func NewSignedTreeVerifier(root string, manifestBody, signature []byte, pubKey ed25519.PublicKey) (*SignedTreeVerifier, error) {
	return NewSignedTreeVerifierKeys(root, manifestBody, signature, []ed25519.PublicKey{pubKey})
}

// NewSignedTreeVerifierKeys is NewSignedTreeVerifier against a set of release
// keys, the machine's trusted set (specs/release_key_rotation.md R3): the
// signature must verify against one of them. Exactly one signature, of
// ed25519.SignatureSize bytes: anything else is refused, so nobody adds a
// second signer beside the first.
func NewSignedTreeVerifierKeys(root string, manifestBody, signature []byte, keys []ed25519.PublicKey) (*SignedTreeVerifier, error) {
	usable := 0
	for _, key := range keys {
		if len(key) == ed25519.PublicKeySize {
			usable++
		}
	}
	if usable == 0 {
		return nil, errors.New("release verification key is missing or malformed")
	}
	if len(signature) != ed25519.SignatureSize {
		return nil, errors.New("tree manifest signature is not one Ed25519 signature")
	}
	var signer ed25519.PublicKey
	for _, key := range keys {
		if len(key) == ed25519.PublicKeySize && ed25519.Verify(key, manifestBody, signature) {
			signer = key
			break
		}
	}
	if signer == nil {
		return nil, errors.New("tree manifest signature does not verify against a release key this machine trusts")
	}
	hashes, err := parseTreeManifest(manifestBody)
	if err != nil {
		return nil, err
	}
	return &SignedTreeVerifier{Root: root, Hashes: hashes, Key: signer}, nil
}

// Verify hashes the file at path and compares it to the manifest entry.
func (v *SignedTreeVerifier) Verify(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(v.Root, abs)
	if err != nil || strings.HasPrefix(rel, "..") {
		return errors.New("file is outside the signed tree: " + path)
	}
	want, listed := v.Hashes[filepath.ToSlash(rel)]
	if !listed {
		return &NotInManifestError{Rel: filepath.ToSlash(rel)}
	}
	got, err := fileSha256(abs)
	if err != nil {
		return err
	}
	if got != want {
		return errors.New("file does not match its signed hash — it has been modified since release: " + rel)
	}
	return nil
}

func fileSha256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// parseTreeManifest reads the "<sha256>  <relative/path>" lines a signed tree
// manifest carries.
func parseTreeManifest(body []byte) (map[string]string, error) {
	out := map[string]string{}
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// sha256sum convention: 64 hex characters, two spaces, then the path.
		// The path may itself contain spaces — one real file in the shipped
		// tree does — so the line is CUT at a fixed offset, never
		// whitespace-split: Fields() here once made a single spaced filename
		// unreadable and took every script primitive on the node with it.
		if len(line) < 67 || line[64] != ' ' || line[65] != ' ' {
			return nil, errors.New("tree manifest has an unreadable line")
		}
		hash := line[:64]
		path := line[66:]
		if _, err := hex.DecodeString(hash); err != nil {
			return nil, errors.New("tree manifest has a non-hex hash")
		}
		out[filepath.ToSlash(path)] = strings.ToLower(hash)
	}
	if len(out) == 0 {
		return nil, errors.New("tree manifest lists no files")
	}
	return out, nil
}
