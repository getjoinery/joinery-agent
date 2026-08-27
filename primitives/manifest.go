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
	// including "there is no manifest" — see UnavailableVerifier.
	Verify(path string) error
}

// ErrNoManifest is the honest state of the platform today: the release pipeline
// signs the agent bundle, but there is no signed per-file tree manifest yet.
// That is component G of the migration, new publish-time work.
//
// Until it exists, this verifier refuses everything, which makes every
// script-invoking primitive unavailable rather than unverified. The gate is
// built and enforced now precisely so component G plugs into a boundary that
// is already closed, instead of one that has to be remembered.
var ErrNoManifest = errors.New(
	"this release carries no signed per-file tree manifest, so no script can be verified before running as root")

// UnavailableVerifier is the Phase 1 production verifier.
type UnavailableVerifier struct{}

// Verify always refuses.
func (UnavailableVerifier) Verify(path string) error { return ErrNoManifest }

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
}

// NewSignedTreeVerifier checks the manifest's own signature before trusting a
// single hash in it, then returns a verifier over its contents.
func NewSignedTreeVerifier(root string, manifestBody, signature []byte, pubKey ed25519.PublicKey) (*SignedTreeVerifier, error) {
	if len(pubKey) != ed25519.PublicKeySize {
		return nil, errors.New("release verification key is missing or malformed")
	}
	if !ed25519.Verify(pubKey, manifestBody, signature) {
		return nil, errors.New("tree manifest signature does not verify against the compiled-in release key")
	}
	hashes, err := parseTreeManifest(manifestBody)
	if err != nil {
		return nil, err
	}
	return &SignedTreeVerifier{Root: root, Hashes: hashes}, nil
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
		return errors.New("file is not in the signed release manifest: " + rel)
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
