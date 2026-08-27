package primitives

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// ArtifactManifests verifies a file against the signed manifest of the artifact
// that SHIPS it — core's manifest for core files, a plugin's own for that
// plugin's files (component G, spec §10.3 Surprise 1).
//
// One manifest per release would have been simpler and wrong. Plugin archives
// ship and upgrade independently of the core release: the marketplace installs
// plugins after a deploy, and extensions marked receives_upgrades:false are
// preserved on purpose. A core-signed manifest would therefore describe a tree a
// node can legitimately diverge from, and a routine plugin update would silently
// stop that plugin's scripts verifying — the kind of failure diagnosed months
// later as "primitives mysteriously stopped working on nodes with plugin X".
//
// Two rules make that safe, and both are structural rather than remembered:
//
//   - NO CROSS-MANIFEST FALLBACK. A file is verified against its owner's
//     manifest or not at all. Falling back to core's would let a plugin file be
//     "verified" by a manifest that never listed it, which is not verification.
//   - NO MANIFEST MEANS UNAVAILABLE. An artifact without a manifest — an older
//     archive, a third-party plugin — yields a refusal for its scripts, never a
//     warning and a run. This mirrors UnavailableVerifier: the boundary is
//     closed by default and opens only on proof.
type ArtifactManifests struct {
	// Root is the site root; every manifest records paths relative to it.
	Root string
	// PubKey is the release verification key compiled into this binary. No
	// manifest is trusted for a single hash before its signature verifies
	// against this, and nothing is fetched to obtain it.
	PubKey ed25519.PublicKey

	mu    sync.Mutex
	cache map[string]*SignedTreeVerifier
}

// NewArtifactManifests builds a verifier over a site root.
func NewArtifactManifests(root string, pubKey ed25519.PublicKey) *ArtifactManifests {
	return &ArtifactManifests{Root: root, PubKey: pubKey, cache: map[string]*SignedTreeVerifier{}}
}

// Verify resolves the file to its owning artifact and checks it there.
func (a *ArtifactManifests) Verify(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(a.Root, abs)
	if err != nil || strings.HasPrefix(rel, "..") {
		return errors.New("file is outside the site root: " + path)
	}
	rel = filepath.ToSlash(rel)

	owner := owningArtifact(rel)
	verifier, err := a.verifierFor(owner)
	if err != nil {
		return err
	}
	return verifier.Verify(abs)
}

// owningArtifact returns the site-root-relative directory of the artifact that
// ships a file, or "" for the core release.
//
// Plugins and themes are the only independently-shipped artifacts; everything
// else — public_html itself, maintenance_scripts, utils — travels in the core
// archive and is covered by the manifest at the site root.
func owningArtifact(rel string) string {
	parts := strings.Split(rel, "/")
	if len(parts) >= 3 && parts[0] == "public_html" {
		switch parts[1] {
		case "plugins", "theme":
			return strings.Join(parts[:3], "/")
		}
	}
	return ""
}

// verifierFor loads and caches one artifact's manifest.
//
// Failures are deliberately NOT cached. An upgrade can deliver a manifest to an
// artifact that had none, and this process may outlive that — an agent caching
// "no manifest" would keep refusing scripts it has since been given the means to
// verify. Re-reading a file that is not there costs a syscall.
func (a *ArtifactManifests) verifierFor(owner string) (*SignedTreeVerifier, error) {
	a.mu.Lock()
	if v, ok := a.cache[owner]; ok {
		a.mu.Unlock()
		return v, nil
	}
	a.mu.Unlock()

	dir := a.Root
	if owner != "" {
		dir = filepath.Join(a.Root, filepath.FromSlash(owner))
	}

	body, err := os.ReadFile(filepath.Join(dir, "RELEASE_MANIFEST"))
	if err != nil {
		return nil, artifactUnverifiable(owner, "it ships no signed release manifest")
	}
	sigRaw, err := os.ReadFile(filepath.Join(dir, "RELEASE_MANIFEST.sig"))
	if err != nil {
		return nil, artifactUnverifiable(owner, "its release manifest has no signature")
	}
	signature, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sigRaw)))
	if err != nil {
		return nil, artifactUnverifiable(owner, "its manifest signature is not readable base64")
	}

	verifier, err := NewSignedTreeVerifier(a.Root, body, signature, a.PubKey)
	if err != nil {
		return nil, artifactUnverifiable(owner, err.Error())
	}

	a.mu.Lock()
	a.cache[owner] = verifier
	a.mu.Unlock()
	return verifier, nil
}

func artifactUnverifiable(owner, why string) error {
	name := "this release"
	if owner != "" {
		name = owner
	}
	return errors.New("no script from " + name + " can be verified before running as root: " + why)
}
