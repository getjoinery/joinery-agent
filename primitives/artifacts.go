package primitives

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
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
	cache map[string]cachedVerifier
}

// cachedVerifier is a parsed manifest plus the identity of the file it was
// parsed from, so a manifest replaced under a running process is noticed.
type cachedVerifier struct {
	verifier *SignedTreeVerifier
	stamp    string
}

// NewArtifactManifests builds a verifier over a site root.
func NewArtifactManifests(root string, pubKey ed25519.PublicKey) *ArtifactManifests {
	return &ArtifactManifests{Root: root, PubKey: pubKey, cache: map[string]cachedVerifier{}}
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

// Usable reports whether this artifact's manifest can be used at all: present,
// parseable, and signed by the key compiled into this binary. Nil means script
// primitives for that artifact can run; an error is the reason they cannot.
//
// THE DISTINCTION THIS METHOD DRAWS IS THE WHOLE OF ITS PURPOSE. It answers a
// question about the MANIFEST, never about a file. A file that does not match
// its signed hash fails in Verify() and never reaches here, which is what keeps
// manifest recovery structurally incapable of firing on a modified file — the
// one case where fetching a fresh manifest would destroy the evidence the check
// exists to produce. See specs/agent_manifest_trust_recovery.md.
func (a *ArtifactManifests) Usable(owner string) error {
	_, err := a.verifierFor(owner)
	return err
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

// verifierFor loads one artifact's manifest, caching the parse but never the
// FILE — a cached entry is used only while the manifest on disk is still the one
// it was parsed from.
//
// Failures are deliberately NOT cached. An upgrade can deliver a manifest to an
// artifact that had none, and this process may outlive that — an agent caching
// "no manifest" would keep refusing scripts it has since been given the means to
// verify. Re-reading a file that is not there costs a syscall.
//
// SUCCESS IS NOT CACHED ACROSS A CHANGE TO THE FILE EITHER, and that half is
// less obvious. This agent outlives many core releases — the binary changes far
// less often than the platform does — so a process that parsed a manifest at
// startup and never looked again goes on verifying against it after an upgrade
// has replaced both the manifest and the files it describes. Every changed file
// then fails its hash and is reported as MODIFIED SINCE RELEASE: a routine
// upgrade reads as tampering, which is the most alarming possible way to be
// wrong. The mirror case is as bad the other way — a manifest replaced with an
// unusable one stays invisible, and the node reports itself healthy, until
// something restarts the process.
//
// So the cache carries the file's identity and is dropped when that changes.
// Re-reading is a stat on the common path; a reload is one Ed25519 verify and a
// parse, on an operation that runs a script as root.
func (a *ArtifactManifests) verifierFor(owner string) (*SignedTreeVerifier, error) {
	dir := a.Root
	if owner != "" {
		dir = filepath.Join(a.Root, filepath.FromSlash(owner))
	}
	stamp := manifestStamp(filepath.Join(dir, "RELEASE_MANIFEST"))

	a.mu.Lock()
	if entry, ok := a.cache[owner]; ok && entry.stamp == stamp {
		a.mu.Unlock()
		return entry.verifier, nil
	}
	a.mu.Unlock()

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
	a.cache[owner] = cachedVerifier{verifier: verifier, stamp: stamp}
	a.mu.Unlock()
	return verifier, nil
}

// manifestStamp identifies the manifest file cheaply enough to check on every
// use: size, modification time and inode. Lstat, so a manifest swapped for a
// symlink is a different stamp rather than a silent read through it.
//
// A file that cannot be stat'ed gets a stamp of its own, which is what makes a
// deleted manifest invalidate a cached verifier instead of leaving the last good
// one answering for a tree that no longer has one.
func manifestStamp(path string) string {
	st, err := os.Lstat(path)
	if err != nil {
		return "absent"
	}
	stamp := strconv.FormatInt(st.Size(), 10) + ":" +
		strconv.FormatInt(st.ModTime().UnixNano(), 10) + ":" +
		st.Mode().String()
	if sys, ok := st.Sys().(*syscall.Stat_t); ok && sys != nil {
		stamp += ":" + strconv.FormatUint(uint64(sys.Ino), 10)
	}
	return stamp
}

func artifactUnverifiable(owner, why string) error {
	name := "this release"
	if owner != "" {
		name = owner
	}
	return errors.New("no script from " + name + " can be verified before running as root: " + why)
}
