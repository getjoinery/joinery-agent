package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"joinery-agent/primitives"
)

// The support bundle: a signed tree of the scripts a machine with no site
// invokes, and the answer to a problem that looked like three problems.
//
// A script-invoking primitive verifies its script against the signed release
// manifest before running it as root. That check is what stops a web-layer
// compromise becoming root, and it resolves everything against the site tree —
// so a machine with NO site tree has nothing to verify against and therefore no
// script primitives at all. Its entire vocabulary is embedded Go. That is the
// constraint that made "rewrite the relay provisioning in Go" look necessary,
// and it is a constraint about verification rather than about language: what a
// relay needs is not Go instead of a script, it is a script it can prove.
//
// So the same channel that serves the agent binary serves a small signed tree,
// unpacked root-owned to /opt/joinery-agent/tree. It carries its own
// RELEASE_MANIFEST and .sig, signed with the release key, and script primitives
// resolve against it when there is no site root.
//
// THE TRUST ROOT IS INSIDE THE BUNDLE, NOT ON THE WIRE. The plane serves bytes
// it cannot sign — it does not hold the release key — so nothing it says about
// those bytes is believed. The sha256 it advertises is used for exactly one
// thing: skipping a download this machine already has. What makes the tree
// usable is the signature INSIDE it, verified against the key compiled into
// this binary, and then every file in the tree hashed against that manifest.
// A plane that lies about the sha256 achieves a wasted download; a plane that
// serves a tampered tree achieves a refusal.
//
// AND THE CHECK IS TWO-SIDED. Every file the manifest lists must match its
// hash, AND no file may exist in the tree that the manifest does not list — a
// tarball can add a file as easily as it can change one, and a bundle carrying
// an unlisted executable beside a listed one would otherwise unpack happily.

// bundleRootDefault is where the verified tree lives. Root-owned, outside any
// web tree, and deliberately not under the site root a node might have.
const bundleRootDefault = "/opt/joinery-agent/tree"

const (
	// maxBundleArtifactBytes bounds the compressed bundle on the wire. It
	// carries shell scripts and, later, a prebuilt sealer binary.
	maxBundleArtifactBytes = 32 << 20

	// maxBundleUnpackedBytes bounds what those bytes become, which is the
	// number a decompression bomb attacks.
	maxBundleUnpackedBytes = 128 << 20

	// maxBundleEntries bounds the file count, because a million empty files is
	// a denial of service that no byte ceiling notices.
	maxBundleEntries = 4096
)

// BundleRoot is the installed tree's path, overridable for tests.
func BundleRoot() string {
	if v := os.Getenv("AGENT_TOOL_ROOT"); v != "" {
		return v
	}
	return bundleRootDefault
}

func bundleStampPath() string { return BundleRoot() + ".version" }

// bundleStamp records what is installed. Two values, because they answer two
// different questions: SourceSha256 is what the plane served (so a redundant
// download can be skipped) and Version identifies the VERIFIED CONTENT (so
// what the plane is told is a fact about the tree rather than about the
// delivery).
type bundleStamp struct {
	Version      string `json:"version"`
	SourceSha256 string `json:"source_sha256"`
}

func readBundleStamp() *bundleStamp {
	raw, err := os.ReadFile(bundleStampPath())
	if err != nil {
		return nil
	}
	var s bundleStamp
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil
	}
	return &s
}

// installedBundleVersion is what this machine reports on claim. Empty means
// "no bundle here", which is the honest answer on every machine that has a site
// tree to verify against and needs none.
func installedBundleVersion() string {
	if stamp := readBundleStamp(); stamp != nil {
		return stamp.Version
	}
	return ""
}

// BundleSync keeps the installed tree current. It runs on the same clock and
// under the same lock as the self-updater, for the same reason: swapping the
// scripts under a job that is running one of them is the file-level version of
// swapping the binary under a running job.
type BundleSync struct {
	source   *channelSource
	pubKey   ed25519.PublicKey
	siteless bool

	mu     sync.Mutex
	warned map[string]bool
	// lastSha suppresses re-fetching a bundle that failed verification until
	// the plane offers different bytes. Same backoff shape the updater applies
	// to a manifest that would not verify.
	failedSha string
}

// NewBundleSync returns nil when this machine has no business holding a
// bundle: one with a site tree verifies scripts against its own release, and
// giving it a second script root would be a second answer to a question that
// already has one. A build with no release key cannot verify a bundle and so
// must not install one.
func NewBundleSync(cfg *Config) *BundleSync {
	if cfg == nil || !cfg.Siteless {
		return nil
	}
	key, err := base64.StdEncoding.DecodeString(updatePubKeyB64)
	if updatePubKeyB64 == "" || err != nil || len(key) != ed25519.PublicKeySize {
		log.Printf("support bundle unavailable: this build carries no usable release key, so it could not verify one")
		return nil
	}
	return &BundleSync{
		source:   newChannelSource(cfg.PlaneTLSInsecure),
		pubKey:   ed25519.PublicKey(key),
		siteless: true,
		warned:   map[string]bool{},
	}
}

func (b *BundleSync) warnOnce(key, format string, args ...interface{}) {
	if b.warned[key] {
		return
	}
	b.warned[key] = true
	log.Printf(format, args...)
}

// CheckAndApply fetches, verifies and installs the bundle when the plane offers
// one this machine does not already have. Returns true when the tree changed.
func (b *BundleSync) CheckAndApply() bool {
	if b == nil {
		return false
	}
	id, err := b.source.identity()
	if err != nil {
		return false // not paired, or no usable credential: nothing to ask
	}

	ctx, cancel := context.WithTimeout(context.Background(), remoteHTTPTimeout)
	raw, err := signedArtifactEnvelope(ctx, b.source.client, id, artifactKindBundleInfo, "")
	cancel()
	if err != nil {
		b.warnOnce("info", "support bundle: could not ask %s what it has (retrying quietly): %v", id.PlaneURL, err)
		return false
	}

	var offer struct {
		Available bool   `json:"available"`
		Sha256    string `json:"sha256"`
		Bytes     int64  `json:"bytes"`
	}
	if err := json.Unmarshal(raw, &offer); err != nil {
		b.warnOnce("info-shape", "support bundle: %s described its bundle in a way this agent cannot read", id.PlaneURL)
		return false
	}
	if !offer.Available || offer.Sha256 == "" {
		return false // the plane's release ships no bundle
	}

	stamp := readBundleStamp()
	if stamp != nil && strings.EqualFold(stamp.SourceSha256, offer.Sha256) && bundleTreePresent() {
		return false // already installed
	}
	if b.failedSha != "" && strings.EqualFold(offer.Sha256, b.failedSha) {
		return false // refused once; not retried until the plane offers different bytes
	}
	if offer.Bytes > maxBundleArtifactBytes {
		b.warnOnce("size-"+offer.Sha256, "support bundle: %s offers a %d-byte bundle, over this agent's %d-byte limit — not fetched",
			id.PlaneURL, offer.Bytes, maxBundleArtifactBytes)
		b.failedSha = offer.Sha256
		return false
	}

	version, err := b.install(id, offer.Sha256)
	if err != nil {
		b.failedSha = offer.Sha256
		log.Printf("=== Support bundle === REFUSED: %v", err)
		log.Printf("  Not retrying until the management node offers a different bundle.")
		return false
	}

	log.Printf("=== Support bundle === installed %s at %s — script primitives are available on this machine",
		version, BundleRoot())
	return true
}

// install does the whole dance: fetch, integrity-check the delivery, unpack
// into a staging tree, verify that tree against its own signed manifest, and
// only then put it in place.
func (b *BundleSync) install(id *NodeIdentity, wantSha string) (string, error) {
	root := BundleRoot()
	if err := os.MkdirAll(filepath.Dir(root), 0o755); err != nil {
		return "", fmt.Errorf("cannot create %s: %w", filepath.Dir(root), err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), artifactHTTPTimeout)
	defer cancel()

	body, err := signedArtifactStream(ctx, b.source.client, id, artifactKindBundleBody, "", maxBundleArtifactBytes)
	if err != nil {
		return "", fmt.Errorf("fetching the bundle: %w", err)
	}
	defer body.Close()

	// Hash what actually arrived, and compare it to what was advertised. This
	// is a DELIVERY check, not a trust check — the signature below is the trust
	// check — and it earns its place by turning a truncated transfer into a
	// clear refusal instead of a confusing manifest failure.
	hasher := sha256.New()
	staging := root + ".new"
	if err := removeTree(staging); err != nil {
		return "", err
	}
	if err := unpackBundle(io.TeeReader(body, hasher), staging); err != nil {
		removeTree(staging)
		return "", err
	}
	got := hex.EncodeToString(hasher.Sum(nil))
	if !strings.EqualFold(got, wantSha) {
		removeTree(staging)
		return "", fmt.Errorf("the management node served bytes that do not match the bundle it advertised")
	}

	version, err := verifyBundleTree(staging, b.pubKey)
	if err != nil {
		removeTree(staging)
		return "", err
	}

	// Swap. The previous tree is kept only until the new one is in place; there
	// is no rollback to it, because a bundle that verified is by construction
	// the publisher's and a bundle that did not never got here.
	old := root + ".old"
	removeTree(old)
	if _, statErr := os.Stat(root); statErr == nil {
		if err := os.Rename(root, old); err != nil {
			removeTree(staging)
			return "", fmt.Errorf("cannot move the previous bundle aside: %w", err)
		}
	}
	if err := os.Rename(staging, root); err != nil {
		os.Rename(old, root)
		removeTree(staging)
		return "", fmt.Errorf("cannot move the new bundle into place: %w", err)
	}
	removeTree(old)

	stamp, _ := json.Marshal(bundleStamp{Version: version, SourceSha256: strings.ToLower(wantSha)})
	if err := os.WriteFile(bundleStampPath(), append(stamp, '\n'), 0o644); err != nil {
		// The tree is in place and usable; only the record of it failed. Say
		// so rather than tearing down working scripts over a bookkeeping file.
		log.Printf("support bundle: installed, but the version stamp could not be written: %v", err)
	}
	return version, nil
}

func bundleTreePresent() bool {
	info, err := os.Stat(filepath.Join(BundleRoot(), primitivesManifestName))
	return err == nil && info.Mode().IsRegular()
}

// primitivesManifestName is the file the signed tree carries, and it is spelled
// the same on both sides of the wire on purpose: a bundle is verified by the
// very machinery a site tree is, so there is one manifest format in this system
// rather than a second one for machines that happen to have no site.
const primitivesManifestName = "RELEASE_MANIFEST"
const primitivesSignatureName = "RELEASE_MANIFEST.sig"

// unpackBundle extracts a gzipped tar into dest, refusing everything a tar can
// contain that a bundle has no business containing.
//
// The sender is hostile by assumption, so the rules are stated as refusals
// rather than sanitisations: a name that would escape the destination is not
// cleaned up and accepted, it ends the unpack. Symlinks and hard links are
// refused outright — a link is how an extraction writes outside its tree even
// when every name looks innocent, and a bundle of scripts needs none.
func unpackBundle(r io.Reader, dest string) error {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("the bundle is not gzip: %w", err)
	}
	defer gz.Close()

	if err := os.MkdirAll(dest, 0o755); err != nil {
		return fmt.Errorf("cannot create %s: %w", dest, err)
	}

	tr := tar.NewReader(io.LimitReader(gz, maxBundleUnpackedBytes+1))
	entries, written := 0, int64(0)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("the bundle is not a readable tar: %w", err)
		}
		entries++
		if entries > maxBundleEntries {
			return fmt.Errorf("the bundle holds more than %d entries", maxBundleEntries)
		}

		name, err := safeBundlePath(header.Name)
		if err != nil {
			return err
		}
		if name == "" {
			// The archive's own root entry ("./"), which every tar of a
			// directory carries. It names the destination, which already
			// exists; there is nothing to create and nothing wrong.
			continue
		}
		target := filepath.Join(dest, name)

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return fmt.Errorf("cannot create %s in the bundle: %w", name, err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return fmt.Errorf("cannot create the directory for %s: %w", name, err)
			}
			// Mode is masked, never taken as sent: 0755 keeps a script
			// executable and drops setuid, setgid and the sticky bit, none of
			// which a shipped script needs and any of which would be a
			// privilege escalation delivered by tar.
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_EXCL, os.FileMode(header.Mode)&0o755)
			if err != nil {
				return fmt.Errorf("cannot write %s from the bundle: %w", name, err)
			}
			n, err := io.Copy(f, tr)
			f.Close()
			if err != nil {
				return fmt.Errorf("cannot write %s from the bundle: %w", name, err)
			}
			written += n
			if written > maxBundleUnpackedBytes {
				return fmt.Errorf("the bundle unpacks to more than this agent's %d-byte limit", maxBundleUnpackedBytes)
			}
		default:
			// Symlinks, hard links, devices, fifos. A bundle carries scripts
			// and directories; anything else is either an attack or a mistake,
			// and the two are indistinguishable from here.
			return fmt.Errorf("the bundle carries %q, which is not a plain file or directory — refused", header.Name)
		}
	}
	if entries == 0 {
		return fmt.Errorf("the bundle is empty")
	}
	return nil
}

// safeBundlePath turns a tar entry name into a relative path inside the tree,
// refuses it, or reports it as the archive's own root.
//
// An empty return with no error means the ROOT ENTRY — "./", which every tar of
// a directory begins with. It is not an error and not a file: it names the
// destination itself. Treating it as either (refusing it, or trying to create
// it) would make a correctly built bundle fail on its first entry, which is a
// fine way to ship a mechanism that never works.
func safeBundlePath(name string) (string, error) {
	clean := filepath.ToSlash(strings.TrimSpace(name))
	if strings.Contains(clean, `\`) {
		return "", fmt.Errorf("the bundle carries a backslash in %q — refused", name)
	}
	if strings.HasPrefix(clean, "/") || filepath.IsAbs(clean) {
		return "", fmt.Errorf("the bundle carries an absolute path %q — refused", name)
	}
	// A climb is refused wherever it appears, not only at the front: a check on
	// the prefix alone misses "scripts/../../escaped.sh".
	for _, segment := range strings.Split(clean, "/") {
		if segment == ".." {
			return "", fmt.Errorf("the bundle carries a path that climbs out of the tree: %q — refused", name)
		}
	}

	clean = strings.TrimPrefix(clean, "./")
	clean = strings.TrimSuffix(clean, "/")
	if clean == "" || clean == "." {
		return "", nil // the root entry
	}

	// Belt and braces. filepath.Clean is what a caller would reach for and is
	// NOT sufficient on its own — it happily returns "../x" — so the segment
	// walk above is the real check and this only catches what it could not
	// have produced.
	final := filepath.Clean(clean)
	if final == "." || final == ".." || strings.HasPrefix(final, "../") || filepath.IsAbs(final) {
		return "", fmt.Errorf("the bundle carries an unusable path %q — refused", name)
	}
	return final, nil
}

// verifyBundleTree is where the bundle earns the right to be executed as root.
//
// The manifest's signature is checked against the key compiled into this binary
// — no network call, nothing fetched, nothing the plane could influence. Then
// every listed file is hashed, and the tree is walked to prove it holds nothing
// the manifest did not list. Returns the bundle's version: the hash of the
// manifest body, which identifies the verified content rather than the delivery.
func verifyBundleTree(root string, pubKey ed25519.PublicKey) (string, error) {
	body, err := os.ReadFile(filepath.Join(root, primitivesManifestName))
	if err != nil {
		return "", fmt.Errorf("the bundle carries no %s, so nothing in it can be verified", primitivesManifestName)
	}
	sigRaw, err := os.ReadFile(filepath.Join(root, primitivesSignatureName))
	if err != nil {
		return "", fmt.Errorf("the bundle's manifest carries no signature")
	}
	signature, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sigRaw)))
	if err != nil {
		return "", fmt.Errorf("the bundle's manifest signature is not readable base64")
	}

	verifier, err := primitives.NewSignedTreeVerifier(root, body, signature, pubKey)
	if err != nil {
		return "", fmt.Errorf("the bundle's manifest does not verify: %w", err)
	}

	listed := map[string]bool{}
	for rel := range verifier.Hashes {
		listed[rel] = true
		if err := verifier.Verify(filepath.Join(root, filepath.FromSlash(rel))); err != nil {
			return "", fmt.Errorf("the bundle does not match its own manifest: %w", err)
		}
	}

	// The other side of the check. A tar can ADD a file as easily as change
	// one, and an unlisted script sitting beside a listed one would be a file
	// nothing verified in a tree the agent otherwise trusts.
	err = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		rel = filepath.ToSlash(rel)
		if rel == primitivesManifestName || rel == primitivesSignatureName {
			return nil
		}
		if !listed[rel] {
			return fmt.Errorf("the bundle carries %s, which its own manifest does not list", rel)
		}
		return nil
	})
	if err != nil {
		return "", err
	}

	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])[:16], nil
}

func removeTree(path string) error {
	if err := os.RemoveAll(path); err != nil {
		return fmt.Errorf("cannot clear %s: %w", path, err)
	}
	return nil
}
