package primitives

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A long-running agent must notice that its manifest changed under it.
//
// The agent binary changes far less often than the platform does — one build
// spans many core releases — so a process that parsed the manifest at startup
// and cached it forever keeps verifying against the OLD one after an upgrade has
// replaced both the manifest and the files it describes. Every changed file then
// fails its hash and is reported as "modified since release": a routine upgrade
// reads as tampering. And the mirror case is as bad — a manifest replaced with
// an unusable one stays invisible while the node reports itself healthy.

func layTree(t *testing.T, key ed25519.PrivateKey, body string) (root, script string) {
	t.Helper()
	root = t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "public_html", "utils"), 0o755); err != nil {
		t.Fatal(err)
	}
	script = filepath.Join(root, "public_html", "utils", "upgrade.php")
	if err := os.WriteFile(script, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(body))
	manifest := "# manifest\n" + hex.EncodeToString(sum[:]) + "  public_html/utils/upgrade.php\n"
	signTree(t, root, key, manifest)
	return root, script
}

func signTree(t *testing.T, root string, key ed25519.PrivateKey, manifest string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, "RELEASE_MANIFEST"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(key, []byte(manifest))
	if err := os.WriteFile(filepath.Join(root, "RELEASE_MANIFEST.sig"),
		[]byte(base64.StdEncoding.EncodeToString(sig)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// An upgrade replaces the manifest AND the file. The same process must verify
// against the new pair, not report the new file as modified.
func TestAnUpgradeUnderARunningAgentIsNotReadAsTampering(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	root, script := layTree(t, priv, "<?php // v1\n")

	a := NewArtifactManifests(root, pub)
	if err := a.Verify(script); err != nil {
		t.Fatalf("the shipped tree should verify: %v", err)
	}

	// The upgrade lands: new file, new manifest describing it.
	next := "<?php // v2 — a later release\n"
	if err := os.WriteFile(script, []byte(next), 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(next))
	time.Sleep(10 * time.Millisecond) // a distinguishable mtime
	signTree(t, root, priv, "# manifest\n"+hex.EncodeToString(sum[:])+"  public_html/utils/upgrade.php\n")

	if err := a.Verify(script); err != nil {
		t.Fatalf("after an upgrade the same process must verify against the NEW manifest, got: %v", err)
	}
}

// The other direction: a manifest that becomes unusable while the process runs
// must stop reporting the node as healthy.
func TestAManifestBrokenUnderARunningAgentStopsVerifying(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	root, script := layTree(t, priv, "<?php // v1\n")

	a := NewArtifactManifests(root, pub)
	if err := a.Usable(""); err != nil {
		t.Fatalf("premise: the tree should start usable: %v", err)
	}

	// Somebody re-signs the live tree with another key — the getjoinery shape.
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	body, _ := os.ReadFile(filepath.Join(root, "RELEASE_MANIFEST"))
	time.Sleep(10 * time.Millisecond)
	signTree(t, root, other, string(body))

	if err := a.Usable(""); err == nil {
		t.Fatal("a re-signed manifest must stop being usable in the SAME process")
	}
	if err := a.Verify(script); err == nil {
		t.Fatal("and scripts must stop verifying")
	}
}

// A manifest deleted under the process must invalidate the cached verifier
// rather than leaving the last good one answering for a tree with none.
func TestADeletedManifestInvalidatesTheCache(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	root, _ := layTree(t, priv, "<?php // v1\n")

	a := NewArtifactManifests(root, pub)
	if err := a.Usable(""); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "RELEASE_MANIFEST")); err != nil {
		t.Fatal(err)
	}
	if err := a.Usable(""); err == nil {
		t.Fatal("a deleted manifest must not keep answering from cache")
	}
}

// An unchanged manifest still caches: the stamp check is a stat, not a reparse.
func TestAnUnchangedManifestIsNotReparsed(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	root, script := layTree(t, priv, "<?php // v1\n")

	a := NewArtifactManifests(root, pub)
	if err := a.Verify(script); err != nil {
		t.Fatal(err)
	}
	first, _ := a.verifierFor("")
	second, _ := a.verifierFor("")
	if first != second {
		t.Fatal("an unchanged manifest should be served from cache, not reparsed")
	}
}
