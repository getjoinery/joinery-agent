package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"joinery-agent/primitives"
)

// A node's poll-time trust report answers for the tree it runs scripts from.
// On a machine with no site that is the support bundle — so a siteless node
// can set and clear the plane's script-trust state the way a site node does,
// instead of standing mute while a refusal it can never repeat colours it red
// (docker-prod, 2026-09-15).

// signedToolTree writes one file and a manifest signed by a fresh key at root,
// and returns the key the verifier must be built with.
func signedToolTree(t *testing.T, root string) ed25519.PublicKey {
	t.Helper()
	rel := "maintenance_scripts/install_tools/host_housekeeping.sh"
	body := "#!/bin/bash\nexit 0\n"
	full := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(body))
	manifest := hex.EncodeToString(sum[:]) + "  " + rel + "\n"
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "RELEASE_MANIFEST"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(manifest))) + "\n"
	if err := os.WriteFile(filepath.Join(root, "RELEASE_MANIFEST.sig"), []byte(sig), 0o644); err != nil {
		t.Fatal(err)
	}
	return pub
}

func stampBundle(t *testing.T, root, version string) {
	t.Helper()
	raw, _ := json.Marshal(bundleStamp{Version: version, SourceSha256: "abc"})
	if err := os.WriteFile(root+".version", raw, 0o644); err != nil {
		t.Fatal(err)
	}
}

func sitelessSource(t *testing.T, env *primitives.ExecEnv) *RemoteSource {
	t.Helper()
	return NewRemoteSource(&NodeIdentity{NodeID: 7, PlaneURL: "https://mn.example"},
		&primitives.Policy{Accept: []primitives.Class{primitives.ClassObserve}}, env, &sync.Mutex{}, "9.9.9")
}

func TestASitelessNodeReportsTrustFromItsBundle(t *testing.T) {
	root := filepath.Join(t.TempDir(), "tree")
	t.Setenv("AGENT_TOOL_ROOT", root)
	pub := signedToolTree(t, root)
	stampBundle(t, root, "deadbeef")

	env := &primitives.ExecEnv{
		Manifest:     primitives.UnavailableVerifier{}, // what a siteless machine's site verifier is
		ToolRoot:     root,
		ToolManifest: primitives.NewArtifactManifests(root, pub),
	}
	if got := sitelessSource(t, env).scriptTrust(); got != "ok" {
		t.Fatalf("a siteless node with a good bundle reports ok; got %q", got)
	}

	// The bundle's manifest stops verifying: the same state a site node
	// reports as untrusted_manifest, reported the same way.
	if err := os.WriteFile(filepath.Join(root, "RELEASE_MANIFEST"), []byte("tampered\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := sitelessSource(t, env).scriptTrust(); got != "untrusted_manifest" {
		t.Fatalf("a bundle whose manifest does not verify is a manifest problem; got %q", got)
	}
}

// Between the join and the first bundle delivery the machine has been handed
// nothing to verify. It says nothing, rather than a manifest problem the plane
// would paint red for the minute it takes the bundle to land.
func TestASitelessNodeWithNoBundleYetSaysNothing(t *testing.T) {
	root := filepath.Join(t.TempDir(), "tree")
	t.Setenv("AGENT_TOOL_ROOT", root)
	pub, _, _ := ed25519.GenerateKey(nil)
	env := &primitives.ExecEnv{
		Manifest:     primitives.UnavailableVerifier{},
		ToolRoot:     root,
		ToolManifest: primitives.NewArtifactManifests(root, pub),
	}
	if got := sitelessSource(t, env).scriptTrust(); got != "" {
		t.Fatalf("no bundle yet is no answer; got %q", got)
	}
}

// A site node is unchanged: its site tree answers, and a bundle beside it —
// which no site machine has — would not be consulted.
func TestASiteNodeStillReportsTrustFromItsSiteTree(t *testing.T) {
	env := &primitives.ExecEnv{SiteRoot: t.TempDir(), Manifest: primitives.UnavailableVerifier{}}
	if got := sitelessSource(t, env).scriptTrust(); got != "" {
		t.Fatalf("a site verifier that is not manifest-backed says nothing; got %q", got)
	}
}
