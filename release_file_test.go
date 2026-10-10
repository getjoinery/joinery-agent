package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"joinery-agent/primitives"
)

// A node tells the plane which deployment files differ from its release, and can
// ask the plane for one of them back (specs/release_file_repair.md).

func relSiteForPoll(t *testing.T, body string) (string, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	root := t.TempDir()
	manifest := "# manifest\n"
	for _, rel := range primitives.SelfUpdateFiles {
		full := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body+rel), 0o644); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256([]byte(body + rel))
		manifest += hex.EncodeToString(sum[:]) + "  " + rel + "\n"
	}
	if err := os.WriteFile(filepath.Join(root, "RELEASE_MANIFEST"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(manifest))) + "\n"
	if err := os.WriteFile(filepath.Join(root, "RELEASE_MANIFEST.sig"), []byte(sig), 0o644); err != nil {
		t.Fatal(err)
	}
	return root, pub, priv
}

func TestThePollNamesTheFilesThatDifferFromTheRelease(t *testing.T) {
	root, pub, _ := relSiteForPoll(t, "<?php // 0.8.475 ")
	env := &primitives.ExecEnv{SiteRoot: root, WebRoot: filepath.Join(root, "public_html"),
		Manifest: primitives.NewArtifactManifests(root, pub)}
	src := sitelessSource(t, env)

	if got := src.scriptTrust(); got != "ok" {
		t.Fatalf("matching files report ok, got %q", got)
	}
	if names, checked := src.scriptTrustFiles(); !checked || len(names) != 0 {
		t.Fatalf("a node that looked and found nothing sends an empty list, got %v checked=%v", names, checked)
	}

	// An upgrade stopped after replacing upgrade.php.
	changed := filepath.Join(root, "public_html", "utils", "upgrade.php")
	if err := os.WriteFile(changed, []byte("<?php // 0.8.477"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := src.scriptTrust(); got != "untrusted_file" {
		t.Fatalf("a differing deployment file reports untrusted_file, got %q", got)
	}
	names, checked := src.scriptTrustFiles()
	if !checked || len(names) != 1 || names[0] != "public_html/utils/upgrade.php" {
		t.Fatalf("the file is named, got %v checked=%v", names, checked)
	}
}

func TestAnUnusableManifestStaysTheManifestsReport(t *testing.T) {
	root, pub, _ := relSiteForPoll(t, "<?php ")
	env := &primitives.ExecEnv{SiteRoot: root, WebRoot: filepath.Join(root, "public_html"),
		Manifest: primitives.NewArtifactManifests(root, pub)}
	src := sitelessSource(t, env)
	_ = os.Remove(filepath.Join(root, "RELEASE_MANIFEST"))
	if got := src.scriptTrust(); got != "untrusted_manifest" {
		t.Fatalf("an unusable manifest is reported as that, never as a file, got %q", got)
	}
	if _, checked := src.scriptTrustFiles(); checked {
		t.Fatal("files cannot be judged against a manifest that cannot be used")
	}
}

func TestFetchReleaseFileAsksForTheInstalledVersionAndANamedFile(t *testing.T) {
	var got struct {
		Kind    string `json:"kind"`
		Version string `json:"version"`
		File    string `json:"file"`
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&got)
		writeEnvelope(w, map[string]interface{}{
			"available": true,
			"content":   base64.StdEncoding.EncodeToString([]byte("<?php // signed\n")),
		})
	}))
	defer server.Close()
	installTestIdentity(t, server.URL)

	body, err := fetchReleaseFile(context.Background(), newPlaneClient(false), "0.8.475", "public_html/utils/upgrade.php")
	if err != nil || string(body) != "<?php // signed\n" {
		t.Fatalf("fetch: %q err=%v", body, err)
	}
	if got.Kind != artifactKindReleaseFile || got.Version != "0.8.475" || got.File != "public_html/utils/upgrade.php" {
		t.Fatalf("wrong request: %+v", got)
	}
	if _, err := fetchReleaseFile(context.Background(), newPlaneClient(false), "0.8.475", "public_html/index.php"); err == nil {
		t.Fatal("a file outside the five is never asked for")
	}
}

func TestFetchReleaseFileSaysWhenThePlaneHasNoCopy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeEnvelope(w, map[string]interface{}{"available": false})
	}))
	defer server.Close()
	installTestIdentity(t, server.URL)
	if _, err := fetchReleaseFile(context.Background(), newPlaneClient(false), "0.8.475", "public_html/utils/upgrade.php"); err == nil {
		t.Fatal("an absent copy is an error the word can refuse on")
	}
}
