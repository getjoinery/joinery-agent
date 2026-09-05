package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"

	"joinery-agent/primitives"
)

// Manifest recovery: getting a node that cannot verify its own scripts back to
// one that can, without a human on the box.
//
// The behaviour under test is small and the consequence of getting it wrong is
// not. A node whose MANIFEST is unusable refuses every script primitive it has,
// including the upgrade that would repair it — so this path is the only way back
// once SSH is gone. But the same refusal is also raised when a FILE does not
// match its signed hash, and there the remedy is opposite: the manifest is doing
// its job, the file on disk is not the file that was published, and fetching a
// fresh manifest would overwrite the evidence.
//
// So the tests here are mostly about what recovery must NOT do.

// writeSignedTree lays down a site root with a manifest signed by key, listing
// one file with its true hash. Returns the site root.
func writeSignedTree(t *testing.T, key ed25519.PrivateKey, scriptBody string) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "public_html", "utils"), 0o755); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(root, "public_html", "utils", "upgrade.php")
	if err := os.WriteFile(script, []byte(scriptBody), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "public_html", "VERSION"), []byte("0.8.370\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	sum := sha256.Sum256([]byte(scriptBody))
	body := "# Joinery release manifest\n" + hex.EncodeToString(sum[:]) + "  public_html/utils/upgrade.php\n"
	writeManifest(t, root, key, body)
	return root
}

func writeManifest(t *testing.T, root string, key ed25519.PrivateKey, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, "RELEASE_MANIFEST"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(key, []byte(body))
	if err := os.WriteFile(filepath.Join(root, "RELEASE_MANIFEST.sig"),
		[]byte(base64.StdEncoding.EncodeToString(sig)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func healerFor(t *testing.T, root string, pub ed25519.PublicKey) *manifestHealer {
	t.Helper()
	return &manifestHealer{
		siteRoot: root,
		verifier: primitives.NewArtifactManifests(root, pub),
		pubKey:   pub,
		warned:   map[string]bool{},
	}
}

// A healthy node does nothing at all — no fetch, no write, no noise. The
// ordinary case runs every ten minutes for the life of the agent.
func TestHealerLeavesAHealthyNodeAlone(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	root := writeSignedTree(t, priv, "<?php // upgrade\n")
	h := healerFor(t, root, pub)

	before, _ := os.ReadFile(filepath.Join(root, "RELEASE_MANIFEST"))
	if h.CheckAndHeal() {
		t.Fatal("a node whose manifest verifies must not be healed")
	}
	after, _ := os.ReadFile(filepath.Join(root, "RELEASE_MANIFEST"))
	if string(before) != string(after) {
		t.Fatal("a healthy node's manifest was rewritten")
	}
}

// THE RULE THAT MUST NOT BREAK.
//
// A file that does not match its signed hash means the file on disk is not the
// file that was published — precisely what the gate exists to catch. Recovery
// must not fire, must not fetch, and must not overwrite the manifest that is
// producing the evidence. The structure is what enforces this: a hash mismatch
// is raised by Verify, and the healer only ever consults Usable.
func TestHealerNeverFiresOnAModifiedFile(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	root := writeSignedTree(t, priv, "<?php // upgrade\n")

	// Someone modifies a root-run file after release.
	script := filepath.Join(root, "public_html", "utils", "upgrade.php")
	if err := os.WriteFile(script, []byte("<?php system($_GET['x']);\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	verifier := primitives.NewArtifactManifests(root, pub)
	if err := verifier.Verify(script); err == nil {
		t.Fatal("a modified file must fail verification — the test's premise is wrong")
	}
	// ...and the manifest itself is still perfectly usable, which is the whole
	// distinction. If Usable ever started reporting on files, recovery would
	// begin firing on tampering.
	if err := verifier.Usable(""); err != nil {
		t.Fatalf("a modified file must not make the MANIFEST unusable: %v", err)
	}

	h := healerFor(t, root, pub)
	h.verifier = verifier
	before, _ := os.ReadFile(filepath.Join(root, "RELEASE_MANIFEST"))
	if h.CheckAndHeal() {
		t.Fatal("recovery fired on a modified file — it must never do this")
	}
	after, _ := os.ReadFile(filepath.Join(root, "RELEASE_MANIFEST"))
	if string(before) != string(after) {
		t.Fatal("recovery overwrote the manifest that was catching a modified file")
	}
}

// A manifest signed by a key this binary does not carry is the getjoinery case:
// a republishing site re-signed its own live tree. Everything refuses, and the
// manifest — not any file — is what cannot be used.
func TestManifestSignedByAnotherKeyIsAManifestProblem(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	root := writeSignedTree(t, priv, "<?php // upgrade\n")

	// Re-sign the same tree with somebody else's key.
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	body, _ := os.ReadFile(filepath.Join(root, "RELEASE_MANIFEST"))
	writeManifest(t, root, other, string(body))

	v := primitives.NewArtifactManifests(root, pub)
	err := v.Usable("")
	if err == nil {
		t.Fatal("a manifest signed by another key must not be usable")
	}
	if !contains(err.Error(), "can be verified before running as root") {
		t.Fatalf("the refusal must carry the wording the plane classifies on, got: %v", err)
	}
}

// A missing manifest is the same class of problem: nothing is known about any
// file, so everything refuses.
func TestMissingManifestIsAManifestProblem(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	root := writeSignedTree(t, priv, "<?php // upgrade\n")
	os.Remove(filepath.Join(root, "RELEASE_MANIFEST"))

	if err := primitives.NewArtifactManifests(root, pub).Usable(""); err == nil {
		t.Fatal("a missing manifest must not be usable")
	}
}

// A manifest that does not verify against this binary's key is refused, is not
// written, and is not asked for again until what is on offer changes. A plane
// cannot talk a node into trusting a tree, and cannot make it spin either.
func TestHealerRefusesAManifestItCannotVerify(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	root := writeSignedTree(t, priv, "<?php // upgrade\n")

	// Break the node the way a republish does.
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	good, _ := os.ReadFile(filepath.Join(root, "RELEASE_MANIFEST"))
	writeManifest(t, root, other, string(good))

	h := healerFor(t, root, pub)

	// A plane offering a manifest signed by a key this node does not carry.
	forged := "# Joinery release manifest\n" + hex.EncodeToString(make([]byte, 32)) +
		"  public_html/utils/upgrade.php\n"
	calls := 0
	h.fetcher = func(string) (*manifestPair, error) {
		calls++
		return &manifestPair{manifest: []byte(forged), signature: ed25519.Sign(other, []byte(forged))}, nil
	}

	onDisk, _ := os.ReadFile(filepath.Join(root, "RELEASE_MANIFEST"))
	if h.CheckAndHeal() {
		t.Fatal("a manifest that does not verify must not count as healing")
	}
	after, _ := os.ReadFile(filepath.Join(root, "RELEASE_MANIFEST"))
	if string(onDisk) != string(after) {
		t.Fatal("a refused manifest was written to disk")
	}
	if calls != 1 {
		t.Fatalf("expected exactly one fetch, got %d", calls)
	}

	// The verdict holds until the bytes change. Re-fetching what was already
	// refused is noise that buries the one line saying why.
	if h.CheckAndHeal() {
		t.Fatal("second pass reported healing")
	}
	if calls != 2 {
		t.Fatalf("the healer should re-fetch but not re-judge; got %d calls", calls)
	}
	after2, _ := os.ReadFile(filepath.Join(root, "RELEASE_MANIFEST"))
	if string(onDisk) != string(after2) {
		t.Fatal("the second pass wrote a manifest it had already refused")
	}
}

// The whole path, on the shape that actually happened: a node whose live tree
// was re-signed with somebody else's key heals itself from what the plane
// offers, and apply_update's own script verifies again afterwards.
func TestHealerRecoversTheGetjoineryCase(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	root := writeSignedTree(t, priv, "<?php // upgrade\n")
	good, _ := os.ReadFile(filepath.Join(root, "RELEASE_MANIFEST"))

	_, other, _ := ed25519.GenerateKey(rand.Reader)
	writeManifest(t, root, other, string(good))

	h := healerFor(t, root, pub)
	if err := h.verifier.Usable(""); err == nil {
		t.Fatal("premise wrong: the node should be refusing before recovery")
	}

	asked := ""
	h.fetcher = func(version string) (*manifestPair, error) {
		asked = version
		return &manifestPair{manifest: good, signature: ed25519.Sign(priv, good)}, nil
	}

	if !h.CheckAndHeal() {
		t.Fatal("the node should have healed")
	}
	if asked != "0.8.370" {
		t.Fatalf("the healer asked for %q, not the version the site runs", asked)
	}
	if err := h.verifier.Usable(""); err != nil {
		t.Fatalf("after healing the manifest should be usable: %v", err)
	}
	if err := h.verifier.Verify(filepath.Join(root, "public_html", "utils", "upgrade.php")); err != nil {
		t.Fatalf("apply_update's script should verify, so the node can upgrade itself: %v", err)
	}

	// Healed nodes stop asking.
	calls := 0
	h.fetcher = func(string) (*manifestPair, error) { calls++; return nil, nil }
	if h.CheckAndHeal() || calls != 0 {
		t.Fatal("a healed node kept fetching")
	}
}

// A plane with nothing to offer — the archive pruned by retention, or a release
// predating signed manifests — is an ordinary answer, not an error, and must not
// be mistaken for a transport failure or latch anything off.
func TestHealerHandlesAPlaneWithNothingToOffer(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	root := writeSignedTree(t, priv, "<?php // upgrade\n")
	good, _ := os.ReadFile(filepath.Join(root, "RELEASE_MANIFEST"))
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	writeManifest(t, root, other, string(good))

	h := healerFor(t, root, pub)
	h.fetcher = func(string) (*manifestPair, error) { return nil, errNoManifestOffered }
	if h.CheckAndHeal() {
		t.Fatal("nothing on offer is not healing")
	}

	// And when the plane later has it, the node takes it — nothing was latched.
	h.fetcher = func(string) (*manifestPair, error) {
		return &manifestPair{manifest: good, signature: ed25519.Sign(priv, good)}, nil
	}
	if !h.CheckAndHeal() {
		t.Fatal("a plane that can help later must still be able to")
	}
}

// A verified pair replaces the pair on disk, and the node can verify again.
func TestInstallRestoresVerification(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	root := writeSignedTree(t, priv, "<?php // upgrade\n")

	good, _ := os.ReadFile(filepath.Join(root, "RELEASE_MANIFEST"))

	// Break it the way a republish does.
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	writeManifest(t, root, other, string(good))

	h := healerFor(t, root, pub)
	if err := h.verifier.Usable(""); err == nil {
		t.Fatal("premise wrong: the tree should be unusable before healing")
	}

	pair := &manifestPair{manifest: good, signature: ed25519.Sign(priv, good)}
	if err := h.install(pair); err != nil {
		t.Fatalf("install: %v", err)
	}
	if err := h.verifier.Usable(""); err != nil {
		t.Fatalf("after installing a good manifest the node should verify again: %v", err)
	}
	script := filepath.Join(root, "public_html", "utils", "upgrade.php")
	if err := h.verifier.Verify(script); err != nil {
		t.Fatalf("apply_update's own script should verify after recovery: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "RELEASE_MANIFEST.incoming")); !os.IsNotExist(err) {
		t.Fatal("the temporary file was left behind")
	}
}

// Install keeps whatever mode the existing pair had. The web user reads these
// during an upgrade; a root-only manifest would trade one failure for another.
func TestInstallPreservesMode(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	root := writeSignedTree(t, priv, "<?php // upgrade\n")
	path := filepath.Join(root, "RELEASE_MANIFEST")
	if err := os.Chmod(path, 0o660); err != nil {
		t.Fatal(err)
	}
	body, _ := os.ReadFile(path)

	h := healerFor(t, root, pub)
	if err := h.install(&manifestPair{manifest: body, signature: ed25519.Sign(priv, body)}); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o660 {
		t.Fatalf("mode not preserved: got %v, want 0660", st.Mode().Perm())
	}
}

// The version is read from a tree that is, by definition, not trusted. Being
// wrong must be safe, and unreadable must be an error rather than a guess.
func TestInstalledVersionRefusesRubbish(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	root := writeSignedTree(t, priv, "<?php // upgrade\n")
	h := healerFor(t, root, pub)

	if v, err := h.installedVersion(); err != nil || v != "0.8.370" {
		t.Fatalf("a normal VERSION should read back: %q %v", v, err)
	}

	for _, bad := range []string{"", "  ", "../../etc/passwd", "0.8.370; rm -rf /", "latest",
		"0.8.370\n0.8.371", string(make([]byte, 40))} {
		if err := os.WriteFile(filepath.Join(root, "public_html", "VERSION"), []byte(bad), 0o644); err != nil {
			t.Fatal(err)
		}
		if v, err := h.installedVersion(); err == nil {
			t.Fatalf("VERSION %q was accepted as %q", bad, v)
		}
	}
}

// A machine with no site tree has no release manifest to heal, and one built
// without a release key cannot verify anything. Both must decline to exist
// rather than run a loop that can never succeed.
func TestNoHealerWhereThereIsNothingToHeal(t *testing.T) {
	if h := newManifestHealer(&Config{SiteRoot: ""}, primitives.UnavailableVerifier{}); h != nil {
		t.Fatal("a machine with no site root should get no healer")
	}
	if h := newManifestHealer(&Config{SiteRoot: "/tmp"}, primitives.UnavailableVerifier{}); h != nil {
		t.Fatal("a verifier that is not manifest-backed should get no healer")
	}
	if h := newManifestHealer(nil, nil); h != nil {
		t.Fatal("no config should get no healer")
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (haystack == needle ||
		len(needle) == 0 || indexOf(haystack, needle) >= 0)
}

func indexOf(h, n string) int {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return i
		}
	}
	return -1
}

// The fetch itself, over a real HTTP round trip against a real signed request.
//
// THIS IS THE TEST THAT WAS MISSING. Every test above injects `fetcher`, so all
// of them passed while fetch() could not succeed at all: the ordinary plane
// answer is read under agentMaxJobBody (64 KiB) and a real manifest is 186 KiB,
// so every live recovery would have failed as "transport", warned once, and
// retried every ten minutes forever on a node that could do nothing else.
// A manifest LARGER than the default cap is the whole point of the case.
func TestFetchReadsAManifestLargerThanAJob(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	// Bigger than agentMaxJobBody, the size a real manifest actually is.
	var b []byte
	b = append(b, "# Joinery release manifest\n"...)
	for len(b) < 200*1024 {
		b = append(b, hex.EncodeToString(make([]byte, 32))...)
		b = append(b, "  public_html/some/file.php\n"...)
	}
	sig := ed25519.Sign(priv, b)

	var gotKind, gotOwner, gotVersion string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Kind    string `json:"kind"`
			Owner   string `json:"owner"`
			Version string `json:"version"`
		}
		json.NewDecoder(r.Body).Decode(&in)
		gotKind, gotOwner, gotVersion = in.Kind, in.Owner, in.Version
		writeEnvelope(w, map[string]interface{}{
			"available": true,
			"manifest":  string(b),
			"signature": base64.StdEncoding.EncodeToString(sig),
		})
	}))
	defer server.Close()
	installTestIdentity(t, server.URL)

	root := writeSignedTree(t, priv, "<?php // upgrade\n")
	h := healerFor(t, root, pub)
	h.client = newPlaneClient(false)

	pair, err := h.fetch("0.8.370")
	if err != nil {
		t.Fatalf("fetching a real-sized manifest failed: %v", err)
	}
	if len(pair.manifest) != len(b) || string(pair.manifest) != string(b) {
		t.Fatalf("manifest came back changed: got %d bytes, want %d", len(pair.manifest), len(b))
	}
	if !ed25519.Verify(pub, pair.manifest, pair.signature) {
		t.Fatal("the fetched pair does not verify — the bytes did not survive the round trip")
	}
	if gotKind != artifactKindReleaseManifest || gotOwner != "" || gotVersion != "0.8.370" {
		t.Fatalf("wrong request: kind=%q owner=%q version=%q", gotKind, gotOwner, gotVersion)
	}
}

// The cap is still a cap. A plane that answers with something enormous is
// refused unread rather than being allowed to hold this agent reading.
func TestFetchStillRefusesAnEnormousAnswer(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"api_version":"1.0","data":{"available":true,"manifest":"`))
		chunk := make([]byte, 64*1024)
		for i := range chunk {
			chunk[i] = 'A'
		}
		for written := 0; written < maxReleaseManifestBytes+(1<<20); written += len(chunk) {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
		w.Write([]byte(`"}}`))
	}))
	defer server.Close()
	installTestIdentity(t, server.URL)

	root := writeSignedTree(t, priv, "<?php // upgrade\n")
	h := healerFor(t, root, pub)
	h.client = newPlaneClient(false)

	if _, err := h.fetch("0.8.370"); err == nil {
		t.Fatal("an answer past the cap must be refused")
	}
}

// A plane with nothing for this version answers plainly, and the healer must
// read that as an ordinary answer rather than a transport fault.
func TestFetchReadsNothingOnOfferAsSuch(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeEnvelope(w, map[string]interface{}{"available": false})
	}))
	defer server.Close()
	installTestIdentity(t, server.URL)

	root := writeSignedTree(t, priv, "<?php // upgrade\n")
	h := healerFor(t, root, pub)
	h.client = newPlaneClient(false)

	if _, err := h.fetch("0.8.370"); !errors.Is(err, errNoManifestOffered) {
		t.Fatalf("expected errNoManifestOffered, got %v", err)
	}
}

// The site root is WEB-WRITABLE on a real node — install.sh chowns the tree to
// www-data (getjoinery: drwxrwx--- www-data). So this root process writes into a
// directory an attacker who has the web layer can create entries in, and the
// only thing standing between that and root is how these files are opened.
//
// The attack this pins: make the manifest unusable so the healer arms, then
// plant a symlink at the temp name a root write is about to use. The first
// version of this code used a FIXED, predictable temp name (path + ".incoming")
// and os.WriteFile/os.Chmod/os.Chown BY PATH, every one of which follows a
// symlink — so the manifest landed in /etc/sudoers.d/x or authorized_keys and
// the target was chowned to www-data along the way.
//
// This is therefore a regression test for that specific defect, and it is worth
// being precise about what it does and does not prove. It proves the predictable
// name is gone: the planted link is untouched, still a link, and its target is
// unchanged. It does NOT prove O_EXCL, because the temp name is now random and a
// test cannot predict it to plant anything there — that protection is carried by
// os.CreateTemp and by the fd-based chmod/chown, and is argued at the call site.
func TestInstallCannotBeAimedAtAnotherFileBySymlink(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	root := writeSignedTree(t, priv, "<?php // upgrade\n")
	body, _ := os.ReadFile(filepath.Join(root, "RELEASE_MANIFEST"))

	// Somewhere outside the site tree, standing in for a root-owned target.
	outside := t.TempDir()
	target := filepath.Join(outside, "authorized_keys")
	if err := os.WriteFile(target, []byte("ORIGINAL\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	h := healerFor(t, root, pub)

	// Every name this code might open, aimed at the target.
	for _, plant := range []string{"RELEASE_MANIFEST.incoming", "RELEASE_MANIFEST.sig.incoming"} {
		_ = os.Remove(filepath.Join(root, plant))
		if err := os.Symlink(target, filepath.Join(root, plant)); err != nil {
			t.Fatal(err)
		}
	}

	if err := h.install(&manifestPair{manifest: body, signature: ed25519.Sign(priv, body)}); err != nil {
		t.Fatalf("install should still succeed on its own files: %v", err)
	}

	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "ORIGINAL\n" {
		t.Fatalf("a symlink redirected a root write: target now holds %q", got)
	}
	if st, err := os.Lstat(target); err == nil && st.Mode().Perm() != 0o600 {
		t.Fatalf("a symlink redirected a root chmod: target mode is now %v", st.Mode().Perm())
	}

	// The planted links must still BE links and still point where they did: a
	// write that replaced one would mean the code opened that name.
	for _, plant := range []string{"RELEASE_MANIFEST.incoming", "RELEASE_MANIFEST.sig.incoming"} {
		st, err := os.Lstat(filepath.Join(root, plant))
		if err != nil {
			t.Fatalf("%s was consumed by the install", plant)
		}
		if st.Mode()&os.ModeSymlink == 0 {
			t.Fatalf("%s was replaced by a real file — the install wrote to that name", plant)
		}
	}
}

// The destination itself replaced by a symlink. rename() replaces the link
// rather than following it, but a manifest that IS a symlink is never a state to
// write into, and refusing says so out loud.
func TestInstallRefusesWhenTheManifestIsASymlink(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	root := writeSignedTree(t, priv, "<?php // upgrade\n")
	body, _ := os.ReadFile(filepath.Join(root, "RELEASE_MANIFEST"))

	outside := t.TempDir()
	target := filepath.Join(outside, "sudoers")
	if err := os.WriteFile(target, []byte("ORIGINAL\n"), 0o440); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "RELEASE_MANIFEST")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}

	if err := h_install(t, root, pub, body, priv); err == nil {
		t.Fatal("installing over a symlinked manifest must be refused")
	}
	got, _ := os.ReadFile(target)
	if string(got) != "ORIGINAL\n" {
		t.Fatalf("the symlink target was written through: %q", got)
	}
}

func h_install(t *testing.T, root string, pub ed25519.PublicKey, body []byte, priv ed25519.PrivateKey) error {
	t.Helper()
	h := healerFor(t, root, pub)
	return h.install(&manifestPair{manifest: body, signature: ed25519.Sign(priv, body)})
}

// The temp file must never be left behind under a name an attacker can predict
// and pre-create, and a failed install must not leave rubbish either.
func TestInstallLeavesNoTempBehind(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	root := writeSignedTree(t, priv, "<?php // upgrade\n")
	body, _ := os.ReadFile(filepath.Join(root, "RELEASE_MANIFEST"))

	h := healerFor(t, root, pub)
	if err := h.install(&manifestPair{manifest: body, signature: ed25519.Sign(priv, body)}); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(root)
	for _, e := range entries {
		if n := e.Name(); n != "RELEASE_MANIFEST" && n != "RELEASE_MANIFEST.sig" && n != "public_html" {
			t.Fatalf("install left %q behind", n)
		}
	}
}

// THE WEB USER OWNS THE SITE ROOT'S PARENT on a real node — install.sh runs
// chown -R www-data:www-data /var/www/, and on getjoinery /var/www/html is
// www-data:www-data 755. So a web-layer compromise can rename the site root
// aside and leave a symlink of the same name pointing anywhere.
//
// Unlike the O_EXCL case, this one CAN be planted deterministically, so this
// test proves the property rather than the absence of an old defect: resolving
// the site root by path would create the temp inside the target directory,
// chown it to the web user, and rename it to a fixed name there —
// /etc/logrotate.d/RELEASE_MANIFEST is read by root daily and takes postrotate
// scripts. O_NOFOLLOW on the directory open refuses instead.
func TestInstallRefusesASymlinkedSiteRoot(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	real := writeSignedTree(t, priv, "<?php // upgrade\n")
	body, _ := os.ReadFile(filepath.Join(real, "RELEASE_MANIFEST"))

	// Where the attacker wants the file to land.
	victimDir := t.TempDir()

	// The site root the healer is configured with is now a symlink into it.
	parent := t.TempDir()
	siteRoot := filepath.Join(parent, "site")
	if err := os.Symlink(victimDir, siteRoot); err != nil {
		t.Fatal(err)
	}

	h := &manifestHealer{
		siteRoot: siteRoot,
		verifier: primitives.NewArtifactManifests(siteRoot, pub),
		pubKey:   pub,
		warned:   map[string]bool{},
	}

	err := h.install(&manifestPair{manifest: body, signature: ed25519.Sign(priv, body)})
	if err == nil {
		t.Fatal("installing through a symlinked site root must be refused")
	}
	for _, name := range []string{"RELEASE_MANIFEST", "RELEASE_MANIFEST.sig"} {
		if _, statErr := os.Lstat(filepath.Join(victimDir, name)); statErr == nil {
			t.Fatalf("a file was dropped into the symlink target: %s", name)
		}
	}
	entries, _ := os.ReadDir(victimDir)
	if len(entries) != 0 {
		t.Fatalf("the symlink target was written into: %v", entries)
	}
}

// The same protection, one level in: a regular site root whose RELEASE_MANIFEST
// has been replaced by a symlink. The write must not go through it, and the
// target must be untouched.
func TestWriteAtRefusesASymlinkedDestination(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	root := writeSignedTree(t, priv, "<?php // upgrade\n")
	body, _ := os.ReadFile(filepath.Join(root, "RELEASE_MANIFEST"))

	victim := filepath.Join(t.TempDir(), "authorized_keys")
	if err := os.WriteFile(victim, []byte("ORIGINAL\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "RELEASE_MANIFEST")
	os.Remove(path)
	if err := os.Symlink(victim, path); err != nil {
		t.Fatal(err)
	}

	h := healerFor(t, root, pub)
	if err := h.install(&manifestPair{manifest: body, signature: ed25519.Sign(priv, body)}); err == nil {
		t.Fatal("writing over a symlinked manifest must be refused")
	}
	got, _ := os.ReadFile(victim)
	if string(got) != "ORIGINAL\n" {
		t.Fatalf("the symlink target was written through: %q", got)
	}
}

// Ownership must come from the directory descriptor, so a file the web user
// planted cannot dictate who ends up owning the replacement.
func TestInstallTakesOwnershipFromTheDirectory(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	root := writeSignedTree(t, priv, "<?php // upgrade\n")
	body, _ := os.ReadFile(filepath.Join(root, "RELEASE_MANIFEST"))

	h := healerFor(t, root, pub)
	if err := h.install(&manifestPair{manifest: body, signature: ed25519.Sign(priv, body)}); err != nil {
		t.Fatal(err)
	}

	var dirSt, fileSt unix.Stat_t
	if err := unix.Stat(root, &dirSt); err != nil {
		t.Fatal(err)
	}
	if err := unix.Stat(filepath.Join(root, "RELEASE_MANIFEST"), &fileSt); err != nil {
		t.Fatal(err)
	}
	if fileSt.Uid != dirSt.Uid || fileSt.Gid != dirSt.Gid {
		t.Fatalf("owner %d:%d does not match the directory's %d:%d",
			fileSt.Uid, fileSt.Gid, dirSt.Uid, dirSt.Gid)
	}
}
