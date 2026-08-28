package main

import (
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// testUpdaterEnv builds an Updater pointed at temp dirs with a fake
// "installed" binary and a real Ed25519 keypair.
type testUpdaterEnv struct {
	u       *Updater
	distDir string
	install string
	pub     ed25519.PublicKey
	priv    ed25519.PrivateKey
}

func newTestUpdaterEnv(t *testing.T, runningVersion string) *testUpdaterEnv {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	distDir := t.TempDir()
	installDir := t.TempDir()
	install := filepath.Join(installDir, "joinery-agent")
	if err := os.WriteFile(install, []byte("OLD-BINARY"), 0755); err != nil {
		t.Fatalf("seed installed binary: %v", err)
	}
	u := &Updater{
		source:      localDirSource{dir: distDir},
		distDir:     distDir,
		installPath: install,
		platform:    "linux-amd64",
		pubKey:      pub,
		running:     runningVersion,
		warned:      map[string]bool{},
		// convergeService nil: no systemd in tests
	}
	return &testUpdaterEnv{u: u, distDir: distDir, install: install, pub: pub, priv: priv}
}

// writeDist writes a gzipped binary and manifest. mangle lets a test corrupt
// the checksum or signature.
func (e *testUpdaterEnv) writeDist(t *testing.T, version string, binary []byte, mangle func(*distBinary)) {
	t.Helper()
	var gzBuf bytes.Buffer
	gz := gzip.NewWriter(&gzBuf)
	if _, err := gz.Write(binary); err != nil {
		t.Fatalf("gzip: %v", err)
	}
	gz.Close()

	sum := sha256.Sum256(binary)
	entry := distBinary{
		File:      "joinery-agent-linux-amd64.gz",
		Sha256:    hex.EncodeToString(sum[:]),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(e.priv, binary)),
	}
	if mangle != nil {
		mangle(&entry)
	}
	if err := os.WriteFile(filepath.Join(e.distDir, entry.File), gzBuf.Bytes(), 0644); err != nil {
		t.Fatalf("write artifact: %v", err)
	}
	m := distManifest{Version: version, Binaries: map[string]distBinary{"linux-amd64": entry}}
	raw, _ := json.Marshal(m)
	if err := os.WriteFile(filepath.Join(e.distDir, "manifest.json"), raw, 0644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
}

func (e *testUpdaterEnv) installedContent(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(e.install)
	if err != nil {
		t.Fatalf("read installed binary: %v", err)
	}
	return string(data)
}

func TestNoManifestIsQuietNoOp(t *testing.T) {
	e := newTestUpdaterEnv(t, "0.3.0")
	if e.u.CheckAndApply() {
		t.Fatal("updated with no manifest present")
	}
	if _, state := e.u.HeartbeatInfo(); state != "" {
		t.Fatalf("state = %q, want empty", state)
	}
}

func TestCurrentVersionIsNoOp(t *testing.T) {
	e := newTestUpdaterEnv(t, "0.3.0")
	e.writeDist(t, "0.3.0", []byte("NEW-BINARY"), nil)
	if e.u.CheckAndApply() {
		t.Fatal("updated when already current")
	}
	bundled, state := e.u.HeartbeatInfo()
	if bundled != "0.3.0" || state != updateStateCurrent {
		t.Fatalf("got (%q,%q), want (0.3.0,current)", bundled, state)
	}
	if e.installedContent(t) != "OLD-BINARY" {
		t.Fatal("binary changed on a no-op")
	}
}

func TestGoodUpdateSwapsAndKeepsBackup(t *testing.T) {
	e := newTestUpdaterEnv(t, "0.3.0")
	e.writeDist(t, "0.3.1", []byte("NEW-BINARY"), nil)
	if !e.u.CheckAndApply() {
		t.Fatal("valid update was not applied")
	}
	if got := e.installedContent(t); got != "NEW-BINARY" {
		t.Fatalf("installed content = %q, want NEW-BINARY", got)
	}
	bak, err := os.ReadFile(e.install + ".bak")
	if err != nil || string(bak) != "OLD-BINARY" {
		t.Fatalf("backup missing or wrong: %v %q", err, bak)
	}
	if _, state := e.u.HeartbeatInfo(); state != updateStatePending {
		t.Fatalf("state = %q, want update_pending", state)
	}
	info, err := os.Stat(e.install)
	if err != nil || info.Mode().Perm() != 0755 {
		t.Fatalf("installed binary mode = %v, want 0755", info.Mode().Perm())
	}
}

func TestBadChecksumRefusedWithBackoff(t *testing.T) {
	e := newTestUpdaterEnv(t, "0.3.0")
	e.writeDist(t, "0.3.1", []byte("NEW-BINARY"), func(b *distBinary) {
		sum := sha256.Sum256([]byte("something else"))
		b.Sha256 = hex.EncodeToString(sum[:])
	})
	if e.u.CheckAndApply() {
		t.Fatal("installed a binary with a bad checksum")
	}
	if e.installedContent(t) != "OLD-BINARY" {
		t.Fatal("binary changed after refused update")
	}
	if _, state := e.u.HeartbeatInfo(); state != updateStateVerifyFailed {
		t.Fatalf("state = %q, want verify_failed", state)
	}
	// Same manifest again: backoff path, still refused.
	if e.u.CheckAndApply() {
		t.Fatal("backoff did not hold")
	}
	// A fixed manifest is picked up.
	e.writeDist(t, "0.3.1", []byte("NEW-BINARY"), nil)
	if !e.u.CheckAndApply() {
		t.Fatal("fixed manifest was not applied")
	}
}

func TestBadSignatureRefused(t *testing.T) {
	e := newTestUpdaterEnv(t, "0.3.0")
	_, wrongPriv, _ := ed25519.GenerateKey(rand.Reader)
	e.writeDist(t, "0.3.1", []byte("NEW-BINARY"), func(b *distBinary) {
		b.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(wrongPriv, []byte("NEW-BINARY")))
	})
	if e.u.CheckAndApply() {
		t.Fatal("installed a binary signed by the wrong key")
	}
	if e.installedContent(t) != "OLD-BINARY" {
		t.Fatal("binary changed after refused update")
	}
	if _, state := e.u.HeartbeatInfo(); state != updateStateVerifyFailed {
		t.Fatalf("state = %q, want verify_failed", state)
	}
}

func TestNoKeyNeverUpdates(t *testing.T) {
	e := newTestUpdaterEnv(t, "0.3.0")
	e.u.pubKey = nil
	e.writeDist(t, "0.3.1", []byte("NEW-BINARY"), nil)
	if e.u.CheckAndApply() {
		t.Fatal("keyless build applied an update")
	}
	if _, state := e.u.HeartbeatInfo(); state != updateStateUnsignedBuild {
		t.Fatalf("state = %q, want unsigned_build", state)
	}
}

func TestMissingArchEntry(t *testing.T) {
	e := newTestUpdaterEnv(t, "0.3.0")
	e.u.platform = "linux-arm64"
	e.writeDist(t, "0.3.1", []byte("NEW-BINARY"), nil) // writes linux-amd64 only
	if e.u.CheckAndApply() {
		t.Fatal("updated with no artifact for this arch")
	}
	if _, state := e.u.HeartbeatInfo(); state != updateStateNoBinary {
		t.Fatalf("state = %q, want no_binary", state)
	}
}

func TestRejectedVersionIsSkippedUntilNewRelease(t *testing.T) {
	e := newTestUpdaterEnv(t, "0.3.0")
	if err := os.WriteFile(e.install+".rejected", []byte("0.3.1\n"), 0644); err != nil {
		t.Fatal(err)
	}
	e.writeDist(t, "0.3.1", []byte("NEW-BINARY"), nil)
	if e.u.CheckAndApply() {
		t.Fatal("reinstalled a version that previously failed to boot")
	}
	if _, state := e.u.HeartbeatInfo(); state != updateStateRejected {
		t.Fatalf("state = %q, want version_rejected", state)
	}
	// A newer release supersedes the rejection.
	e.writeDist(t, "0.3.2", []byte("NEWER-BINARY"), nil)
	if !e.u.CheckAndApply() {
		t.Fatal("newer release was not applied over a stale rejection")
	}
	if e.installedContent(t) != "NEWER-BINARY" {
		t.Fatal("wrong binary installed")
	}
	if _, err := os.Stat(e.install + ".rejected"); !os.IsNotExist(err) {
		t.Fatal("stale rejection marker not cleared")
	}
}

func TestBootFallbackRestoresBackup(t *testing.T) {
	e := newTestUpdaterEnv(t, "0.3.1") // pretend we are the new, broken binary
	if err := os.WriteFile(e.install+".bak", []byte("OLD-BINARY"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(e.install, []byte("BROKEN-BINARY"), 0755); err != nil {
		t.Fatal(err)
	}
	if !e.u.RestoreBackupBinary() {
		t.Fatal("fallback did not restore")
	}
	if e.installedContent(t) != "OLD-BINARY" {
		t.Fatal("previous binary not restored")
	}
	rejected, err := os.ReadFile(e.install + ".rejected")
	if err != nil || string(bytes.TrimSpace(rejected)) != "0.3.1" {
		t.Fatalf("rejection marker wrong: %v %q", err, rejected)
	}
	// No backup → no restore.
	if e.u.RestoreBackupBinary() {
		t.Fatal("restored with no backup present")
	}
}

func TestConfirmHealthyCleansUp(t *testing.T) {
	e := newTestUpdaterEnv(t, "0.3.1")
	os.WriteFile(e.install+".bak", []byte("OLD-BINARY"), 0755)
	os.WriteFile(e.install+".rejected", []byte("0.3.1\n"), 0644)
	e.u.ConfirmHealthy()
	if _, err := os.Stat(e.install + ".bak"); !os.IsNotExist(err) {
		t.Fatal("backup not removed after healthy boot")
	}
	if _, err := os.Stat(e.install + ".rejected"); !os.IsNotExist(err) {
		t.Fatal("own-version rejection marker not removed after healthy boot")
	}
}
