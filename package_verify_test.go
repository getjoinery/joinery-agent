package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// The package fix channel's directory, checked as the support bundle is
// (verify-package, specs/package_fixes_automatic.md WP6).

var channelFiles = map[string]string{
	"ACTIVE":    "php8.5 8.5.4-0ubuntu1.6+joinery2\n",
	"WITHDRAWN": "",
	"CHANNEL":   "1\n",
}

func sumHex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// writeChannel writes files and a manifest listing them, signed by priv.
// statement, when set, is given the manifest's statement subject and returns
// the RELEASE_STATEMENT to list beside the files.
func writeChannel(t *testing.T, priv ed25519.PrivateKey, statement func(subject string) []byte) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "channel")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	var names []string
	for name, body := range channelFiles {
		names = append(names, name)
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	sort.Strings(names)
	body := "# Joinery package fix channel\n"
	for _, name := range names {
		body += sumHex([]byte(channelFiles[name])) + "  " + name + "\n"
	}
	if statement != nil {
		doc := statement(statementSubject([]byte(body)))
		if err := os.WriteFile(filepath.Join(dir, releaseStatementName), doc, 0o644); err != nil {
			t.Fatal(err)
		}
		body += sumHex(doc) + "  " + releaseStatementName + "\n"
	}
	sig := ed25519.Sign(priv, []byte(body))
	os.WriteFile(filepath.Join(dir, primitivesManifestName), []byte(body), 0o644)
	os.WriteFile(filepath.Join(dir, primitivesSignatureName), []byte(base64.StdEncoding.EncodeToString(sig)+"\n"), 0o644)
	return dir
}

func newReleaseKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func wantVerdict(t *testing.T, got packageVerdict, name string) {
	t.Helper()
	if got.name != name {
		t.Fatalf("want verdict %s, got %s", name, got)
	}
	if !strings.HasPrefix(got.String(), "verdict: "+name+": ") || got.why == "" {
		t.Fatalf("the line is not \"verdict: <name>: <why>\": %q", got.String())
	}
}

func TestASignedChannelPasses(t *testing.T) {
	pub, priv := newReleaseKey(t)
	dir := writeChannel(t, priv, nil)
	c := releaseTreeChecks{releaseKeys: releaseKeysOf(pub), keyDir: t.TempDir()}
	wantVerdict(t, c.verifyPackageDir(dir), pkgSigned)
	wantVerdict(t, c.verifyPackageDir(dir+"/"), pkgSigned)
}

func TestAChangedByteFails(t *testing.T) {
	pub, priv := newReleaseKey(t)
	dir := writeChannel(t, priv, nil)
	os.WriteFile(filepath.Join(dir, "ACTIVE"), []byte("php8.5 8.5.4-0ubuntu1.6+joinery3\n"), 0o644)
	c := releaseTreeChecks{releaseKeys: releaseKeysOf(pub)}
	wantVerdict(t, c.verifyPackageDir(dir), pkgTampered)
}

func TestAChangedManifestByteFails(t *testing.T) {
	pub, priv := newReleaseKey(t)
	dir := writeChannel(t, priv, nil)
	body, _ := os.ReadFile(filepath.Join(dir, primitivesManifestName))
	body[2] ^= 1 // in the comment: no file changes, only the signed bytes
	os.WriteFile(filepath.Join(dir, primitivesManifestName), body, 0o644)
	c := releaseTreeChecks{releaseKeys: releaseKeysOf(pub)}
	wantVerdict(t, c.verifyPackageDir(dir), pkgUnknownKey)
}

func TestAnExtraFileFails(t *testing.T) {
	pub, priv := newReleaseKey(t)
	dir := writeChannel(t, priv, nil)
	os.WriteFile(filepath.Join(dir, "ACTIVE.orig"), []byte("x\n"), 0o644)
	c := releaseTreeChecks{releaseKeys: releaseKeysOf(pub)}
	wantVerdict(t, c.verifyPackageDir(dir), pkgExtraFile)
}

func TestASymlinkFails(t *testing.T) {
	pub, priv := newReleaseKey(t)
	dir := writeChannel(t, priv, nil)
	os.Symlink("ACTIVE", filepath.Join(dir, "LINK"))
	c := releaseTreeChecks{releaseKeys: releaseKeysOf(pub)}
	wantVerdict(t, c.verifyPackageDir(dir), pkgExtraFile)
}

func TestAMissingFileFails(t *testing.T) {
	pub, priv := newReleaseKey(t)
	dir := writeChannel(t, priv, nil)
	os.Remove(filepath.Join(dir, "WITHDRAWN"))
	c := releaseTreeChecks{releaseKeys: releaseKeysOf(pub)}
	wantVerdict(t, c.verifyPackageDir(dir), pkgMissingFile)
}

func TestAnUnknownKeyFails(t *testing.T) {
	pub, _ := newReleaseKey(t)
	_, stranger := newReleaseKey(t)
	dir := writeChannel(t, stranger, nil)
	c := releaseTreeChecks{releaseKeys: releaseKeysOf(pub)}
	wantVerdict(t, c.verifyPackageDir(dir), pkgUnknownKey)
}

func TestNoManifestIsUnsignedAndNoKeysIsNoKeys(t *testing.T) {
	pub, priv := newReleaseKey(t)
	dir := writeChannel(t, priv, nil)
	wantVerdict(t, releaseTreeChecks{keyDir: t.TempDir()}.verifyPackageDir(dir), pkgNoKeys)
	os.Remove(filepath.Join(dir, primitivesSignatureName))
	wantVerdict(t, releaseTreeChecks{releaseKeys: releaseKeysOf(pub)}.verifyPackageDir(dir), pkgUnsigned)
	wantVerdict(t, releaseTreeChecks{releaseKeys: releaseKeysOf(pub)}.verifyPackageDir(dir+"/nothing"), pkgUnreadable)
}

// A manifest whose files sit under a directory is a package of another
// shape: PackageSignature would resolve it against a parent this check
// never reads.
func TestARootedManifestIsNotThisCheck(t *testing.T) {
	pub, priv := newReleaseKey(t)
	dir := filepath.Join(t.TempDir(), "channel")
	os.MkdirAll(filepath.Join(dir, "sub"), 0o755)
	os.WriteFile(filepath.Join(dir, "sub", "ACTIVE"), []byte("a\n"), 0o644)
	body := sumHex([]byte("a\n")) + "  sub/ACTIVE\n"
	os.WriteFile(filepath.Join(dir, primitivesManifestName), []byte(body), 0o644)
	os.WriteFile(filepath.Join(dir, primitivesSignatureName), []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(body)))), 0o644)
	wantVerdict(t, releaseTreeChecks{releaseKeys: releaseKeysOf(pub)}.verifyPackageDir(dir), pkgUnreadable)
}

func loggedChecks(t *testing.T, pub ed25519.PublicKey, sk testStatementKey, l testLog) releaseTreeChecks {
	held := keysOf(sk, l)
	return releaseTreeChecks{releaseKeys: releaseKeysOf(pub), keyDir: t.TempDir(), held: func() releaseLogKeys { return held }}
}

func TestALoggedChannelPassesAndNothingIsKept(t *testing.T) {
	pub, priv := newReleaseKey(t)
	sk, l := newTestStatementKey(t), newTestLog(t, "log.channel-test.example")
	dir := writeChannel(t, priv, func(subject string) []byte {
		return bundleStatement(t, sk, l, map[string]string{"package_fix_channel": subject})
	})
	c := loggedChecks(t, pub, sk, l)
	v := c.verifyPackageDir(dir)
	wantVerdict(t, v, pkgSigned)
	if !strings.Contains(v.why, "logged publicly at log.channel-test.example") {
		t.Fatalf("a logged package says where it is logged: %s", v)
	}
	if entries, _ := os.ReadDir(c.keyDir); len(entries) != 0 {
		t.Fatalf("verify-package wrote %d file(s) to the key directory; it must change nothing", len(entries))
	}
}

func TestAStatementThatDoesNotRecordTheSubjectFails(t *testing.T) {
	pub, priv := newReleaseKey(t)
	sk, l := newTestStatementKey(t), newTestLog(t, "log.channel-test.example")
	dir := writeChannel(t, priv, func(subject string) []byte {
		// The sha256 of the whole manifest file is not its subject.
		return bundleStatement(t, sk, l, map[string]string{"package_fix_channel": sumHex([]byte(subject))})
	})
	wantVerdict(t, loggedChecks(t, pub, sk, l).verifyPackageDir(dir), pkgUnlogged)
}

func TestNoStatementFailsWhereLogKeysAreHeld(t *testing.T) {
	pub, priv := newReleaseKey(t)
	sk, l := newTestStatementKey(t), newTestLog(t, "log.channel-test.example")
	dir := writeChannel(t, priv, nil)
	wantVerdict(t, loggedChecks(t, pub, sk, l).verifyPackageDir(dir), pkgUnlogged)
}

func TestAStatementByAnUnheldKeyFails(t *testing.T) {
	pub, priv := newReleaseKey(t)
	sk, l := newTestStatementKey(t), newTestLog(t, "log.channel-test.example")
	other := newTestStatementKey(t)
	dir := writeChannel(t, priv, func(subject string) []byte {
		return bundleStatement(t, other, l, map[string]string{"package_fix_channel": subject})
	})
	wantVerdict(t, loggedChecks(t, pub, sk, l).verifyPackageDir(dir), pkgUnlogged)
}

func TestTheCommandExitsNonZeroUnlessSigned(t *testing.T) {
	if code := cliVerifyPackage([]string{filepath.Join(t.TempDir(), "absent")}); code != 1 {
		t.Fatalf("an absent directory exits 1, got %d", code)
	}
	if code := cliVerifyPackage(nil); code != 1 {
		t.Fatalf("no directory is a usage error, exit 1, got %d", code)
	}
}
