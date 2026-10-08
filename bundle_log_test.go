package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The support bundle is held to the public log the way the binary is
// (release_transparency, WP7 review B1): a machine holding the log keys
// installs only a bundle its release statement records.

func bundleStatement(t *testing.T, sk testStatementKey, l testLog, artifacts map[string]string) []byte {
	t.Helper()
	env, entry := loggedEnv(t, sk, l, payloadFor(t, artifacts, keysOf(sk, l)))
	return statementDoc(t, env, entry)
}

func bundleSum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func requiredBundleSync(t *testing.T, sk testStatementKey, l testLog) *BundleSync {
	return &BundleSync{bakedLogKeys: keysOf(sk, l), keyDir: t.TempDir(), warned: map[string]bool{}}
}

func TestALoggedBundleIsAcceptedAndItsKeysAreKept(t *testing.T) {
	sk, l := newTestStatementKey(t), newTestLog(t, "log.bundle-test.example")
	b := requiredBundleSync(t, sk, l)
	sum := bundleSum([]byte("bundle bytes"))
	doc := bundleStatement(t, sk, l, map[string]string{"support_bundle": sum, "agent/linux-amd64": bundleSum([]byte("agent"))})
	if err := b.checkLogged(sum, "v1", func() ([]byte, error) { return doc, nil }); err != nil {
		t.Fatalf("a bundle its logged statement records was refused: %v", err)
	}
	entries, _ := os.ReadDir(b.keyDir)
	if len(entries) == 0 {
		t.Fatalf("the keys the statement proved were not kept in %s", b.keyDir)
	}
}

func TestABundleWithNoStatementIsRefused(t *testing.T) {
	sk, l := newTestStatementKey(t), newTestLog(t, "log.bundle-test.example")
	b := requiredBundleSync(t, sk, l)
	err := b.checkLogged(bundleSum([]byte("bundle bytes")), "v1", func() ([]byte, error) { return nil, nil })
	if !errors.Is(err, errBundleUnlogged) || errors.Is(err, errBundleRetry) || !strings.Contains(err.Error(), "unlogged") {
		t.Fatalf("a stripped statement must be refused as unlogged, not retried; got %v", err)
	}
}

func TestABundleItsStatementDoesNotRecordIsRefused(t *testing.T) {
	sk, l := newTestStatementKey(t), newTestLog(t, "log.bundle-test.example")
	b := requiredBundleSync(t, sk, l)
	other := bundleStatement(t, sk, l, map[string]string{"support_bundle": bundleSum([]byte("other bytes"))})
	if err := b.checkLogged(bundleSum([]byte("bundle bytes")), "v1", func() ([]byte, error) { return other, nil }); err == nil || errors.Is(err, errBundleRetry) {
		t.Fatalf("a statement recording other bytes must refuse the bundle; got %v", err)
	}
	agentOnly := bundleStatement(t, sk, l, map[string]string{"agent/linux-amd64": bundleSum([]byte("bundle bytes"))})
	if err := b.checkLogged(bundleSum([]byte("bundle bytes")), "v1", func() ([]byte, error) { return agentOnly, nil }); err == nil {
		t.Fatalf("the same bytes recorded under another artifact name must not pass for the bundle")
	}
}

func TestAStatementThatCannotBeFetchedIsRetriedNotRefused(t *testing.T) {
	sk, l := newTestStatementKey(t), newTestLog(t, "log.bundle-test.example")
	b := requiredBundleSync(t, sk, l)
	err := b.checkLogged(bundleSum([]byte("bundle bytes")), "v1", func() ([]byte, error) { return nil, errors.New("connection reset") })
	if !errors.Is(err, errBundleRetry) {
		t.Fatalf("a transport failure must be retried, not held against the bytes; got %v", err)
	}
}

func TestAKeyDirThatCannotBeWrittenIsRetriedNotInstalled(t *testing.T) {
	sk, l := newTestStatementKey(t), newTestLog(t, "log.bundle-test.example")
	b := requiredBundleSync(t, sk, l)
	b.keyDir = filepath.Join(t.TempDir(), "file-not-dir")
	if err := os.WriteFile(b.keyDir, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	sum := bundleSum([]byte("bundle bytes"))
	doc := bundleStatement(t, sk, l, map[string]string{"support_bundle": sum})
	if err := b.checkLogged(sum, "v1", func() ([]byte, error) { return doc, nil }); !errors.Is(err, errBundleRetry) {
		t.Fatalf("keys that cannot be kept must stop the swap and retry; got %v", err)
	}
}

func TestAMachineWithNoLogKeysInstallsOnTheSignatureAndNeverAsks(t *testing.T) {
	b := &BundleSync{bakedLogKeys: releaseLogKeys{}, keyDir: t.TempDir(), warned: map[string]bool{}}
	if err := b.checkLogged(bundleSum([]byte("bundle bytes")), "v1", func() ([]byte, error) {
		t.Fatalf("a machine holding no keys must not ask for a statement")
		return nil, nil
	}); err != nil {
		t.Fatalf("a machine holding no keys must not refuse: %v", err)
	}
}

func TestTheBundleReportIsSilentUntilACheckConcludes(t *testing.T) {
	b := &BundleSync{warned: map[string]bool{}}
	if _, ok := b.Report(); ok {
		t.Fatalf("a bundle sync that has not concluded must not report")
	}
	b.setState(bundleStateVerifyFailed)
	if state, ok := b.Report(); !ok || state != bundleStateVerifyFailed {
		t.Fatalf("got %q %v, want verify_failed", state, ok)
	}
	var none *BundleSync
	if _, ok := none.Report(); ok {
		t.Fatalf("a machine with a site has no bundle sync and reports nothing")
	}
}

// Publish writes the bundle before the statement that records it (review B1a):
// an agent asking in between refuses the new bytes beside the last release's
// statement, and installs them once the new statement is served, without the
// plane having to offer different bytes.
func TestABundleSeenBeforeItsStatementIsRetriedWhenTheStatementArrives(t *testing.T) {
	sk, l := newTestStatementKey(t), newTestLog(t, "log.bundle-test.example")
	b := requiredBundleSync(t, sk, l)
	sum := bundleSum([]byte("new bundle bytes"))
	previous := bundleStatement(t, sk, l, map[string]string{"support_bundle": bundleSum([]byte("old bundle bytes"))})
	current := bundleStatement(t, sk, l, map[string]string{"support_bundle": sum})

	if err := b.checkLogged(sum, "v2", func() ([]byte, error) { return previous, nil }); !errors.Is(err, errBundleUnlogged) {
		t.Fatalf("the new bundle beside the last release's statement must be refused as unlogged; got %v", err)
	}
	b.unloggedSha, b.unloggedStmtSum = sum, b.lastStatementSum // as CheckAndApply records the refusal

	if !b.unloggedHolds(sum, func() ([]byte, error) { return previous, nil }) {
		t.Fatalf("while the statement is unchanged, the refusal must hold")
	}
	if !b.unloggedHolds(sum, func() ([]byte, error) { return nil, errors.New("timeout") }) {
		t.Fatalf("a statement that cannot be fetched must hold the refusal, not retry blind")
	}
	if b.unloggedHolds(sum, func() ([]byte, error) { return current, nil }) {
		t.Fatalf("a new statement must let the same bytes be tried again")
	}
	if err := b.checkLogged(sum, "v2", func() ([]byte, error) { return current, nil }); err != nil {
		t.Fatalf("with the statement that records it, the same bundle must install: %v", err)
	}
	if b.unloggedHolds(bundleSum([]byte("other bytes")), func() ([]byte, error) { return previous, nil }) {
		t.Fatalf("a refusal of one bundle must not hold another")
	}
}
