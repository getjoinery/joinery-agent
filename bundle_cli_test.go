package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// joinery-agent bundle install FILE: a bundle from a file on this machine (the
// release's own, for a Docker host with no management node) is held to what a
// bundle from a management node is held to, and lands where that one does.

func fileBundleSync(t *testing.T, pub ed25519.PublicKey) *BundleSync {
	t.Setenv("AGENT_TOOL_ROOT", filepath.Join(t.TempDir(), "tree"))
	return &BundleSync{pubKey: pub, siteless: true, keyDir: t.TempDir(), warned: map[string]bool{}}
}

func writeBundleFile(t *testing.T, raw []byte) string {
	p := filepath.Join(t.TempDir(), "support_bundle.tar.gz")
	if err := os.WriteFile(p, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestABundleFromAFileIsInstalledAndStampedWithItsBytes(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	raw := signedBundle(t, priv, map[string]string{"maintenance_scripts/install_tools/install_host_converger.sh": "#!/bin/bash\n"}, nil)
	b := fileBundleSync(t, pub)
	if code := installBundleFile(b, writeBundleFile(t, raw), ""); code != 0 {
		t.Fatalf("a correctly signed bundle from a file was refused (exit %d)", code)
	}
	if _, err := os.Stat(filepath.Join(BundleRoot(), "maintenance_scripts/install_tools/install_host_converger.sh")); err != nil {
		t.Fatalf("the tree is not in place: %v", err)
	}
	stamp := readBundleStamp()
	if stamp == nil || stamp.SourceSha256 != bundleSum(raw) {
		got, _ := json.Marshal(stamp)
		t.Fatalf("the stamp must record the file's bytes, so a management node offering the same ones is not fetched again: %s", got)
	}
}

func TestATamperedBundleFromAFileIsRefusedAndNothingIsInstalled(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	raw := signedBundle(t, priv, map[string]string{"a.sh": "original"},
		func(shipped map[string]string, manifest *string) { shipped["a.sh"] = "tampered" })
	b := fileBundleSync(t, pub)
	if code := installBundleFile(b, writeBundleFile(t, raw), ""); code == 0 {
		t.Fatal("a file that does not match its signed hash must be refused, whatever the bundle's source")
	}
	if _, err := os.Stat(BundleRoot()); !os.IsNotExist(err) {
		t.Fatalf("a refused bundle must leave no tree behind: %v", err)
	}
}

func TestABundleSignedByAnotherKeyFromAFileIsRefused(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	raw := signedBundle(t, other, map[string]string{"a.sh": "x"}, nil)
	if code := installBundleFile(fileBundleSync(t, pub), writeBundleFile(t, raw), ""); code == 0 {
		t.Fatal("a bundle not signed with this binary's release key must be refused")
	}
}

func TestWhereTheLogIsHeldAFileBundleNeedsItsStatement(t *testing.T) {
	sk, l := newTestStatementKey(t), newTestLog(t, "log.bundle-file-test.example")
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	raw := signedBundle(t, priv, map[string]string{"a.sh": "x"}, nil)
	b := fileBundleSync(t, pub)
	b.bakedLogKeys = keysOf(sk, l)
	file := writeBundleFile(t, raw)
	if code := installBundleFile(b, file, ""); code == 0 {
		t.Fatal("a machine held to the public log must refuse a file bundle given no statement")
	}

	doc := bundleStatement(t, sk, l, map[string]string{"support_bundle": bundleSum(raw), "agent/linux-amd64": bundleSum([]byte("agent"))})
	stmt := filepath.Join(t.TempDir(), "RELEASE_STATEMENT")
	if err := os.WriteFile(stmt, doc, 0o644); err != nil {
		t.Fatal(err)
	}
	if code := installBundleFile(b, file, stmt); code != 0 {
		t.Fatal("a file bundle its release statement records must be installed")
	}

	wrong := bundleStatement(t, sk, l, map[string]string{"support_bundle": strings.Repeat("0", 64)})
	if err := os.WriteFile(stmt, wrong, 0o644); err != nil {
		t.Fatal(err)
	}
	b2 := fileBundleSync(t, pub)
	b2.bakedLogKeys = keysOf(sk, l)
	if code := installBundleFile(b2, file, stmt); code == 0 {
		t.Fatal("a file bundle whose statement records other bytes must be refused")
	}
}

func TestBundleInstallArguments(t *testing.T) {
	for _, args := range [][]string{nil, {"install"}, {"remove", "x"}, {"install", "x", "--other"}} {
		if code := cliBundle(args); code == 0 {
			t.Errorf("bundle %v must be refused", args)
		}
	}
}

func TestALiveJobMarkerHoldsTheBundleInstall(t *testing.T) {
	saved := jobMarkerPath
	t.Cleanup(func() { jobMarkerPath = saved })
	jobMarkerPath = filepath.Join(t.TempDir(), "job-running")
	if pid := liveJobMarkerPid(); pid != 0 {
		t.Fatalf("no marker must read as no job, got pid %d", pid)
	}

	// A joinery-agent process: a copy of sleep under that name.
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("no sleep binary")
	}
	agent := filepath.Join(t.TempDir(), "joinery-agent")
	raw, _ := os.ReadFile(sleep)
	if err := os.WriteFile(agent, raw, 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(agent, "30")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	os.WriteFile(jobMarkerPath, []byte(fmt.Sprintf("%d\n4711\nnow\n", cmd.Process.Pid)), 0o644)
	if pid := liveJobMarkerPid(); pid != cmd.Process.Pid {
		t.Fatalf("a marker naming a running joinery-agent must hold the install, got pid %d", pid)
	}

	// The same pid read by another program: the test binary itself.
	os.WriteFile(jobMarkerPath, []byte(fmt.Sprintf("%d\n4711\nnow\n", os.Getpid())), 0o644)
	if pid := liveJobMarkerPid(); pid != 0 {
		t.Fatalf("a marker whose pid another program now has must not hold it, got pid %d", pid)
	}
	os.WriteFile(jobMarkerPath, []byte("999999999\n4711\nnow\n"), 0o644)
	if pid := liveJobMarkerPid(); pid != 0 {
		t.Fatalf("a marker a killed process left must not hold it, got pid %d", pid)
	}
}

func TestTheSameBundleIsNotSwappedAgain(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	raw := signedBundle(t, priv, map[string]string{"a.sh": "x"}, nil)
	b := fileBundleSync(t, pub)
	file := writeBundleFile(t, raw)
	if code := installBundleFile(b, file, ""); code != 0 {
		t.Fatal("first install refused")
	}
	// A file the manifest does not list: a swap would remove it with the tree.
	witness := filepath.Join(BundleRoot(), "witness")
	if err := os.WriteFile(witness, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if code := installBundleFile(b, file, ""); code != 0 {
		t.Fatal("installing the bytes already in place must succeed")
	}
	if _, err := os.Stat(witness); err != nil {
		t.Fatal("the same bytes already in place were swapped again")
	}
}

func TestAHeldInstallLockIsARetryAndInstallsNothing(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	raw := signedBundle(t, priv, map[string]string{"a.sh": "x"}, nil)
	b := fileBundleSync(t, pub)
	if err := os.MkdirAll(filepath.Dir(BundleRoot()), 0o755); err != nil {
		t.Fatal(err)
	}
	unlock, err := lockBundleInstall(BundleRoot() + ".lock")
	if err != nil {
		t.Fatal(err)
	}
	_, err = b.installFrom(bytes.NewReader(raw), "", func() ([]byte, error) { return nil, nil })
	if !errors.Is(err, errBundleRetry) {
		t.Fatalf("a held install lock must be a retry, never a verdict on the bytes (the daemon would stop retrying them): %v", err)
	}
	if code := installBundleFile(b, writeBundleFile(t, raw), ""); code == 0 {
		t.Fatal("an install while another holds the lock must fail")
	}
	if _, err := os.Stat(BundleRoot()); !os.IsNotExist(err) {
		t.Fatalf("nothing may be installed while another install holds the lock: %v", err)
	}
	unlock()
	if code := installBundleFile(b, writeBundleFile(t, raw), ""); code != 0 {
		t.Fatal("once the lock is free the install must go through")
	}
}
