package primitives

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

// A copy from backups (specs/site_copy.md WP10): the chain key, sealed to the
// owner's recovery key in a libsodium sealed box, is opened here from the one
// value the owner's browser works out with WebCrypto (X25519 of the recovery
// key with the box's ephemeral key), and written as copy_import would have
// written it.

type recoveryFixture struct {
	pub, priv *[32]byte
	sealed    []byte
	dataKey   string
}

func newRecoveryFixture(t *testing.T) recoveryFixture {
	t.Helper()
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dataKey := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	sealed, err := box.SealAnonymous(nil, []byte(dataKey), pub, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return recoveryFixture{pub: pub, priv: priv, sealed: sealed, dataKey: dataKey}
}

// browserShare is what the owner's browser computes: X25519(recovery private,
// the box's ephemeral public).
func (r recoveryFixture) browserShare(t *testing.T) []byte {
	t.Helper()
	shared, err := curve25519.X25519(r.priv[:], r.sealed[:32])
	if err != nil {
		t.Fatal(err)
	}
	return shared
}

func (r recoveryFixture) fingerprint() string {
	sum := sha256.Sum256(r.pub[:])
	return hex.EncodeToString(sum[:])
}

func TestTheBrowserShareOpensTheSealedBox(t *testing.T) {
	r := newRecoveryFixture(t)
	opened, err := openRecoverySealed(r.sealed, r.browserShare(t), r.pub[:])
	if err != nil || string(opened) != r.dataKey {
		t.Fatalf("opened %q, %v; want the data key", opened, err)
	}

	other := newRecoveryFixture(t)
	if _, err := openRecoverySealed(r.sealed, other.browserShare(t), r.pub[:]); err == nil {
		t.Error("another box's share opened this one")
	}
	if _, err := openRecoverySealed(r.sealed, r.browserShare(t), other.pub[:]); err == nil {
		t.Error("the share opened with the wrong recipient key in the nonce")
	}
	if _, err := openRecoverySealed(r.sealed, make([]byte, 32), r.pub[:]); err == nil {
		t.Error("an all-zero share was taken")
	}
	tampered := append([]byte{}, r.sealed...)
	tampered[len(tampered)-1] ^= 1
	if _, err := openRecoverySealed(tampered, r.browserShare(t), r.pub[:]); err == nil {
		t.Error("a tampered box opened")
	}
}

// fakeHandoff answers each request with the answers it holds, in turn, until
// one is accepted.
type fakeHandoff struct {
	answers [][2][]byte
	staged  CopyKeyRequest
	jobID   int64
	refused []string
}

func (h *fakeHandoff) Await(ctx context.Context, jobID int64, req CopyKeyRequest, try func(shared, pub []byte) error) error {
	h.staged, h.jobID = req, jobID
	for _, a := range h.answers {
		err := try(a[0], a[1])
		if err == nil {
			return nil
		}
		h.refused = append(h.refused, err.Error())
	}
	return &RefusalError{Reason: "no one answered"}
}

func takeKeyParams(t *testing.T, r recoveryFixture) Params {
	return validParams(t, "copy_take_key", map[string]interface{}{
		"chain_id":             exportChainID,
		"manifest_sha256":      strings.Repeat("ab", 32),
		"run_time":             "2026-10-01T03:00:00Z",
		"recovery_fingerprint": r.fingerprint(),
		"recovery_sealed":      base64.StdEncoding.EncodeToString(r.sealed),
		"site":                 "copytest.example.com",
	})
}

func TestCopyTakeKeyWritesWhatCopyImportWould(t *testing.T) {
	f := newExportFixture(t)
	r := newRecoveryFixture(t)
	wrong := newRecoveryFixture(t)
	h := &fakeHandoff{answers: [][2][]byte{
		{wrong.browserShare(t), wrong.pub[:]}, // a different recovery key
		{r.browserShare(t), r.pub[:]},
	}}
	f.tEnv.CopyKeyHandoff = h
	ctx := WithJobID(context.Background(), 9001)

	out, err := copyTakeKeyRun(ctx, f.tEnv, takeKeyParams(t, r))
	if err != nil {
		t.Fatalf("copy_take_key: %v", err)
	}
	if h.jobID != 9001 || h.staged.ChainID != exportChainID || h.staged.EphemeralPublic != base64.StdEncoding.EncodeToString(r.sealed[:32]) {
		t.Errorf("staged %+v for job %d", h.staged, h.jobID)
	}
	if len(h.refused) != 1 || !strings.Contains(h.refused[0], "fingerprint") {
		t.Errorf("the wrong key was refused as %v; want its fingerprint named", h.refused)
	}
	if out["chain_id"] != exportChainID {
		t.Errorf("result %v", out)
	}
	key, err := os.ReadFile(filepath.Join(chainWorkspace(ctx, f.tEnv, exportChainID), chainKeyFile))
	if err != nil || string(key) != r.dataKey {
		t.Errorf("chain.key holds %q, %v", key, err)
	}
	vouched, err := vouchedManifests(f.tEnv, exportChainID)
	if err != nil || len(vouched) != 1 || vouched[0] != strings.Repeat("ab", 32) {
		t.Errorf("vouched %v, %v; want the stated manifest for the chain", vouched, err)
	}
}

func TestCopyTakeKeyRefusals(t *testing.T) {
	f := newExportFixture(t)
	r := newRecoveryFixture(t)
	ctx := WithJobID(context.Background(), 1)

	if _, err := copyTakeKeyRun(ctx, f.tEnv, takeKeyParams(t, r)); err == nil || !strings.Contains(err.Error(), "cannot ask") {
		t.Errorf("no handoff: %v", err)
	}
	f.tEnv.CopyKeyHandoff = &fakeHandoff{}
	if _, err := copyTakeKeyRun(ctx, f.tEnv, takeKeyParams(t, r)); err == nil {
		t.Error("taken with no answer")
	}
	// A live site never takes a chain key.
	if err := os.Remove(filepath.Join(SiteStateDir, "copysite", "state")); err != nil {
		t.Fatal(err)
	}
	f.tEnv.CopyKeyHandoff = &fakeHandoff{answers: [][2][]byte{{r.browserShare(t), r.pub[:]}}}
	_, err := copyTakeKeyRun(ctx, f.tEnv, takeKeyParams(t, r))
	var refusal *RefusalError
	if !errors.As(err, &refusal) || !strings.Contains(err.Error(), "dormant copy") {
		t.Errorf("a live site: %v", err)
	}
}

func TestCopyLookReportsThePath(t *testing.T) {
	f := newExportFixture(t)
	if _, err := copyLookRun(context.Background(), f.tEnv, Params{}); err == nil {
		t.Error("a copy with no look secret reported a path")
	}
	mustWrite(t, filepath.Join(SiteStateDir, "copysite", copyLookSecretFile), strings.Repeat("a1", 16)+"\n", 0o600)
	out, err := copyLookRun(context.Background(), f.tEnv, Params{})
	if err != nil || out["look_path"] != "/.joinery-look/"+strings.Repeat("a1", 16) {
		t.Errorf("look %v, %v", out, err)
	}
}

// A box sealed by PHP's libsodium (sodium_crypto_box_seal), as every backup
// envelope is, opened from the X25519 share PHP's sodium_crypto_scalarmult
// computes (the browser's WebCrypto deriveBits gives the same bytes). Pins
// the construction to the one the backups actually use, not only to Go's.
func TestALibsodiumSealedBoxOpens(t *testing.T) {
	dec := func(s string) []byte {
		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	opened, err := openRecoverySealed(
		dec("rlvXlqNslUhw5d1VXk7ZiN/7PkHKVnpzBhTT2kmUbXUbf0lVJT39f5A6u5A0Qr6OrzBXbNfXm3l3yQsKIU3v9v5mua7HyiOSm1rNTqvYtUUOz1Tbz+XOtHmYRQQ="),
		dec("/NjKx5dkDq+czEO4GKnrOkBM5+32eMxtyHxVon2hQiM="),
		dec("1AE/yfyjLvav97MztrVb9Y6azrE/t2bb0TidVIXgiUU="))
	if err != nil || string(opened) != "5S1zsUQmyOfNSxo847p9+4EgHCGocYnGr5WepneRz9A=" {
		t.Fatalf("opened %q, %v", opened, err)
	}
}
