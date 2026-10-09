package primitives

import (
	"context"
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
	"strings"
	"testing"
	"time"

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

// storedChain is a chain's manifest at a storage server of the test's own:
// served with the Last-Modified the test sets, believed as a provider's only
// when the test says the host is one.
type storedChain struct {
	body     []byte
	modified time.Time
	status   int
	redirect string
	srv      *httptest.Server
}

func manifestBody(t *testing.T, chainID, runTime string, r recoveryFixture) []byte {
	t.Helper()
	body, err := json.Marshal(map[string]interface{}{
		"version":  3,
		"chain_id": chainID,
		"envelope": map[string]interface{}{"recipients": []map[string]string{
			{"kind": "recovery", "fingerprint": r.fingerprint(), "sealed": base64.StdEncoding.EncodeToString(r.sealed)},
			{"kind": "site", "fingerprint": strings.Repeat("cd", 32), "sealed": "c2l0ZQ=="},
		}},
		"runs": []map[string]interface{}{{"seq": 0, "time": "2026-09-30T03:00:00Z"}, {"seq": 1, "time": runTime}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// newStoredChain serves r's chain, stored a day after its newest run, and
// makes this test's server a provider's storage host.
func newStoredChain(t *testing.T, r recoveryFixture) *storedChain {
	t.Helper()
	c := &storedChain{body: manifestBody(t, exportChainID, "2026-10-01T03:00:00Z", r),
		modified: time.Date(2026, 10, 1, 3, 20, 0, 0, time.UTC), status: http.StatusOK}
	c.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if c.redirect != "" {
			http.Redirect(w, req, c.redirect, http.StatusFound)
			return
		}
		w.Header().Set("Last-Modified", c.modified.Format(http.TimeFormat))
		w.WriteHeader(c.status)
		_, _ = w.Write(c.body)
	}))
	t.Cleanup(c.srv.Close)
	client, provider := storedManifestClient, storageProviderOf
	storedManifestClient = c.srv.Client()
	storedManifestClient.CheckRedirect = client.CheckRedirect
	storageProviderOf = func(host string) string {
		if host == "127.0.0.1" {
			return "Test Storage"
		}
		return provider(host)
	}
	t.Cleanup(func() { storedManifestClient, storageProviderOf = client, provider })
	return c
}

func (c *storedChain) sha() string {
	sum := sha256.Sum256(c.body)
	return hex.EncodeToString(sum[:])
}

func takeKeyParams(t *testing.T, r recoveryFixture, c *storedChain) Params {
	return validParams(t, "copy_take_key", map[string]interface{}{
		"chain_id":             exportChainID,
		"manifest_sha256":      c.sha(),
		"run_time":             "2026-10-01T03:00:00Z",
		"recovery_fingerprint": r.fingerprint(),
		"recovery_sealed":      base64.StdEncoding.EncodeToString(r.sealed),
		"site":                 "copytest.example.com",
		"manifest_url":         c.srv.URL + "/bucket/copysite/manager/" + exportChainID + "/manifest-0001.json?X-Amz-Signature=abc",
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
	c := newStoredChain(t, r)

	out, err := copyTakeKeyRun(ctx, f.tEnv, takeKeyParams(t, r, c))
	if err != nil {
		t.Fatalf("copy_take_key: %v", err)
	}
	if h.jobID != 9001 || h.staged.ChainID != exportChainID || h.staged.EphemeralPublic != base64.StdEncoding.EncodeToString(r.sealed[:32]) {
		t.Errorf("staged %+v for job %d", h.staged, h.jobID)
	}
	if len(h.refused) != 1 || !strings.Contains(h.refused[0], "fingerprint") {
		t.Errorf("the wrong key was refused as %v; want its fingerprint named", h.refused)
	}
	if h.staged.RunTime != "2026-10-01T03:00:00Z" || h.staged.StoredTime != "2026-10-01T03:20:00Z" || h.staged.StoredAt != "Test Storage" {
		t.Errorf("staged run %q stored %q at %q; want the manifest's newest run and the provider's date",
			h.staged.RunTime, h.staged.StoredTime, h.staged.StoredAt)
	}
	if out["chain_id"] != exportChainID || out["stored_time"] != "2026-10-01T03:20:00Z" {
		t.Errorf("result %v", out)
	}
	key, err := os.ReadFile(filepath.Join(chainWorkspace(ctx, f.tEnv, exportChainID), chainKeyFile))
	if err != nil || string(key) != r.dataKey {
		t.Errorf("chain.key holds %q, %v", key, err)
	}
	vouched, err := vouchedManifests(f.tEnv, exportChainID)
	if err != nil || len(vouched) != 1 || vouched[0] != c.sha() {
		t.Errorf("vouched %v, %v; want the stated manifest for the chain", vouched, err)
	}
}

func TestCopyTakeKeyRefusals(t *testing.T) {
	f := newExportFixture(t)
	r := newRecoveryFixture(t)
	ctx := WithJobID(context.Background(), 1)
	c := newStoredChain(t, r)

	if _, err := copyTakeKeyRun(ctx, f.tEnv, takeKeyParams(t, r, c)); err == nil || !strings.Contains(err.Error(), "cannot ask") {
		t.Errorf("no handoff: %v", err)
	}
	f.tEnv.CopyKeyHandoff = &fakeHandoff{}
	if _, err := copyTakeKeyRun(ctx, f.tEnv, takeKeyParams(t, r, c)); err == nil {
		t.Error("taken with no answer")
	}
	// A live site never takes a chain key.
	if err := os.Remove(filepath.Join(SiteStateDir, "copysite", "state")); err != nil {
		t.Fatal(err)
	}
	f.tEnv.CopyKeyHandoff = &fakeHandoff{answers: [][2][]byte{{r.browserShare(t), r.pub[:]}}}
	_, err := copyTakeKeyRun(ctx, f.tEnv, takeKeyParams(t, r, c))
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

// The copy reads the backup itself (specs/storage_targets.md F7): a manifest
// that is not the one named, not this chain's, sealing another key, recorded
// before its run, or not served plainly is refused before the owner is asked
// anything; a date from a host that is not a provider's is not shown as one.
func TestCopyTakeKeyReadsTheBackupItself(t *testing.T) {
	f := newExportFixture(t)
	r := newRecoveryFixture(t)
	ctx := WithJobID(context.Background(), 2)
	c := newStoredChain(t, r)
	asked := func() *fakeHandoff {
		h := &fakeHandoff{answers: [][2][]byte{{r.browserShare(t), r.pub[:]}}}
		f.tEnv.CopyKeyHandoff = h
		return h
	}
	refused := func(what, want string, p Params) {
		t.Helper()
		h := asked()
		_, err := copyTakeKeyRun(ctx, f.tEnv, p)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v; want a refusal naming %q", what, err, want)
		}
		if h.jobID != 0 {
			t.Errorf("%s: the owner was asked", what)
		}
		if strings.Contains(errString(err), "X-Amz-Signature") {
			t.Errorf("%s: the refusal carries the signed link: %v", what, err)
		}
	}

	good := takeKeyParams(t, r, c)
	named := c.body
	c.body = append(append([]byte{}, named...), ' ')
	refused("other bytes than the hash named", "hash differs", good)
	c.body = manifestBody(t, "chain-20260101_000000", "2026-10-01T03:00:00Z", r)
	refused("another chain's manifest", "not chain-", takeKeyParams(t, r, c))
	other := newRecoveryFixture(t)
	c.body = manifestBody(t, exportChainID, "2026-10-01T03:00:00Z", other)
	refused("a manifest sealing another key", "not the one this backup's manifest seals", takeKeyParams(t, r, c))
	c.body = named
	c.modified = time.Date(2026, 10, 1, 2, 0, 0, 0, time.UTC)
	refused("stored before its newest run", "cannot be recorded before it happens", good)
	c.modified = time.Date(2026, 10, 1, 3, 20, 0, 0, time.UTC)
	c.status = http.StatusNotFound
	refused("not in storage", "HTTP 404", good)
	c.status = http.StatusForbidden
	refused("an expired link", "may have expired", good)
	c.status = http.StatusOK
	c.redirect = "https://example.com/elsewhere"
	refused("a redirect", "HTTP 302", good)
	c.redirect = ""

	// A host that is not a provider's: the run and the hash still hold, and
	// the date is not passed off as checked.
	storageProviderOf = func(string) string { return "" }
	h := asked()
	if _, err := copyTakeKeyRun(ctx, f.tEnv, good); err != nil {
		t.Fatalf("an unknown host: %v", err)
	}
	if h.staged.StoredTime != "" || h.staged.StoredAt != "" || h.staged.RunTime != "2026-10-01T03:00:00Z" {
		t.Errorf("an unknown host staged %+v; want no stored date", h.staged)
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// The hosts whose Last-Modified the copy believes: each provider's API host in
// the form this platform signs links for, and nothing that merely resembles one.
func TestStorageProviderHosts(t *testing.T) {
	for host, want := range map[string]string{
		"s3.us-west-004.backblazeb2.com":              "Backblaze B2",
		"us-ord-10.linodeobjects.com":                 "Linode",
		"us-east-1.linodeobjects.com":                 "Linode",
		"my-bucket.s3.us-east-1.amazonaws.com":        "Amazon S3",
		"my.dotted.bucket.s3.eu-west-2.amazonaws.com": "Amazon S3",
		"s3.us-gov-west-1.amazonaws.com":              "Amazon S3",
		"s3.amazonaws.com":                            "Amazon S3",
		"0123abcd.r2.cloudflarestorage.com":           "Cloudflare R2",
		"0123abcd.eu.r2.cloudflarestorage.com":        "Cloudflare R2",
		"s3.us-east-1.wasabisys.com":                  "Wasabi",
		"nyc3.digitaloceanspaces.com":                 "DigitalOcean Spaces",
		"fsn1.your-objectstorage.com":                 "Hetzner",

		"s3.example.com":                                   "",
		"backblazeb2.com.evil.example":                     "",
		"f004.backblazeb2.com":                             "",
		"my-bucket.website-us-east-1.linodeobjects.com":    "",
		"my-bucket.s3-website-us-east-1.amazonaws.com":     "",
		"ap-1234.s3-accesspoint.us-east-1.amazonaws.com":   "",
		"ol-1234.s3-object-lambda.us-east-1.amazonaws.com": "",
		"abc.execute-api.us-east-1.amazonaws.com":          "",
		"my-bucket.nyc3.cdn.digitaloceanspaces.com":        "",
		"127.0.0.1": "",
	} {
		if got := storageProviderOf(host); got != want {
			t.Errorf("%s: %q; want %q", host, got, want)
		}
	}
}
