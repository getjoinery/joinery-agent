package primitives

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

// The copy export end to end (specs/site_copy.md WP4): copy_export seals on
// the source, copy_import opens on the copy, copy_stage reads the vouch. And
// each refusal the test plan names: a tampered byte, a wrong target key, a
// wrong source key, an expired bundle, a replayed bundle, a manifest not in
// the signed list, and a run missing from the source's ledger.

const exportChainID = "chain-20260930_010203"

// testKey is a NodeKey over a key the test holds, as the agent's identity is
// over the key in its identity file.
type testKey struct{ priv ed25519.PrivateKey }

func (k testKey) PublicKey() ed25519.PublicKey { return k.priv.Public().(ed25519.PublicKey) }
func (k testKey) SignDomain(domain string, msg []byte) ([]byte, error) {
	if !strings.HasPrefix(string(msg), domain+"\n") {
		panic("message does not begin with its domain")
	}
	return ed25519.Sign(k.priv, msg), nil
}
func (k testKey) OpenSealed(blob []byte) ([]byte, error) { return OpenSealedToAgentKey(k.priv, blob) }

func newTestKey(t *testing.T) testKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return testKey{priv: priv}
}

type exportFixture struct {
	t              *testing.T
	source, target testKey
	sEnv, tEnv     *ExecEnv
	dataKey        string
	manifestSum    string
	tLE, tDKIM     string
}

// writeHostFixture lays out a certbot tree with one lineage at version 3,
// an account, a DNS-01 credential and a DKIM key under dir.
func writeHostFixture(t *testing.T, dir string) (le, dkim string) {
	t.Helper()
	le = filepath.Join(dir, "letsencrypt")
	dkim = filepath.Join(dir, "dkim")
	files := map[string]string{
		"renewal/example.org.conf":              "archive_dir = /etc/letsencrypt/archive/example.org\n",
		"archive/example.org/cert1.pem":         "OLD CERT",
		"archive/example.org/cert3.pem":         "CERT 3",
		"archive/example.org/chain3.pem":        "CHAIN 3",
		"archive/example.org/fullchain3.pem":    "FULLCHAIN 3",
		"archive/example.org/privkey3.pem":      "PRIVKEY 3",
		"accounts/acme/directory/abc/meta.json": "{}",
		"cloudflare.ini":                        "dns_cloudflare_api_token = secret\n",
	}
	for rel, body := range files {
		p := filepath.Join(le, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	live := filepath.Join(le, "live", "example.org")
	if err := os.MkdirAll(live, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"cert", "chain", "fullchain", "privkey"} {
		if err := os.Symlink("../../archive/example.org/"+f+"3.pem", filepath.Join(live, f+".pem")); err != nil {
			t.Fatal(err)
		}
	}
	keyDir := filepath.Join(dkim, "example.org")
	if err := os.MkdirAll(keyDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(keyDir, "mail.private"), []byte("DKIM KEY"), 0o600); err != nil {
		t.Fatal(err)
	}
	return le, dkim
}

// newExportFixture builds a source with one chain in its ledger and its
// manifest on disk, and a dormant copy that recorded the source's key.
func newExportFixture(t *testing.T) *exportFixture {
	t.Helper()
	f := &exportFixture{t: t, source: newTestKey(t), target: newTestKey(t)}

	// The source: a site root with a backup keypair, a chain manifest sealed
	// to it, and the ledger entry that vouches for the manifest.
	sRoot := filepath.Join(t.TempDir(), "sourcesite")
	sitePub, sitePriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(sRoot, "config", siteKeyFile),
		base64.StdEncoding.EncodeToString(append(append([]byte{}, sitePriv[:]...), sitePub[:]...)), 0o640)
	f.dataKey = base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	sealed, err := box.SealAnonymous(nil, []byte(f.dataKey), sitePub, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifest, _ := json.Marshal(map[string]interface{}{
		"chain_id": exportChainID,
		"envelope": map[string]interface{}{"recipients": []map[string]string{
			{"kind": "recovery", "sealed": base64.StdEncoding.EncodeToString([]byte("not for this machine"))},
			{"kind": "site", "sealed": base64.StdEncoding.EncodeToString(sealed)},
		}},
	})
	mustWrite(t, filepath.Join(sRoot, "backups", managerSubdir, exportChainID, chainManifestFile), string(manifest), 0o600)
	sum := sha256.Sum256(manifest)
	f.manifestSum = hex.EncodeToString(sum[:])
	ledger, _ := json.Marshal(map[string]ledgerEntry{
		exportChainID + "/" + chainManifestFile: {SHA256: f.manifestSum, Bytes: int64(len(manifest)), UploadedTime: "2026-09-30 01:05:00"},
	})
	mustWrite(t, filepath.Join(sRoot, "config", ledgerDirName, "manager.json"), string(ledger), 0o600)
	_ = os.Chmod(filepath.Join(sRoot, "config", ledgerDirName), 0o700)

	host := t.TempDir()
	sLE, sDKIM := writeHostFixture(t, host)
	oldLE, oldDKIM := CopyLetsEncryptDir, CopyDKIMDir
	CopyLetsEncryptDir, CopyDKIMDir = sLE, sDKIM
	t.Cleanup(func() { CopyLetsEncryptDir, CopyDKIMDir = oldLE, oldDKIM })

	f.sEnv = &ExecEnv{
		SiteRoot: sRoot,
		Key:      func() (NodeKey, error) { return f.source, nil },
		NodeID:   func() (int64, error) { return 41, nil },
	}

	// The copy: quiet copy of node 41, which recorded the source's key.
	states := t.TempDir()
	oldStates := SiteStateDir
	SiteStateDir = states
	t.Cleanup(func() { SiteStateDir = oldStates })
	tRoot := filepath.Join(t.TempDir(), "copysite")
	if err := os.MkdirAll(filepath.Join(tRoot, "backups"), 0o755); err != nil {
		t.Fatal(err)
	}
	st := filepath.Join(states, "copysite")
	mustWrite(t, filepath.Join(st, "state"), "quiet copy\n", 0o644)
	mustWrite(t, filepath.Join(st, "copy_of"), "41\n", 0o644)
	mustWrite(t, filepath.Join(st, copyOfKeyFile), base64.StdEncoding.EncodeToString(f.source.PublicKey())+"\n", 0o644)
	f.tEnv = &ExecEnv{
		SiteRoot: tRoot,
		Key:      func() (NodeKey, error) { return f.target, nil },
		NodeID:   func() (int64, error) { return 57, nil },
	}
	f.tLE = filepath.Join(t.TempDir(), "letsencrypt")
	f.tDKIM = filepath.Join(t.TempDir(), "dkim")
	return f
}

func mustWrite(t *testing.T, path, body string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
}

func (f *exportFixture) exportParams(target ed25519.PublicKey) Params {
	return validParams(f.t, "copy_export", map[string]interface{}{
		"profile":           "manager",
		"chain_id":          exportChainID,
		"target_public_key": base64.StdEncoding.EncodeToString(target),
	})
}

// validParams validates raw against a word's declared params, as Execute does.
func validParams(t *testing.T, word string, raw map[string]interface{}) Params {
	t.Helper()
	p := mustLookup(t, word)
	params, err := ValidateUpTo(p.Params, raw, p.paramsLimit())
	if err != nil {
		t.Fatalf("%s params: %v", word, err)
	}
	return params
}

// export runs copy_export on the source, past its approval, and returns the bundle.
func (f *exportFixture) export(t *testing.T, target ed25519.PublicKey) string {
	t.Helper()
	out, err := copyExportRun(context.Background(), f.sEnv, f.exportParams(target))
	if err != nil {
		t.Fatalf("copy_export: %v", err)
	}
	return out["bundle"].(string)
}

// importBundle runs copy_import on the copy, writing host files into the
// copy's own directories.
func (f *exportFixture) importBundle(t *testing.T, bundle string) (map[string]interface{}, error) {
	t.Helper()
	oldLE, oldDKIM := CopyLetsEncryptDir, CopyDKIMDir
	CopyLetsEncryptDir, CopyDKIMDir = f.tLE, f.tDKIM
	defer func() { CopyLetsEncryptDir, CopyDKIMDir = oldLE, oldDKIM }()
	return copyImportRun(context.Background(), f.tEnv, validParams(t, "copy_import", map[string]interface{}{"bundle": bundle}))
}

func TestTheX25519FormsOfAnAgentKeyAreOneKeypair(t *testing.T) {
	for i := 0; i < 50; i++ {
		k := newTestKey(t)
		pub, err := ed25519PublicToX25519(k.PublicKey())
		if err != nil {
			t.Fatal(err)
		}
		derived, err := curve25519.X25519(ed25519PrivateToX25519(k.priv), curve25519.Basepoint)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(pub) != hex.EncodeToString(derived) {
			t.Fatalf("key %d: the public map and the private scalar disagree", i)
		}
	}
}

func TestASealOpensOnlyWithItsKeyAndOnlyUnchanged(t *testing.T) {
	a, b := newTestKey(t), newTestKey(t)
	blob, err := sealToAgentKey(a.PublicKey(), []byte("the chain key"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := OpenSealedToAgentKey(a.priv, blob); err != nil || string(got) != "the chain key" {
		t.Fatalf("the recipient could not open it: %v", err)
	}
	if _, err := OpenSealedToAgentKey(b.priv, blob); err == nil {
		t.Fatal("another key opened it")
	}
	blob[len(blob)-1] ^= 1
	if _, err := OpenSealedToAgentKey(a.priv, blob); err == nil {
		t.Fatal("a changed seal opened")
	}
}

func TestALowOrderTargetKeyIsRefused(t *testing.T) {
	// y = 1 is the Edwards identity: its X25519 counterpart has no inverse.
	identity := make([]byte, 32)
	identity[0] = 1
	if _, err := sealToAgentKey(ed25519.PublicKey(identity), []byte("x")); err == nil {
		t.Fatal("sealed to the identity point")
	}
}

func TestAnExportOpensOnTheCopyAndWritesWhatTheOtherWordsRead(t *testing.T) {
	f := newExportFixture(t)
	out, err := f.importBundle(t, f.export(t, f.target.PublicKey()))
	if err != nil {
		t.Fatalf("copy_import: %v", err)
	}
	if chains := out["chains"].([]string); len(chains) != 1 || chains[0] != exportChainID {
		t.Errorf("imported chains %v", chains)
	}

	work := chainWorkspace(context.Background(), f.tEnv, exportChainID)
	key, err := os.ReadFile(filepath.Join(work, chainKeyFile))
	if err != nil || string(key) != f.dataKey {
		t.Errorf("chain.key is %q (%v), want the chain's data key", key, err)
	}
	if info, _ := os.Stat(filepath.Join(work, chainKeyFile)); info == nil || info.Mode().Perm() != 0o600 {
		t.Errorf("chain.key is not 0600")
	}
	vouched, err := vouchedManifests(f.tEnv, exportChainID)
	if err != nil || len(vouched) != 1 || vouched[0] != f.manifestSum {
		t.Errorf("vouched %v (%v), want the ledgered manifest %s", vouched, err, f.manifestSum)
	}

	// The current version of the lineage, linked as certbot links it; not the old one.
	link, err := os.Readlink(filepath.Join(f.tLE, "live", "example.org", "privkey.pem"))
	if err != nil || link != "../../archive/example.org/privkey3.pem" {
		t.Errorf("privkey link %q (%v)", link, err)
	}
	if body, _ := os.ReadFile(filepath.Join(f.tLE, "live", "example.org", "fullchain.pem")); string(body) != "FULLCHAIN 3" {
		t.Errorf("fullchain reads %q through its link", body)
	}
	if _, err := os.Stat(filepath.Join(f.tLE, "archive", "example.org", "cert1.pem")); err == nil {
		t.Error("an old version of the certificate travelled")
	}
	for _, rel := range []string{"renewal/example.org.conf", "accounts/acme/directory/abc/meta.json", "cloudflare.ini"} {
		if _, err := os.Stat(filepath.Join(f.tLE, rel)); err != nil {
			t.Errorf("%s did not travel: %v", rel, err)
		}
	}
	if info, err := os.Stat(filepath.Join(f.tLE, "archive", "example.org", "privkey3.pem")); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("the private key did not keep its mode: %v", err)
	}
	if body, _ := os.ReadFile(filepath.Join(f.tDKIM, "example.org", "mail.private")); string(body) != "DKIM KEY" {
		t.Errorf("the DKIM key did not travel")
	}

	// copy_stage now has what it needs, and passes the vouch to its script.
	p := mustLookup(t, "copy_stage")
	params, err := Validate(p.Params, map[string]interface{}{
		"chain_id": exportChainID, "manifest_url": "https://x.invalid/m?X-Amz-Signature=a",
		"artifact_urls": map[string]interface{}{"db-0000.sql.gz.enc": "https://x.invalid/d?X-Amz-Signature=b"},
	})
	if err != nil {
		t.Fatal(err)
	}
	argv, err := p.Script.ArgsFrom(context.Background(), f.tEnv, params)
	if err != nil {
		t.Fatalf("copy_stage: %v", err)
	}
	want := []string{"--workspace", work, "--vouched", f.manifestSum}
	if strings.Join(argv, " ") != strings.Join(want, " ") {
		t.Errorf("copy_stage argv %v, want %v", argv, want)
	}
}

func TestTheApprovalNamesTheMachineTheSecretsGoTo(t *testing.T) {
	f := newExportFixture(t)
	f.sEnv.ExportApproval = approveAll{}
	st, gate, _, err := copyExportCeremony(context.Background(), f.sEnv, f.exportParams(f.target.PublicKey()))
	if err != nil {
		t.Fatal(err)
	}
	if gate == nil {
		t.Fatal("no gate")
	}
	sum := sha256.Sum256(f.target.PublicKey())
	text := ""
	for _, fact := range st.Facts {
		text += fact.Label + ": " + fact.Value + "\n"
	}
	for _, want := range []string{hex.EncodeToString(sum[:])[:16], hex.EncodeToString(sum[:]), exportChainID,
		"2026-09-30 01:05:00", "example.org", "1 private key"} {
		if !strings.Contains(text, want) {
			t.Errorf("the statement does not say %q:\n%s", want, text)
		}
	}

	f.sEnv.ExportApproval = nil
	if _, _, _, err := copyExportCeremony(context.Background(), f.sEnv, f.exportParams(f.target.PublicKey())); !Refused(err) {
		t.Errorf("a machine that cannot ask exported anyway: %v", err)
	}
}

type approveAll struct{}

func (approveAll) Require(context.Context, int64, ApprovalStatement) error { return nil }

func TestARunMissingFromTheSourcesLedgerIsNotExported(t *testing.T) {
	f := newExportFixture(t)
	mustWrite(t, filepath.Join(f.sEnv.SiteRoot, "config", ledgerDirName, "manager.json"), "{}", 0o600)
	if _, err := copyExportRun(context.Background(), f.sEnv, f.exportParams(f.target.PublicKey())); !Refused(err) ||
		!strings.Contains(err.Error(), "no record of uploading") {
		t.Errorf("exported a run the ledger does not hold: %v", err)
	}
}

func TestAChangedManifestIsNotExported(t *testing.T) {
	f := newExportFixture(t)
	path := filepath.Join(f.sEnv.SiteRoot, "backups", managerSubdir, exportChainID, chainManifestFile)
	body, _ := os.ReadFile(path)
	mustWrite(t, path, string(body)+" ", 0o600)
	if _, err := copyExportRun(context.Background(), f.sEnv, f.exportParams(f.target.PublicKey())); !Refused(err) {
		t.Errorf("vouched for bytes this machine did not upload: %v", err)
	}
}

func TestADormantCopyExportsNothing(t *testing.T) {
	f := newExportFixture(t)
	f.sEnv.SiteRoot = f.tEnv.SiteRoot
	if _, err := copyExportRun(context.Background(), f.sEnv, f.exportParams(f.target.PublicKey())); !Refused(err) ||
		!strings.Contains(err.Error(), "dormant copy") {
		t.Errorf("a copy exported: %v", err)
	}
}

func TestATamperedByteIsRefused(t *testing.T) {
	f := newExportFixture(t)
	var b copyBundle
	_ = json.Unmarshal([]byte(f.export(t, f.target.PublicKey())), &b)
	raw, _ := base64.StdEncoding.DecodeString(b.Body)
	raw[len(raw)/2] ^= 1
	b.Body = base64.StdEncoding.EncodeToString(raw)
	wire, _ := json.Marshal(b)
	if _, err := f.importBundle(t, string(wire)); !Refused(err) || !strings.Contains(err.Error(), "signature") {
		t.Errorf("a changed bundle was taken: %v", err)
	}
}

func TestABundleForAnotherMachineIsRefused(t *testing.T) {
	f := newExportFixture(t)
	other := newTestKey(t)
	if _, err := f.importBundle(t, f.export(t, other.PublicKey())); !Refused(err) || !strings.Contains(err.Error(), "another machine") {
		t.Errorf("a bundle sealed to another key was taken: %v", err)
	}
}

func TestABundleFromAnotherSourceIsRefused(t *testing.T) {
	f := newExportFixture(t)
	impostor := newTestKey(t)
	f.sEnv.Key = func() (NodeKey, error) { return impostor, nil }
	if _, err := f.importBundle(t, f.export(t, f.target.PublicKey())); !Refused(err) || !strings.Contains(err.Error(), "signature") {
		t.Errorf("a bundle signed by another key was taken: %v", err)
	}
}

func TestABundleNamingAnotherSourceNodeIsRefused(t *testing.T) {
	f := newExportFixture(t)
	f.sEnv.NodeID = func() (int64, error) { return 99, nil }
	if _, err := f.importBundle(t, f.export(t, f.target.PublicKey())); !Refused(err) || !strings.Contains(err.Error(), "node 99") {
		t.Errorf("a bundle from another node was taken: %v", err)
	}
}

// signedBody signs a body as the source would, with chosen times.
func (f *exportFixture) signedBody(t *testing.T, issued, expires time.Time) string {
	t.Helper()
	payload, _ := json.Marshal(copyPayload{Chains: []copyChain{{ChainID: exportChainID, DataKey: "k", Manifests: []string{f.manifestSum}}}})
	sealed, err := sealToAgentKey(f.target.PublicKey(), gzipBytes(t, payload))
	if err != nil {
		t.Fatal(err)
	}
	wire, err := signCopyBundle(copyBundleBody{
		Format: CopyExportDomain, SourceNodeID: 41,
		SourceKey: base64.StdEncoding.EncodeToString(f.source.PublicKey()),
		TargetKey: base64.StdEncoding.EncodeToString(f.target.PublicKey()),
		Issued:    issued.Format(time.RFC3339Nano), Expires: expires.Format(time.RFC3339Nano),
		Sealed: base64.StdEncoding.EncodeToString(sealed),
	}, func(m []byte) ([]byte, error) { return f.source.SignDomain(CopyExportDomain, m) })
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func TestAnExpiredBundleIsRefused(t *testing.T) {
	f := newExportFixture(t)
	issued := time.Now().UTC().Add(-7 * time.Hour)
	if _, err := f.importBundle(t, f.signedBody(t, issued, issued.Add(copyExportLifetime))); !Refused(err) ||
		!strings.Contains(err.Error(), "expired") {
		t.Errorf("an expired bundle was taken: %v", err)
	}
}

func TestABundleFromTheFutureIsRefused(t *testing.T) {
	f := newExportFixture(t)
	issued := time.Now().UTC().Add(time.Hour)
	if _, err := f.importBundle(t, f.signedBody(t, issued, issued.Add(copyExportLifetime))); !Refused(err) ||
		!strings.Contains(err.Error(), "clock") {
		t.Errorf("a bundle issued an hour ahead was taken: %v", err)
	}
}

func TestAReplayedOrOlderBundleIsRefused(t *testing.T) {
	f := newExportFixture(t)
	older := f.signedBody(t, time.Now().UTC().Add(-time.Hour), time.Now().UTC().Add(time.Hour))
	bundle := f.export(t, f.target.PublicKey())
	if _, err := f.importBundle(t, bundle); err != nil {
		t.Fatalf("first import: %v", err)
	}
	if _, err := f.importBundle(t, bundle); !Refused(err) || !strings.Contains(err.Error(), "already imported") {
		t.Errorf("the same bundle was taken twice: %v", err)
	}
	if _, err := f.importBundle(t, older); !Refused(err) {
		t.Errorf("an older bundle was taken after a newer: %v", err)
	}
	if _, err := f.importBundle(t, f.export(t, f.target.PublicKey())); err != nil {
		t.Errorf("a fresh export after the first was refused: %v", err)
	}
}

func TestALiveSiteTakesNoBundle(t *testing.T) {
	f := newExportFixture(t)
	if err := os.RemoveAll(filepath.Join(SiteStateDir, "copysite")); err != nil {
		t.Fatal(err)
	}
	if _, err := f.importBundle(t, f.export(t, f.target.PublicKey())); !Refused(err) || !strings.Contains(err.Error(), "dormant copy") {
		t.Errorf("a live site took a bundle: %v", err)
	}
}

func TestACopyWithNoRecordedSourceKeyTakesNoBundle(t *testing.T) {
	f := newExportFixture(t)
	if err := os.Remove(filepath.Join(SiteStateDir, "copysite", copyOfKeyFile)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.importBundle(t, f.export(t, f.target.PublicKey())); !Refused(err) || !strings.Contains(err.Error(), "--copy-of-key") {
		t.Errorf("a copy with no source key took a bundle: %v", err)
	}
}

func TestAManifestNotInTheSignedListIsNotStaged(t *testing.T) {
	f := newExportFixture(t)
	if _, err := f.importBundle(t, f.export(t, f.target.PublicKey())); err != nil {
		t.Fatal(err)
	}
	p := mustLookup(t, "copy_stage")
	params, _ := Validate(p.Params, map[string]interface{}{
		"chain_id": "chain-20260101_000000", "manifest_url": "https://x.invalid/m?X-Amz-Signature=a",
		"artifact_urls": map[string]interface{}{"db-0000.sql.gz.enc": "https://x.invalid/d?X-Amz-Signature=b"},
	})
	if _, err := p.Script.ArgsFrom(context.Background(), f.tEnv, params); !Refused(err) || !strings.Contains(err.Error(), "vouched for no run") {
		t.Errorf("staged a chain the source did not vouch for: %v", err)
	}

	// And copy_restore refuses a staged manifest the vouch does not list.
	work := chainWorkspace(context.Background(), f.tEnv, exportChainID)
	mustWrite(t, filepath.Join(work, chainManifestFile), "{\"chain_id\":\""+exportChainID+"\"}", 0o600)
	if err := requireVouched(f.tEnv, exportChainID, filepath.Join(work, chainManifestFile)); !Refused(err) ||
		!strings.Contains(err.Error(), "not one the source vouched for") {
		t.Errorf("an unvouched manifest passed: %v", err)
	}
}

// A source's signing keys are read from where rspamd signs, and from where
// opendkim kept them on a machine whose mail installer has not moved them yet.
// Either way they travel under the one root name, so the copy writes them
// where rspamd signs.
func TestDKIMKeysAreReadFromEitherHome(t *testing.T) {
	oldLE, oldDKIM, oldFormer := CopyLetsEncryptDir, CopyDKIMDir, CopyFormerDKIMDir
	defer func() { CopyLetsEncryptDir, CopyDKIMDir, CopyFormerDKIMDir = oldLE, oldDKIM, oldFormer }()

	writeKey := func(dir, body string) {
		t.Helper()
		keyDir := filepath.Join(dir, "example.org")
		if err := os.MkdirAll(keyDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(keyDir, "mail.private"), []byte(body), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	keyBody := func(entries []copyHostFile) string {
		t.Helper()
		for _, e := range entries {
			if e.Root == "dkim" && e.Path == "example.org/mail.private" {
				raw, err := base64.StdEncoding.DecodeString(e.Data)
				if err != nil {
					t.Fatal(err)
				}
				return string(raw)
			}
		}
		return ""
	}

	base := t.TempDir()
	CopyLetsEncryptDir = filepath.Join(base, "no-letsencrypt")
	CopyDKIMDir = filepath.Join(base, "rspamd-dkim")
	CopyFormerDKIMDir = filepath.Join(base, "opendkim-keys")

	// Only the former home exists: the source has not been moved yet.
	writeKey(CopyFormerDKIMDir, "FORMER KEY")
	entries, sum, err := collectHostFiles()
	if err != nil {
		t.Fatal(err)
	}
	if got := keyBody(entries); got != "FORMER KEY" || sum.DKIMKeys != 1 {
		t.Fatalf("a key under the former home was not carried: %q, %d key(s)", got, sum.DKIMKeys)
	}

	// Both exist: the home rspamd signs from is the one that is read.
	writeKey(CopyDKIMDir, "CURRENT KEY")
	entries, sum, err = collectHostFiles()
	if err != nil {
		t.Fatal(err)
	}
	if got := keyBody(entries); got != "CURRENT KEY" || sum.DKIMKeys != 1 {
		t.Fatalf("the key rspamd signs with was not the one carried: %q, %d key(s)", got, sum.DKIMKeys)
	}

	// And a copy writes under the home rspamd signs from, never the former one.
	if copyHostRoots()["dkim"] != CopyDKIMDir {
		t.Fatalf("a copy writes signing keys to %s, not %s", copyHostRoots()["dkim"], CopyDKIMDir)
	}
}

func TestHostEntriesCannotLeaveTheirRoots(t *testing.T) {
	dir := t.TempDir()
	oldLE, oldDKIM := CopyLetsEncryptDir, CopyDKIMDir
	CopyLetsEncryptDir, CopyDKIMDir = filepath.Join(dir, "le"), filepath.Join(dir, "dkim")
	defer func() { CopyLetsEncryptDir, CopyDKIMDir = oldLE, oldDKIM }()
	bad := []copyHostFile{
		{Root: "letsencrypt", Path: "../escape", Kind: "file", Data: "eA=="},
		{Root: "letsencrypt", Path: "/etc/passwd", Kind: "file", Data: "eA=="},
		{Root: "elsewhere", Path: "x", Kind: "file", Data: "eA=="},
		{Root: "letsencrypt", Path: "live/x/cert.pem", Kind: "link", Link: "/etc/shadow"},
		{Root: "letsencrypt", Path: "live/x/cert.pem", Kind: "link", Link: "../../archive/y/cert1.pem"},
		{Root: "dkim", Path: "k", Kind: "link", Link: "../../archive/k/cert1.pem"},
		{Root: "letsencrypt", Path: "a/./b", Kind: "dir"},
	}
	for _, e := range bad {
		if _, err := installHostFiles([]copyHostFile{e}); err == nil {
			t.Errorf("installed %+v", e)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "escape")); err == nil {
		t.Error("a file landed outside its root")
	}
}

func gzipBytes(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write(b)
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestSignDomainMessagesAreNeverRequestSignatures(t *testing.T) {
	if strings.HasPrefix(string(copyExportSigned([]byte("x"))), "joinery-agent-v1\n") {
		t.Fatal("the export signs a message in the request domain")
	}
}
