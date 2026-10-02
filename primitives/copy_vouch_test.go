package primitives

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The final copy's vouch (specs/site_copy.md B44): copy_vouch signs on a
// frozen source, copy_take_vouch replaces the copy's vouch with it, and
// copy_stage then reads the new manifest. And each refusal: a live or copy
// source, a tampered byte, another source key, another target, an export
// passed off as a vouch, an expired, future or replayed vouch, and a chain
// the copy holds no key for.

// freeze puts the fixture's source in quiet switchover.
func (f *exportFixture) freeze(t *testing.T) {
	t.Helper()
	mustWrite(t, filepath.Join(SiteStateDir, "sourcesite", "state"), "quiet switchover\n", 0o644)
}

func (f *exportFixture) vouchParams(target []byte) Params {
	return validParams(f.t, "copy_vouch", map[string]interface{}{
		"profile":           "manager",
		"chain_id":          exportChainID,
		"target_public_key": base64.StdEncoding.EncodeToString(target),
	})
}

func (f *exportFixture) vouch(t *testing.T) string {
	t.Helper()
	out, err := copyVouchRun(context.Background(), f.sEnv, f.vouchParams(f.target.PublicKey()))
	if err != nil {
		t.Fatalf("copy_vouch: %v", err)
	}
	return out["vouch"].(string)
}

func (f *exportFixture) takeVouch(t *testing.T, vouch string) (map[string]interface{}, error) {
	t.Helper()
	return copyTakeVouchRun(context.Background(), f.tEnv, validParams(t, "copy_take_vouch", map[string]interface{}{"vouch": vouch}))
}

// rewriteManifest is the final backup run: the chain's manifest grows a run,
// and the ledger records the new bytes.
func (f *exportFixture) rewriteManifest(t *testing.T) string {
	t.Helper()
	sRoot := f.sEnv.SiteRoot
	path := filepath.Join(sRoot, "backups", managerSubdir, exportChainID, chainManifestFile)
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]interface{}
	_ = json.Unmarshal(body, &m)
	m["runs"] = []string{"run-0", "run-1"}
	grown, _ := json.Marshal(m)
	mustWrite(t, path, string(grown), 0o600)
	sum, err := hashFile(path)
	if err != nil {
		t.Fatal(err)
	}
	ledger, _ := json.Marshal(map[string]ledgerEntry{
		exportChainID + "/" + chainManifestFile: {SHA256: sum, Bytes: int64(len(grown)), UploadedTime: "2026-10-02 18:00:00"},
	})
	mustWrite(t, filepath.Join(sRoot, "config", ledgerDirName, "manager.json"), string(ledger), 0o600)
	return sum
}

func TestAVouchMovesTheCopyToTheFinalRunWithNoSecret(t *testing.T) {
	f := newExportFixture(t)
	if _, err := f.importBundle(t, f.export(t, f.target.PublicKey())); err != nil {
		t.Fatalf("copy_import: %v", err)
	}
	f.freeze(t)
	final := f.rewriteManifest(t)
	if final == f.manifestSum {
		t.Fatal("the fixture's final run did not change the manifest")
	}
	wire := f.vouch(t)
	if strings.Contains(wire, f.dataKey) {
		t.Fatal("the vouch carries the chain's data key")
	}
	out, err := f.takeVouch(t, wire)
	if err != nil {
		t.Fatalf("copy_take_vouch: %v", err)
	}
	if out["manifest_sha256"] != final {
		t.Errorf("took %v, want the final manifest %s", out["manifest_sha256"], final)
	}
	vouched, err := vouchedManifests(f.tEnv, exportChainID)
	if err != nil || len(vouched) != 1 || vouched[0] != final {
		t.Errorf("vouched %v (%v), want only the final manifest", vouched, err)
	}
	// The chain key the approved export wrote is untouched.
	key, _ := os.ReadFile(filepath.Join(chainWorkspace(context.Background(), f.tEnv, exportChainID), chainKeyFile))
	if string(key) != f.dataKey {
		t.Errorf("chain.key changed to %q", key)
	}
	if _, err := f.takeVouch(t, wire); !Refused(err) || !strings.Contains(err.Error(), "already taken") {
		t.Errorf("the same vouch was taken twice: %v", err)
	}
}

func TestOnlyAFrozenSourceVouches(t *testing.T) {
	f := newExportFixture(t)
	if _, err := copyVouchRun(context.Background(), f.sEnv, f.vouchParams(f.target.PublicKey())); !Refused(err) ||
		!strings.Contains(err.Error(), "copy_export") {
		t.Errorf("a live site vouched: %v", err)
	}
	f.sEnv.SiteRoot = f.tEnv.SiteRoot
	if _, err := copyVouchRun(context.Background(), f.sEnv, f.vouchParams(f.target.PublicKey())); !Refused(err) {
		t.Errorf("a dormant copy vouched: %v", err)
	}
}

func TestAVouchForAManifestOutsideTheLedgerIsNotMade(t *testing.T) {
	f := newExportFixture(t)
	f.freeze(t)
	path := filepath.Join(f.sEnv.SiteRoot, "backups", managerSubdir, exportChainID, chainManifestFile)
	mustWrite(t, path, `{"chain_id":"`+exportChainID+`","changed":true}`, 0o600)
	if _, err := copyVouchRun(context.Background(), f.sEnv, f.vouchParams(f.target.PublicKey())); err == nil {
		t.Error("vouched for a manifest the ledger did not record")
	}
}

func TestACopyTakesNoVouchForAChainItHoldsNoKeyFor(t *testing.T) {
	f := newExportFixture(t)
	f.freeze(t)
	if _, err := f.takeVouch(t, f.vouch(t)); !Refused(err) || !strings.Contains(err.Error(), "holds no key") {
		t.Errorf("took a vouch with no approved export behind it: %v", err)
	}
}

func TestAVouchMustBeTheSourcesForThisCopy(t *testing.T) {
	f := newExportFixture(t)
	if _, err := f.importBundle(t, f.export(t, f.target.PublicKey())); err != nil {
		t.Fatalf("copy_import: %v", err)
	}
	f.freeze(t)
	f.rewriteManifest(t)

	// Tampered.
	var b copyBundle
	_ = json.Unmarshal([]byte(f.vouch(t)), &b)
	raw, _ := base64.StdEncoding.DecodeString(b.Body)
	raw[len(raw)/2] ^= 1
	b.Body = base64.StdEncoding.EncodeToString(raw)
	wire, _ := json.Marshal(b)
	if _, err := f.takeVouch(t, string(wire)); !Refused(err) || !strings.Contains(err.Error(), "signature") {
		t.Errorf("a changed vouch was taken: %v", err)
	}

	// For another machine.
	out, err := copyVouchRun(context.Background(), f.sEnv, f.vouchParams(newTestKey(t).PublicKey()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.takeVouch(t, out["vouch"].(string)); !Refused(err) || !strings.Contains(err.Error(), "another machine") {
		t.Errorf("a vouch for another key was taken: %v", err)
	}

	// Signed by another key.
	real := f.sEnv.Key
	impostor := newTestKey(t)
	f.sEnv.Key = func() (NodeKey, error) { return impostor, nil }
	if _, err := f.takeVouch(t, f.vouch(t)); !Refused(err) || !strings.Contains(err.Error(), "signature") {
		t.Errorf("a vouch signed by another key was taken: %v", err)
	}
	f.sEnv.Key = real

	// From another node.
	f.sEnv.NodeID = func() (int64, error) { return 99, nil }
	if _, err := f.takeVouch(t, f.vouch(t)); !Refused(err) || !strings.Contains(err.Error(), "node 99") {
		t.Errorf("a vouch from another node was taken: %v", err)
	}
}

func TestAnExportIsNotAVouchAndAVouchIsNotAnExport(t *testing.T) {
	f := newExportFixture(t)
	bundle := f.export(t, f.target.PublicKey())
	if _, err := f.takeVouch(t, bundle); !Refused(err) {
		t.Errorf("an export bundle was taken as a vouch: %v", err)
	}
	if _, err := f.importBundle(t, bundle); err != nil {
		t.Fatalf("copy_import: %v", err)
	}
	f.freeze(t)
	f.rewriteManifest(t)
	if _, err := f.importBundle(t, f.vouch(t)); !Refused(err) {
		t.Errorf("a vouch was imported as an export: %v", err)
	}
}

// signedVouch signs a vouch as the source would, with chosen times.
func (f *exportFixture) signedVouch(t *testing.T, issued, expires time.Time) string {
	t.Helper()
	wire, err := signCopyVouch(copyVouchBody{
		Format: CopyVouchDomain, SourceNodeID: 41,
		SourceKey:      base64.StdEncoding.EncodeToString(f.source.PublicKey()),
		TargetKey:      base64.StdEncoding.EncodeToString(f.target.PublicKey()),
		Issued:         issued.Format(time.RFC3339Nano),
		Expires:        expires.Format(time.RFC3339Nano),
		ChainID:        exportChainID,
		ManifestSHA256: f.manifestSum,
	}, func(m []byte) ([]byte, error) { return f.source.SignDomain(CopyVouchDomain, m) })
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func TestAnExpiredFutureOrOlderVouchIsRefused(t *testing.T) {
	f := newExportFixture(t)
	if _, err := f.importBundle(t, f.export(t, f.target.PublicKey())); err != nil {
		t.Fatalf("copy_import: %v", err)
	}
	now := time.Now().UTC()
	if _, err := f.takeVouch(t, f.signedVouch(t, now.Add(-2*time.Hour), now.Add(-time.Hour))); !Refused(err) ||
		!strings.Contains(err.Error(), "expired") {
		t.Errorf("an expired vouch was taken: %v", err)
	}
	if _, err := f.takeVouch(t, f.signedVouch(t, now.Add(time.Hour), now.Add(2*time.Hour))); !Refused(err) ||
		!strings.Contains(err.Error(), "clock") {
		t.Errorf("a vouch from the future was taken: %v", err)
	}
	// Issued before the export the copy already took.
	if _, err := f.takeVouch(t, f.signedVouch(t, now.Add(-10*time.Minute), now.Add(time.Hour))); !Refused(err) ||
		!strings.Contains(err.Error(), "already taken") {
		t.Errorf("a vouch older than the export was taken: %v", err)
	}
}

func TestAVouchReachesCopyStage(t *testing.T) {
	f := newExportFixture(t)
	if _, err := f.importBundle(t, f.export(t, f.target.PublicKey())); err != nil {
		t.Fatalf("copy_import: %v", err)
	}
	f.freeze(t)
	final := f.rewriteManifest(t)
	if _, err := f.takeVouch(t, f.vouch(t)); err != nil {
		t.Fatalf("copy_take_vouch: %v", err)
	}
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
	if got := strings.Join(argv, " "); !strings.HasSuffix(got, "--vouched "+final) || strings.Contains(got, f.manifestSum) {
		t.Errorf("copy_stage argv %q, want only the final manifest vouched", got)
	}
}
