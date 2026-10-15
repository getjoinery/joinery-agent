package recipes

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"joinery-agent/primitives"
)

// Recipe release_files: the deployment files an upgrade starts from match the
// signed release, or the node puts them back on its own clock
// (specs/release_file_repair_by_hash.md).

func preflight(manifestOK, filesOK bool) map[string]interface{} {
	return map[string]interface{}{
		"ok": manifestOK && filesOK,
		"checks": []map[string]interface{}{
			{"check": "manifest", "ok": manifestOK, "reason": "manifest reason"},
			{"check": "files", "ok": filesOK, "reason": "files reason"},
			{"check": "disk", "ok": false, "reason": "less than 500 MB free where the release is staged"},
			{"check": "theme", "ok": false, "reason": "the active theme is not on this node's disk"},
		},
	}
}

func TestReleaseFilesVerdicts(t *testing.T) {
	cases := []struct {
		name   string
		result map[string]interface{}
		err    error
		want   Kind
		reason string
	}{
		{"every file matches", preflight(true, true), nil, Pass, "files reason"},
		{"a file differs", preflight(true, false), nil, Fail, "files reason"},
		{"the manifest is unusable is the healer's case", preflight(false, false), nil, Unknown, "manifest healer"},
		{"the word refused", nil, &primitives.RefusalError{Reason: "no site"}, Unknown, "refused"},
		{"the word failed", nil, errors.New("boom"), Unknown, "failed"},
		{"no checks at all", map[string]interface{}{"ok": true}, nil, Unknown, "manifest is usable"},
	}
	for _, c := range cases {
		v := releaseFilesVerdict(c.result, c.err)
		if v.Kind != c.want || !strings.Contains(v.Reason, c.reason) {
			t.Errorf("%s: got %+v, want %s containing %q", c.name, v, c.want, c.reason)
		}
	}
	// A disk or theme failure in the same answer is a rollout's business and
	// never this recipe's: with the files matching the verdict is PASS above,
	// though both of those checks fail in the fixture.

	// After a round trip the checks arrive as []interface{}; the reading is the same.
	rt := map[string]interface{}{"checks": []interface{}{
		map[string]interface{}{"check": "manifest", "ok": true, "reason": "fine"},
		map[string]interface{}{"check": "files", "ok": false, "reason": "upgrade.php differs"},
	}}
	if v := releaseFilesVerdict(rt, nil); v.Kind != Fail || v.Reason != "upgrade.php differs" {
		t.Errorf("round-tripped checks read the same, got %+v", v)
	}
}

func TestRepairReleaseFilesOutcome(t *testing.T) {
	full := map[string]interface{}{"ok": true, "restored": []map[string]interface{}{
		{"file": "public_html/utils/upgrade.php", "source": "management node"},
	}, "failed": []map[string]interface{}{}}
	if d, err := repairReleaseFilesOutcome(full, nil); err != nil || !strings.Contains(d, "upgrade.php from the management node") {
		t.Errorf("a full repair is a success naming the files, got %q %v", d, err)
	}
	partial := map[string]interface{}{"ok": false, "restored": []interface{}{
		map[string]interface{}{"file": "public_html/utils/upgrade.php", "source": "kept copy"},
	}}
	if _, err := repairReleaseFilesOutcome(partial, nil); err == nil || !strings.Contains(err.Error(), "remains") {
		t.Errorf("a partial repair is a failure that says a file remains, got %v", err)
	}
	if _, err := repairReleaseFilesOutcome(map[string]interface{}{"ok": true}, nil); err == nil {
		t.Error("a result that put nothing back is a failure")
	}
	if _, err := repairReleaseFilesOutcome(nil, errors.New("refused")); err == nil {
		t.Error("the word's own error is the outcome")
	}
}

// relSiteForRecipe lays a site whose five deployment files match a signed
// manifest, with a verifier of the kind the words read (ArtifactManifests).
func relSiteForRecipe(t *testing.T) (root string, env *primitives.ExecEnv, sign func(), write func(rel, body string)) {
	t.Helper()
	root = t.TempDir()
	t.Cleanup(primitives.SetReleaseFilesDirForTests(filepath.Join(t.TempDir(), "release-files")))
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	write = func(rel, body string) {
		full := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	sign = func() {
		manifest := "# manifest\n"
		for _, rel := range primitives.SelfUpdateFiles {
			b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(b)
			manifest += hex.EncodeToString(sum[:]) + "  " + rel + "\n"
		}
		write("RELEASE_MANIFEST", manifest)
		write("RELEASE_MANIFEST.sig", base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(manifest)))+"\n")
	}
	for _, rel := range primitives.SelfUpdateFiles {
		write(rel, "<?php // "+rel+" 0.8.494\n")
	}
	write("public_html/VERSION", "0.8.494\n")
	sign()
	env = &primitives.ExecEnv{SiteRoot: root, WebRoot: filepath.Join(root, "public_html"),
		Manifest: primitives.NewArtifactManifests(root, pub)}
	return root, env, sign, write
}

// End to end, in the state getjoinery-orgs was left in on 2026-10-14: a deploy
// of 0.8.495 failed and rolled the code back, leaving the 0.8.494 deployment
// files under the 0.8.495 manifest. The real recipe, the real words through
// primitives.Execute, and a plane that answers by hash. Two failing checks,
// one repair, and the node is upgradeable again with no one's hand on it.
func TestTheReleaseFilesRecipeUnwedgesANodeThroughItsTwoWords(t *testing.T) {
	root, exec, sign, write := relSiteForRecipe(t)
	restoreLedger, restoreHold, restoreOut := LedgerDir, HoldDir, OutwardDir
	LedgerDir, HoldDir, OutwardDir = filepath.Join(root, "ledger"), filepath.Join(root, "hold"), ""
	t.Cleanup(func() { LedgerDir, HoldDir, OutwardDir = restoreLedger, restoreHold, restoreOut })
	restoreSite := HasSite
	HasSite = func() bool { return true }
	t.Cleanup(func() { HasSite = restoreSite })

	// 0.8.495's deployment files went in and were signed...
	newBodies := map[string]string{}
	for _, rel := range primitives.SelfUpdateFiles {
		newBodies[rel] = "<?php // " + rel + " 0.8.495\n"
		write(rel, newBodies[rel])
	}
	sign()
	// ...then the rollback put 0.8.494's code, and VERSION, back under that manifest.
	for _, rel := range primitives.SelfUpdateFiles {
		write(rel, "<?php // "+rel+" 0.8.494\n")
	}
	byHash := map[string]string{}
	for _, body := range newBodies {
		sum := sha256.Sum256([]byte(body))
		byHash[hex.EncodeToString(sum[:])] = body
	}
	var askedVersions []string
	exec.FetchReleaseFile = func(_ context.Context, version, rel, hash string) ([]byte, error) {
		askedVersions = append(askedVersions, version)
		body, ok := byHash[hash]
		if !ok {
			return nil, errors.New("no published release carries that hash")
		}
		return []byte(body), nil
	}
	env := &Env{Exec: exec, Policy: primitives.ShippedPolicy()}

	recipe, ok := Lookup("release_files")
	if !ok || recipe.Scope != ScopeRelease || recipe.NoRepair || recipe.NodeDerived {
		t.Fatalf("release_files is a release-scoped recipe with a parameterless repair, got %+v", recipe)
	}
	now := time.Date(2026, 10, 15, 3, 0, 0, 0, time.UTC)
	var lock sync.Mutex
	var logs []string
	loop := NewLoop([]Recipe{recipe}, env, Options{
		Now:  func() time.Time { return now },
		Lock: &lock,
		Logf: func(format string, args ...interface{}) { logs = append(logs, fmt.Sprintf(format, args...)) },
	})
	loop.reportOnly = false
	for i := 0; i < 2; i++ {
		now = now.Add(TickInterval)
		loop.Tick(context.Background())
	}
	entries := readEntries(t, filepath.Join(LedgerDir, "release_files.jsonl"))
	var outcome Entry
	checks := 0
	for _, e := range entries {
		if e.Event == EventOutcome {
			outcome = e
		}
		if e.Event == EventCheck {
			checks++
		}
	}
	if outcome.Outcome != OutcomeRepaired || !strings.Contains(outcome.Detail, "upgrade.php from the management node") {
		t.Fatalf("expected the recipe to repair through repair_release_files and verify through upgrade_preflight, got %+v\nlog:\n%s", outcome, strings.Join(logs, "\n"))
	}
	if checks < 2 {
		t.Errorf("both failing checks should be ledgered, got %d", checks)
	}
	if LastVerdict("release_files") != Pass {
		t.Errorf("after the repair's verifying check the claim should say pass, got %q", LastVerdict("release_files"))
	}
	for _, rel := range primitives.SelfUpdateFiles {
		b, _ := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if string(b) != newBodies[rel] {
			t.Errorf("%s should be the file the signed manifest lists, got %q", rel, b)
		}
	}
	if len(askedVersions) != len(primitives.SelfUpdateFiles) || askedVersions[0] != "0.8.494" {
		t.Errorf("each file is asked for once, by hash, with the VERSION as a hint: %v", askedVersions)
	}
	// And the next tick, matching, does nothing.
	now = now.Add(TickInterval)
	loop.Tick(context.Background())
	if n := len(readEntries(t, filepath.Join(LedgerDir, "release_files.jsonl"))); n != len(entries) {
		t.Errorf("a passing tick after a pass should write nothing; ledger grew from %d to %d", len(entries), n)
	}
}

// A manifest that cannot be used is never this recipe's to repair: the check is
// unknown, nothing is attempted, and the manifest healer has the case.
func TestTheReleaseFilesRecipeLeavesAnUnusableManifestAlone(t *testing.T) {
	root, exec, _, write := relSiteForRecipe(t)
	write("public_html/utils/upgrade.php", "<?php // changed\n")
	if err := os.Remove(filepath.Join(root, "RELEASE_MANIFEST")); err != nil {
		t.Fatal(err)
	}
	fetched := false
	exec.FetchReleaseFile = func(context.Context, string, string, string) ([]byte, error) {
		fetched = true
		return nil, errors.New("must not be asked")
	}
	recipe, _ := Lookup("release_files")
	v := recipe.Check(context.Background(), &Env{Exec: exec, Policy: primitives.ShippedPolicy()})
	if v.Kind != Unknown {
		t.Fatalf("an unusable manifest is unknown, never fail, got %+v", v)
	}
	if fetched {
		t.Fatal("the check asks the plane for nothing")
	}
}

// The publishing site and a developer's box are source checkouts: a deployment
// file there legitimately differs from the last published manifest between
// publishes, and the recipe must never write the released bytes over the edit.
// It does not tick there at all, and the claim says not-applicable.
func TestTheReleaseFilesRecipeNeverTicksOnASourceCheckout(t *testing.T) {
	restoreSite, restoreCheckout := HasSite, SourceCheckout
	HasSite = func() bool { return true }
	SourceCheckout = func() bool { return true }
	t.Cleanup(func() { HasSite, SourceCheckout = restoreSite, restoreCheckout })
	recipe, _ := Lookup("release_files")
	if Applicable(recipe) {
		t.Fatal("release_files must not apply on a source checkout")
	}
	if ModeOf(recipe) != ModeNotApplicable {
		t.Fatalf("the claim says not-applicable on a checkout, got %q", ModeOf(recipe))
	}
	if !strings.Contains(inapplicableReason(recipe), "source checkout") {
		t.Fatalf("the reason names the checkout, got %q", inapplicableReason(recipe))
	}
	SourceCheckout = func() bool { return false }
	if !Applicable(recipe) {
		t.Fatal("release_files applies on a site installed from a release")
	}
	HasSite = func() bool { return false }
	if Applicable(recipe) {
		t.Fatal("release_files does not apply on a machine with no site")
	}
}
