package primitives

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The deployment files an upgrade replaces first, and what happens when it
// stops short (specs/release_file_repair.md). Each test names a way a node was
// left unable to upgrade itself, or a way the repair could be abused.

const (
	oldUpgrade = "<?php // upgrade 0.8.475\n"
	oldHelper  = "<?php // helper 0.8.475\n"
)

type relSite struct {
	t    *testing.T
	root string
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
	env  *ExecEnv
}

// newRelSite lays a site at 0.8.475 whose five deployment files match a signed
// manifest, with the snapshot directory pointed at a temporary one.
func newRelSite(t *testing.T) *relSite {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	root := t.TempDir()
	t.Cleanup(SetReleaseFilesDirForTests(filepath.Join(t.TempDir(), "release-files")))
	s := &relSite{t: t, root: root, pub: pub, priv: priv}
	for _, rel := range SelfUpdateFiles {
		body := "<?php // " + rel + " 0.8.475\n"
		if rel == "public_html/utils/upgrade.php" {
			body = oldUpgrade
		}
		if rel == "public_html/includes/DeploymentHelper.php" {
			body = oldHelper
		}
		s.write(rel, body)
	}
	s.write("public_html/VERSION", "0.8.475\n")
	s.sign()
	s.env = &ExecEnv{SiteRoot: root, WebRoot: filepath.Join(root, "public_html"),
		Manifest: NewArtifactManifests(root, pub)}
	return s
}

func (s *relSite) write(rel, body string) {
	s.t.Helper()
	p := filepath.Join(s.root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		s.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		s.t.Fatal(err)
	}
}

func (s *relSite) read(rel string) string {
	b, err := os.ReadFile(filepath.Join(s.root, filepath.FromSlash(rel)))
	if err != nil {
		return "<" + err.Error() + ">"
	}
	return string(b)
}

// sign writes a manifest over the five files as they are now.
func (s *relSite) sign() {
	s.t.Helper()
	var b strings.Builder
	b.WriteString("# manifest\n")
	for _, rel := range SelfUpdateFiles {
		b.WriteString(relSHA([]byte(s.read(rel))) + "  " + rel + "\n")
	}
	signTree(s.t, s.root, s.priv, b.String())
}

// An upgrade stopped after copying its new deployment files in.
func (s *relSite) stoppedUpgrade() {
	s.write("public_html/utils/upgrade.php", "<?php // upgrade 0.8.477\n")
	s.write("public_html/includes/DeploymentHelper.php", "<?php // helper 0.8.477\n")
}

func TestAStoppedUpgradeHasItsDeploymentFilesPutBack(t *testing.T) {
	s := newRelSite(t)
	if err := TakeReleaseSnapshot(s.env); err != nil {
		t.Fatal(err)
	}
	s.stoppedUpgrade()
	if names, checked := DifferingSelfUpdateFiles(s.env); !checked || len(names) != 2 {
		t.Fatalf("the stopped upgrade should show as two differing files, got %v checked=%v", names, checked)
	}

	restored, err := RestoreSelfUpdateFiles(s.env)
	if err != nil || len(restored) != 2 {
		t.Fatalf("both files should come back, got %v err=%v", restored, err)
	}
	if s.read("public_html/utils/upgrade.php") != oldUpgrade || s.read("public_html/includes/DeploymentHelper.php") != oldHelper {
		t.Fatal("the files should be byte-identical to what the release signed")
	}
	if names, _ := DifferingSelfUpdateFiles(s.env); len(names) != 0 {
		t.Fatalf("nothing should differ afterwards, got %v", names)
	}
	// What was replaced is kept: a modified file in a root-run path is evidence.
	kept, _ := filepath.Glob(filepath.Join(releaseFilesDir, "replaced", "*upgrade.php.*"))
	if len(kept) != 1 {
		t.Fatalf("the replaced upgrade.php should be kept for inspection, found %v", kept)
	}
}

func TestARelease_ThatWentIn_IsNotUndone(t *testing.T) {
	s := newRelSite(t)
	if err := TakeReleaseSnapshot(s.env); err != nil {
		t.Fatal(err)
	}
	// The upgrade succeeded: new files, new manifest, new VERSION.
	s.stoppedUpgrade()
	s.write("public_html/VERSION", "0.8.477\n")
	s.sign()
	restored, err := RestoreSelfUpdateFiles(s.env)
	if err != nil || len(restored) != 0 {
		t.Fatalf("a deployed release must be left alone, got %v err=%v", restored, err)
	}
	if s.read("public_html/utils/upgrade.php") != "<?php // upgrade 0.8.477\n" {
		t.Fatal("the new release's file was overwritten")
	}
}

func TestACorruptedOrPlantedCopyRestoresNothing(t *testing.T) {
	s := newRelSite(t)
	if err := TakeReleaseSnapshot(s.env); err != nil {
		t.Fatal(err)
	}
	s.stoppedUpgrade()
	// Someone with write access to the snapshot directory plants their own bytes.
	if err := os.WriteFile(snapshotFile("public_html/utils/upgrade.php"), []byte("<?php system($_GET['c']);\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	restored, _ := RestoreSelfUpdateFiles(s.env)
	for _, r := range restored {
		if r == "public_html/utils/upgrade.php" {
			t.Fatal("a copy that does not hash to the signed manifest must never be written")
		}
	}
	if strings.Contains(s.read("public_html/utils/upgrade.php"), "system(") {
		t.Fatal("planted bytes reached the site tree")
	}
}

func TestAFileThatDoesNotMatchIsNeverKept(t *testing.T) {
	s := newRelSite(t)
	s.stoppedUpgrade() // already wedged before any snapshot is taken
	if err := TakeReleaseSnapshot(s.env); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(snapshotFile("public_html/utils/upgrade.php")); err == nil {
		t.Fatal("a snapshot is only ever of a file the publisher signed")
	}
}

func TestWriteReleaseFileRefusesWhatTheManifestDoesNotList(t *testing.T) {
	s := newRelSite(t)
	if _, err := WriteReleaseFile(s.root, "public_html/utils/upgrade.php", []byte("evil"), relSHA([]byte(oldUpgrade))); err == nil {
		t.Fatal("bytes that do not hash to the signed value must be refused")
	}
	if _, err := WriteReleaseFile(s.root, "public_html/index.php", []byte("x"), relSHA([]byte("x"))); err == nil {
		t.Fatal("a path outside the five must be refused whatever its hash")
	}
	if _, err := WriteReleaseFile(s.root, "../etc/passwd", []byte("x"), relSHA([]byte("x"))); err == nil {
		t.Fatal("a traversal must be refused")
	}
}

func TestWriteReleaseFileWillNotFollowASymlinkedDirectory(t *testing.T) {
	s := newRelSite(t)
	elsewhere := t.TempDir()
	// The web user swaps utils/ for a link to a directory it wants root to write in.
	if err := os.RemoveAll(filepath.Join(s.root, "public_html", "utils")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, filepath.Join(s.root, "public_html", "utils")); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteReleaseFile(s.root, "public_html/utils/upgrade.php", []byte(oldUpgrade), relSHA([]byte(oldUpgrade))); err == nil {
		t.Fatal("a symlinked directory must stop the write")
	}
	if entries, _ := os.ReadDir(elsewhere); len(entries) != 0 {
		t.Fatalf("nothing may land in the link's target, found %v", entries)
	}
}

func TestWriteReleaseFileKeepsModeAndRefusesANonRegularTarget(t *testing.T) {
	s := newRelSite(t)
	p := filepath.Join(s.root, "public_html", "utils", "upgrade.php")
	if err := os.Chmod(p, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteReleaseFile(s.root, "public_html/utils/upgrade.php", []byte(oldUpgrade), relSHA([]byte(oldUpgrade))); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o640 {
		t.Fatalf("the mode of the replaced file is kept, got %v", st.Mode().Perm())
	}
	// The file replaced by a symlink is refused, not followed.
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", p); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteReleaseFile(s.root, "public_html/utils/upgrade.php", []byte(oldUpgrade), relSHA([]byte(oldUpgrade))); err == nil {
		t.Fatal("a symlink where the file should be must be refused")
	}
}

func restoreParams(t *testing.T, file string) Params {
	t.Helper()
	p, _ := Lookup("restore_release_file")
	params, err := Validate(p.Params, map[string]interface{}{"file": file})
	if err != nil {
		t.Fatal(err)
	}
	return params
}

func TestRestoreReleaseFileNamesOnlyTheFive(t *testing.T) {
	p, ok := Lookup("restore_release_file")
	if !ok || p.Class != ClassOperate || p.Run == nil {
		t.Fatal("restore_release_file is an embedded operate word")
	}
	for _, bad := range []string{"public_html/index.php", "../etc/shadow", "", "public_html/utils/upgrade.php/../../x"} {
		if _, err := Validate(p.Params, map[string]interface{}{"file": bad}); err == nil {
			t.Errorf("file %q must be refused by the closed parameter", bad)
		}
	}
	for _, good := range SelfUpdateFiles {
		if _, err := Validate(p.Params, map[string]interface{}{"file": good}); err != nil {
			t.Errorf("%s should be accepted: %v", good, err)
		}
	}
}

func TestRestoreReleaseFileFromTheKeptCopy(t *testing.T) {
	s := newRelSite(t)
	if err := TakeReleaseSnapshot(s.env); err != nil {
		t.Fatal(err)
	}
	s.stoppedUpgrade()
	p, _ := Lookup("restore_release_file")
	res, err := p.Run(context.Background(), s.env, restoreParams(t, "public_html/utils/upgrade.php"))
	if err != nil || res["source"] != "kept copy" || res["replaced_kept"] != true {
		t.Fatalf("restore from the kept copy: %v err=%v", res, err)
	}
	if s.read("public_html/utils/upgrade.php") != oldUpgrade {
		t.Fatal("the file should be the signed one")
	}
}

func TestRestoreReleaseFileFromTheManagementNode(t *testing.T) {
	s := newRelSite(t)
	s.stoppedUpgrade() // no snapshot: a node already wedged
	var asked struct{ version, rel string }
	s.env.FetchReleaseFile = func(_ context.Context, version, rel string) ([]byte, error) {
		asked.version, asked.rel = version, rel
		return []byte(oldUpgrade), nil
	}
	p, _ := Lookup("restore_release_file")
	res, err := p.Run(context.Background(), s.env, restoreParams(t, "public_html/utils/upgrade.php"))
	if err != nil || res["source"] != "management node" {
		t.Fatalf("restore from the plane: %v err=%v", res, err)
	}
	if asked.version != "0.8.475" || asked.rel != "public_html/utils/upgrade.php" {
		t.Fatalf("the agent asks for the installed version and the named file, got %+v", asked)
	}
	if s.read("public_html/utils/upgrade.php") != oldUpgrade {
		t.Fatal("the file should be the signed one")
	}
}

func TestARestoreRefusesWrongBytesFromThePlane(t *testing.T) {
	s := newRelSite(t)
	s.stoppedUpgrade()
	s.env.FetchReleaseFile = func(context.Context, string, string) ([]byte, error) {
		return []byte("<?php // a hostile plane's idea of upgrade.php\n"), nil
	}
	p, _ := Lookup("restore_release_file")
	_, err := p.Run(context.Background(), s.env, restoreParams(t, "public_html/utils/upgrade.php"))
	if err == nil || !Refused(err) {
		t.Fatalf("bytes that are not the signed file must be refused, got %v", err)
	}
	if s.read("public_html/utils/upgrade.php") != "<?php // upgrade 0.8.477\n" {
		t.Fatal("the site tree must be untouched by a refused restore")
	}
}

func TestARestoreRefusesWhenThereIsNothingToRepairOrNoSource(t *testing.T) {
	s := newRelSite(t)
	p, _ := Lookup("restore_release_file")
	if _, err := p.Run(context.Background(), s.env, restoreParams(t, "public_html/utils/upgrade.php")); err == nil || !Refused(err) {
		t.Fatalf("a file that already matches is refused, got %v", err)
	}
	s.stoppedUpgrade()
	if _, err := p.Run(context.Background(), s.env, restoreParams(t, "public_html/utils/upgrade.php")); err == nil || !Refused(err) {
		t.Fatalf("no kept copy and no way to ask is refused, got %v", err)
	}
	s.env.FetchReleaseFile = func(context.Context, string, string) ([]byte, error) { return nil, errors.New("no archive") }
	if _, err := p.Run(context.Background(), s.env, restoreParams(t, "public_html/utils/upgrade.php")); err == nil || !Refused(err) {
		t.Fatalf("a plane with no archive is refused, got %v", err)
	}
}

func TestARestoreIsNotTheManifestHealersJob(t *testing.T) {
	s := newRelSite(t)
	s.stoppedUpgrade()
	if err := os.Remove(filepath.Join(s.root, "RELEASE_MANIFEST")); err != nil {
		t.Fatal(err)
	}
	p, _ := Lookup("restore_release_file")
	_, err := p.Run(context.Background(), s.env, restoreParams(t, "public_html/utils/upgrade.php"))
	if err == nil || !Refused(err) {
		t.Fatalf("with an unusable manifest nothing can be checked, so nothing is written: %v", err)
	}
}

func TestPreflightNamesWhatWouldStopAnUpgrade(t *testing.T) {
	s := newRelSite(t)
	p, _ := Lookup("upgrade_preflight")
	run := func() (bool, map[string]bool) {
		res, err := p.Run(context.Background(), s.env, Params{})
		if err != nil {
			t.Fatal(err)
		}
		checks := map[string]bool{}
		for _, c := range res["checks"].([]map[string]interface{}) {
			checks[c["check"].(string)] = c["ok"].(bool)
		}
		return res["ok"].(bool), checks
	}
	ok, checks := run()
	if !ok || len(checks) != 6 {
		t.Fatalf("a healthy node passes all six checks, got ok=%v %v", ok, checks)
	}
	s.stoppedUpgrade()
	if ok, checks := run(); ok || checks["files"] {
		t.Fatalf("a changed deployment file must fail the files check, got %v %v", ok, checks)
	}
	s = newRelSite(t)
	_ = os.Remove(filepath.Join(s.root, "public_html", "VERSION"))
	if ok, checks := run(); ok || checks["version"] {
		t.Fatalf("an unreadable VERSION must fail, got %v %v", ok, checks)
	}
}

// The agent runs outside the upgrade's process group, so a run that rewrites its
// own script and dies leaves the signed file behind it.
func TestTheGuardAroundApplyUpdateRestoresAfterAStoppedRun(t *testing.T) {
	if _, err := os.Stat("/usr/bin/php"); err != nil {
		t.Skip("php is not installed here")
	}
	s := newRelSite(t)
	script := `<?php
file_put_contents(__FILE__, "<?php // replaced by the upgrade\n");
file_put_contents(dirname(__DIR__) . "/includes/DeploymentHelper.php", "<?php // replaced too\n");
exit(1);
`
	s.write("public_html/utils/upgrade.php", script)
	s.sign()
	s.env.Manifest = NewArtifactManifests(s.root, s.pub)

	p, _ := Lookup("apply_update")
	if _, err := runScriptPrimitive(context.Background(), s.env, p, Params{}); err == nil {
		t.Fatal("the stopped run should report its error")
	}
	if s.read("public_html/utils/upgrade.php") != script {
		t.Fatalf("upgrade.php should be the signed file again, got %q", s.read("public_html/utils/upgrade.php"))
	}
	if s.read("public_html/includes/DeploymentHelper.php") != oldHelper {
		t.Fatal("the companion file should be back too")
	}
}

func TestTheGuardLeavesASuccessfulUpgradeAlone(t *testing.T) {
	if _, err := os.Stat("/usr/bin/php"); err != nil {
		t.Skip("php is not installed here")
	}
	s := newRelSite(t)
	// A run that deploys changes the VERSION. The manifest cannot be re-signed from
	// inside a script, so this checks the narrower claim: with the VERSION changed,
	// the guard writes nothing.
	s.write("public_html/utils/upgrade.php", `<?php
file_put_contents(dirname(__DIR__) . "/includes/DeploymentHelper.php", "<?php // 0.8.477\n");
file_put_contents(dirname(__DIR__) . "/VERSION", "0.8.477\n");
`)
	s.sign()
	s.env.Manifest = NewArtifactManifests(s.root, s.pub)
	p, _ := Lookup("apply_update")
	if _, err := runScriptPrimitive(context.Background(), s.env, p, Params{}); err != nil {
		t.Fatal(err)
	}
	if s.read("public_html/includes/DeploymentHelper.php") != "<?php // 0.8.477\n" {
		t.Fatal("when the VERSION changed a release went in, and the guard must not undo it")
	}
}
