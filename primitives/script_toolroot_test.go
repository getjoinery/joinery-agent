package primitives

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A machine with no site tree resolves its scripts against the signed support
// bundle instead. These pin the three states that machine can be in, because
// the failure modes point in opposite directions: a bundle consulted where a
// site exists would be a second answer to "may this run as root", and a bundle
// NOT consulted where there is no site leaves the whole siteless posture with
// an empty vocabulary — which is the constraint the bundle exists to remove.

// recordingVerifier accepts one path and records what it was asked about, so a
// test can tell which tree the resolution actually used rather than inferring
// it from an error message.
type recordingVerifier struct {
	accept string
	asked  []string
}

func (v *recordingVerifier) Verify(path string) error {
	v.asked = append(v.asked, path)
	if path == v.accept {
		return nil
	}
	return errNotThisTree
}

var errNotThisTree = &RefusalError{Reason: "not listed in this tree"}

func toolScriptPrimitive() Primitive {
	return Primitive{
		Name:   "proof_only_toolroot",
		Class:  ClassOperate,
		Script: &ScriptSpec{Interpreter: "/bin/bash", ScriptPath: "maintenance_scripts/sysadmin_tools/setup_ssl.sh"},
	}
}

func writeScript(t *testing.T, root, rel string) string {
	t.Helper()
	full := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte("#!/bin/bash\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return full
}

func TestASitelessMachineResolvesScriptsAgainstTheBundle(t *testing.T) {
	toolRoot := t.TempDir()
	p := toolScriptPrimitive()
	scriptPath := writeScript(t, toolRoot, p.Script.ScriptPath)

	verifier := &recordingVerifier{accept: scriptPath}
	env := &ExecEnv{ToolRoot: toolRoot, ToolManifest: verifier}

	params, _ := Validate(nil, nil)
	if _, err := runScriptPrimitive(context.Background(), env, p, params); err != nil {
		t.Fatalf("a bundle-verified script must run on a machine with no site: %v", err)
	}
	if len(verifier.asked) != 1 || verifier.asked[0] != scriptPath {
		t.Fatalf("the bundle's own manifest should have been asked about %s; it was asked about %v",
			scriptPath, verifier.asked)
	}
}

// The site root wins wherever there is one. Nothing about the nine machines in
// the field changes in this release, and this is the check that says so.
func TestASiteRootWinsOverABundle(t *testing.T) {
	siteRoot, toolRoot := t.TempDir(), t.TempDir()
	p := toolScriptPrimitive()
	siteScript := writeScript(t, siteRoot, p.Script.ScriptPath)
	writeScript(t, toolRoot, p.Script.ScriptPath)

	siteVerifier := &recordingVerifier{accept: siteScript}
	toolVerifier := &recordingVerifier{accept: filepath.Join(toolRoot, filepath.FromSlash(p.Script.ScriptPath))}
	env := &ExecEnv{SiteRoot: siteRoot, Manifest: siteVerifier, ToolRoot: toolRoot, ToolManifest: toolVerifier}

	params, _ := Validate(nil, nil)
	if _, err := runScriptPrimitive(context.Background(), env, p, params); err != nil {
		t.Fatalf("the site tree's own script must run: %v", err)
	}
	if len(toolVerifier.asked) != 0 {
		t.Errorf("the bundle was consulted on a machine that has a site tree: %v", toolVerifier.asked)
	}
}

// And a site tree that does not list the script is a refusal, NOT a reason to
// go looking in the bundle. Falling through would mean being listed in some
// manifest is as good as being listed in the one that owns the file — the
// cross-manifest fallback ArtifactManifests refuses for the same reason.
func TestASiteTreeRefusalDoesNotFallThroughToTheBundle(t *testing.T) {
	siteRoot, toolRoot := t.TempDir(), t.TempDir()
	p := toolScriptPrimitive()
	writeScript(t, siteRoot, p.Script.ScriptPath)
	toolScript := writeScript(t, toolRoot, p.Script.ScriptPath)

	siteVerifier := &recordingVerifier{accept: "nothing at all"}
	toolVerifier := &recordingVerifier{accept: toolScript}
	env := &ExecEnv{SiteRoot: siteRoot, Manifest: siteVerifier, ToolRoot: toolRoot, ToolManifest: toolVerifier}

	params, _ := Validate(nil, nil)
	_, err := runScriptPrimitive(context.Background(), env, p, params)
	if !Refused(err) {
		t.Fatalf("a script the site's manifest does not list must be refused; got %v", err)
	}
	if len(toolVerifier.asked) != 0 {
		t.Errorf("the refusal fell through to the bundle: %v", toolVerifier.asked)
	}
}

// A machine with neither refuses exactly as it always did — the bundle removes
// the constraint only where a bundle actually arrived.
func TestAMachineWithNoTreeAtAllStillRefuses(t *testing.T) {
	p := toolScriptPrimitive()
	params, _ := Validate(nil, nil)

	_, err := runScriptPrimitive(context.Background(), &ExecEnv{}, p, params)
	if !Refused(err) {
		t.Fatalf("no site root and no bundle must refuse; got %v", err)
	}
	if !strings.Contains(err.Error(), "support bundle") {
		t.Errorf("the refusal should say a bundle would have answered; got %q", err)
	}
}

// A bundle root with no verifier behind it must refuse rather than run: an
// unpacked tree nothing has checked is exactly what the manifest gate exists to
// keep away from a root process.
func TestABundleRootWithoutAVerifierRefuses(t *testing.T) {
	toolRoot := t.TempDir()
	p := toolScriptPrimitive()
	writeScript(t, toolRoot, p.Script.ScriptPath)

	params, _ := Validate(nil, nil)
	_, err := runScriptPrimitive(context.Background(), &ExecEnv{ToolRoot: toolRoot}, p, params)
	if !Refused(err) {
		t.Fatalf("a bundle with no verifier must refuse; got %v", err)
	}
	if !strings.Contains(err.Error(), "manifest verifier") {
		t.Errorf("the refusal should name the missing verifier; got %q", err)
	}
}

// fixedErrVerifier refuses every path with one chosen error, so a test can
// hand the runner the exact refusal a real verifier would make and read what
// the runner says about it.
type fixedErrVerifier struct{ err error }

func (v fixedErrVerifier) Verify(string) error { return v.err }

// The support bundle carries the host installers and nothing that reads a
// site. A site-only primitive dispatched to a machine with no site therefore
// asks for a script the bundle was never meant to list — a posture, not a
// file that fails its release. The refusal names the posture, in words the
// plane does not read as a trust event (docker-prod, 2026-09-15: the plane
// coloured the host as tampered with over recovery_key_report).
func TestASitelessMachineNamesItsPostureForAScriptTheBundleDoesNotCarry(t *testing.T) {
	p := toolScriptPrimitive()
	env := &ExecEnv{
		ToolRoot:     t.TempDir(),
		ToolManifest: fixedErrVerifier{&NotInManifestError{Rel: p.Script.ScriptPath}},
	}
	params, _ := Validate(nil, nil)
	_, err := runScriptPrimitive(context.Background(), env, p, params)
	if !Refused(err) {
		t.Fatalf("a script the bundle does not carry must be refused; got %v", err)
	}
	msg := err.Error()
	for _, want := range []string{"has no site", "support bundle does not carry " + p.Script.ScriptPath} {
		if !strings.Contains(msg, want) {
			t.Errorf("the refusal should say %q; got %q", want, msg)
		}
	}
	for _, trust := range []string{"signed release manifest", "signed hash", "modified since release", "verified before running as root"} {
		if strings.Contains(msg, trust) {
			t.Errorf("the refusal must not carry the trust-event wording %q; got %q", trust, msg)
		}
	}
}

// A file the bundle DOES list and that does not match is the mismatch it is,
// on a siteless machine as on any other: the posture wording is for a script
// the bundle never carried, never for one it carries and cannot vouch for.
func TestABundleFileThatDoesNotMatchStaysAMismatch(t *testing.T) {
	p := toolScriptPrimitive()
	mismatch := "file does not match its signed hash — it has been modified since release: " + p.Script.ScriptPath
	env := &ExecEnv{ToolRoot: t.TempDir(), ToolManifest: fixedErrVerifier{errors.New(mismatch)}}
	params, _ := Validate(nil, nil)
	_, err := runScriptPrimitive(context.Background(), env, p, params)
	if !Refused(err) || !strings.Contains(err.Error(), mismatch) {
		t.Fatalf("a listed file that does not match must refuse with the mismatch itself; got %v", err)
	}
	if strings.Contains(err.Error(), "has no site") {
		t.Errorf("a mismatch is not a posture; got %q", err)
	}
}

// On a site tree an unlisted file is a stranger in a root-run path, and the
// plane reads exactly this wording as one. Nothing about the siteless refusal
// may leak into it.
func TestASiteMachineStillReportsAnUnlistedFileAsUnlisted(t *testing.T) {
	p := toolScriptPrimitive()
	env := &ExecEnv{
		SiteRoot: t.TempDir(),
		Manifest: fixedErrVerifier{&NotInManifestError{Rel: p.Script.ScriptPath}},
		// A bundle beside a site changes nothing: the site's answer is the answer.
		ToolRoot:     t.TempDir(),
		ToolManifest: fixedErrVerifier{errors.New("never consulted")},
	}
	params, _ := Validate(nil, nil)
	_, err := runScriptPrimitive(context.Background(), env, p, params)
	if !Refused(err) {
		t.Fatalf("expected a refusal; got %v", err)
	}
	if !strings.Contains(err.Error(), "file is not in the signed release manifest: "+p.Script.ScriptPath) {
		t.Errorf("a site tree's unlisted file keeps its wording; got %q", err)
	}
	if strings.Contains(err.Error(), "has no site") {
		t.Errorf("a site machine must never claim to have no site; got %q", err)
	}
}

// The signed-tree verifier reports an unlisted file as the typed error the
// runner reads, with the wording the plane matches unchanged.
func TestAnUnlistedFileIsATypedRefusalWithThePlanesWording(t *testing.T) {
	root := t.TempDir()
	v := &SignedTreeVerifier{Root: root, Hashes: map[string]string{}}
	stranger := writeScript(t, root, "public_html/utils/stranger.php")
	err := v.Verify(stranger)
	var missing *NotInManifestError
	if !errors.As(err, &missing) {
		t.Fatalf("an unlisted file must be a NotInManifestError; got %T %v", err, err)
	}
	if missing.Rel != "public_html/utils/stranger.php" {
		t.Errorf("the error names the tree-relative path; got %q", missing.Rel)
	}
	if err.Error() != "file is not in the signed release manifest: public_html/utils/stranger.php" {
		t.Errorf("the plane matches this wording; got %q", err.Error())
	}
}

// ScriptTree is the one place the choice of tree is made. Pinned so the runner
// and the node's poll-time trust report can never disagree about which tree
// they mean.
func TestScriptTreeIsTheSiteWhereThereIsOneAndTheBundleOtherwise(t *testing.T) {
	site, bundle := fixedErrVerifier{errors.New("site")}, fixedErrVerifier{errors.New("bundle")}
	root, v := (&ExecEnv{SiteRoot: "/srv/site", Manifest: site, ToolRoot: "/opt/tree", ToolManifest: bundle}).ScriptTree()
	if root != "/srv/site" || v != ManifestVerifier(site) {
		t.Errorf("a site wins: got %q %v", root, v)
	}
	root, v = (&ExecEnv{ToolRoot: "/opt/tree", ToolManifest: bundle}).ScriptTree()
	if root != "/opt/tree" || v != ManifestVerifier(bundle) {
		t.Errorf("no site means the bundle: got %q %v", root, v)
	}
	if root, _ := (&ExecEnv{}).ScriptTree(); root != "" {
		t.Errorf("neither means no tree: got %q", root)
	}
	if root, v := (*ExecEnv)(nil).ScriptTree(); root != "" || v != nil {
		t.Errorf("a nil env has no tree")
	}
}
