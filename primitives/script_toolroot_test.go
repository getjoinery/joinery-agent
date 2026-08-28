package primitives

import (
	"context"
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
