package primitives

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// apply_update is the operation the fleet uses most, and the one where getting
// the boundary wrong costs the most: it runs the platform upgrader as root, and
// the upgrader restarts the very process running it. These tests pin the shape
// (nothing wire-supplied, the shipped upgrader, verified against core's
// manifest) and the two numbers the transport depends on.

func TestApplyUpdateAsksForNothing(t *testing.T) {
	// A node upgrades from the source it is configured with. The plane naming a
	// version, a URL, or a tree would be the plane deciding what code runs as
	// root on someone else's machine.
	p, ok := Lookup("apply_update")
	if !ok {
		t.Fatal("apply_update should be registered")
	}
	if len(p.Params) != 0 {
		t.Fatalf("apply_update declares %d parameter(s); it must declare none", len(p.Params))
	}
}

func TestApplyUpdateRefusesEveryWireSuppliedKey(t *testing.T) {
	p, _ := Lookup("apply_update")

	for _, key := range []string{
		"web_root",       // what the SSH string carried, as the plane believed it
		"site_root",      //
		"version",        // "upgrade to this release"
		"target_version", //
		"source",         // "upgrade from this server"
		"upgrade_url",    //
		"args",           // the flag list, as something the plane could extend
		"extra_args",     //
		"force",          //
		"skip_tests",     // the one that would matter most, and the one to be sure of
	} {
		if _, err := Validate(p.Params, map[string]interface{}{key: "anything"}); err == nil {
			t.Errorf("a job carrying %q must be refused; there is no pass-through", key)
		}
	}

	if _, err := Validate(p.Params, nil); err != nil {
		t.Errorf("a job with no parameters is the only well-formed one: %v", err)
	}
}

func TestApplyUpdateInvokesTheShippedUpgraderVerbosely(t *testing.T) {
	p, _ := Lookup("apply_update")

	if p.Class != ClassOperate {
		t.Errorf("apply_update is operate, not %q", p.Class)
	}
	if p.Script == nil {
		t.Fatal("apply_update should be a script primitive")
	}
	if p.Script.ScriptPath != upgradeScript {
		t.Errorf("should invoke %q, got %q", upgradeScript, p.Script.ScriptPath)
	}
	if p.Script.Interpreter != "/usr/bin/php" {
		t.Errorf("the upgrader is a PHP program; interpreter is %q", p.Script.Interpreter)
	}
	// --verbose is not decoration. JobResultProcessor::halted_at_self_update
	// reads the transcript to tell an upgrade that stopped to refresh its own
	// deployment tooling from one that simply did not reach the target version,
	// and those two need different remedies.
	if len(p.Script.Args) != 1 || p.Script.Args[0] != "--verbose" {
		t.Errorf("argv should be exactly [--verbose], got %v", p.Script.Args)
	}
	for _, arg := range p.Script.Args {
		if strings.HasPrefix(arg, "{") {
			t.Errorf("argv element %q is a parameter slot; every argument here is fixed", arg)
		}
	}
	if p.Script.StdinFrom != nil {
		t.Error("the upgrader reads no stdin; supplying one opens a channel nothing needs")
	}
}

func TestApplyUpdateIsVerifiedAgainstTheCoreManifest(t *testing.T) {
	// utils/ ships in the core archive. Resolving to a plugin artifact would
	// mean verification by a manifest that never listed the file.
	if owner := owningArtifact(upgradeScript); owner != "" {
		t.Errorf("the upgrader resolved to artifact %q; it must verify against the site-root manifest", owner)
	}
}

func TestApplyUpdateClaimsEnoughTimeForAWholeUpgrade(t *testing.T) {
	p, _ := Lookup("apply_update")

	// An upgrade downloads, deploys, migrates, runs the deploy-tier suite and
	// then every host installer. The default five minutes would kill it partway
	// through deploying a release, which is the single worst moment to be
	// killed — so the declaration is asserted here rather than left to review.
	if p.Timeout <= DefaultTimeout {
		t.Fatalf("apply_update runs on the default %v timeout; it must declare its own", DefaultTimeout)
	}
	if p.Timeout < 45*time.Minute {
		t.Errorf("apply_update allows %v; an upgrade with the test suite riding along needs longer", p.Timeout)
	}
	if p.Timeout > MaxTimeout {
		t.Errorf("apply_update declares %v, above the %v ceiling", p.Timeout, MaxTimeout)
	}
}

// --- End to end, against a signed tree ---------------------------------------

// signedUpgraderRoot builds a temp site root holding one script at
// upgradeScript, with a manifest signed by a throwaway key.
func signedUpgraderRoot(t *testing.T, body string) (string, ManifestVerifier) {
	t.Helper()

	root := t.TempDir()
	full := filepath.Join(root, filepath.FromSlash(upgradeScript))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}

	sum := sha256.Sum256([]byte(body))
	manifest := []byte(hex.EncodeToString(sum[:]) + "  " + upgradeScript + "\n")

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewSignedTreeVerifier(root, manifest, ed25519.Sign(priv, manifest), pub)
	if err != nil {
		t.Fatal(err)
	}
	return root, verifier
}

func runApplyUpdate(t *testing.T, root string, verifier ManifestVerifier) (map[string]interface{}, error) {
	t.Helper()
	env := &ExecEnv{
		SiteRoot: root,
		WebRoot:  filepath.Join(root, "public_html"),
		Manifest: verifier,
	}
	return Execute(context.Background(), env, ShippedPolicy(), Request{
		JobID:     1,
		Primitive: "apply_update",
	})
}

// requirePHP skips a test on a machine with no PHP at the compiled-in
// interpreter path. The end-to-end tests below run the real interpreter rather
// than substituting a shell, because substituting one would mean mutating the
// registered primitive — and the registry being immutable at runtime is a
// property worth more than the convenience.
func requirePHP(t *testing.T) {
	t.Helper()
	p, _ := Lookup("apply_update")
	if _, err := os.Stat(p.Script.Interpreter); err != nil {
		t.Skipf("no interpreter at %s on this machine", p.Script.Interpreter)
	}
}

func TestApplyUpdatePassesOnlyTheVerboseFlag(t *testing.T) {
	// Asserted against a real process: the framework prepends the script path,
	// so "one fixed flag" means the program sees exactly two argv entries — its
	// own name and --verbose.
	requirePHP(t)
	root, verifier := signedUpgraderRoot(t,
		"<?php echo 'argc=' . ($argc - 1) . ' argv1=' . ($argv[1] ?? '') . \"\\n\";\n")

	result, err := runApplyUpdate(t, root, verifier)
	if err != nil {
		t.Fatalf("a verified upgrader should execute: %v", err)
	}
	got := result["output"].(string)
	if !strings.Contains(got, "argc=1") || !strings.Contains(got, "argv1=--verbose") {
		t.Errorf("the upgrader should receive exactly --verbose. Output: %q", got)
	}
}

func TestTheUpgradeTranscriptSurvivesToTheResult(t *testing.T) {
	// The plane reads this transcript for the two-pass case. Losing it turns a
	// "run it again" into an unexplained failure.
	requirePHP(t)
	root, verifier := signedUpgraderRoot(t,
		"<?php echo \"Deploying files\\nPLEASE RE-RUN THE UPGRADE\\n\";\n")

	result, err := runApplyUpdate(t, root, verifier)
	if err != nil {
		t.Fatalf("exit 0 is success: %v", err)
	}
	if !strings.Contains(result["output"].(string), "PLEASE RE-RUN THE UPGRADE") {
		t.Error("the marker the plane parses did not reach the result")
	}
}

func TestAModifiedUpgraderIsRefusedBeforeItRunsAsRoot(t *testing.T) {
	// upgrade.php sits in public_html, which the web user owns on every node
	// (fix_permissions production mode chowns the whole tree to www-data). This
	// is the assertion that a web-layer compromise does not become root the next
	// time an operator clicks Apply Update.
	root, verifier := signedUpgraderRoot(t, "#!/bin/bash\nexit 0\n")

	full := filepath.Join(root, filepath.FromSlash(upgradeScript))
	if err := os.WriteFile(full, []byte("#!/bin/bash\necho pwned\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	if _, err := runApplyUpdate(t, root, verifier); err == nil {
		t.Fatal("an upgrader that no longer matches its signed hash must not execute")
	} else if !Refused(err) {
		t.Errorf("a hash mismatch is a refusal, not a run that failed: %v", err)
	}
}

func TestWithoutAManifestTheUpgraderDoesNotRun(t *testing.T) {
	root, _ := signedUpgraderRoot(t, "#!/bin/bash\nexit 0\n")

	if _, err := runApplyUpdate(t, root, UnavailableVerifier{}); err == nil {
		t.Fatal("with nothing to verify against, the upgrader must not execute as root")
	} else if !Refused(err) {
		t.Errorf("an unverifiable script is refused, not attempted: %v", err)
	}
}
