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
)

// recovery_key_report answers the one question every backup on this node is
// gated on. What matters about its shape is that the plane cannot influence the
// answer: no parameters, one fixed mode, and the node's own shipped script.

func TestRecoveryKeyReportAsksForNothing(t *testing.T) {
	p, ok := Lookup("recovery_key_report")
	if !ok {
		t.Fatal("recovery_key_report should be registered")
	}
	if len(p.Params) != 0 {
		t.Fatalf("recovery_key_report declares %d parameter(s); it must declare none", len(p.Params))
	}
}

func TestRecoveryKeyReportIsObserveAndReportsOnly(t *testing.T) {
	p, _ := Lookup("recovery_key_report")

	// The class is the claim: asking a node which key it holds must never be
	// able to change which key it holds. set_recovery_key.php's write path was
	// removed for the same reason — a recovery key arriving from outside cannot
	// be verified by the site receiving it — and --report is the only mode left.
	if p.Class != ClassObserve {
		t.Errorf("recovery_key_report reads; it is observe, not %q", p.Class)
	}
	if p.Script == nil {
		t.Fatal("recovery_key_report should be a script primitive")
	}
	if len(p.Script.Args) != 1 || p.Script.Args[0] != "--report" {
		t.Errorf("argv should be exactly [--report], got %v — a mode the plane could choose "+
			"is a mode a compromised plane could choose", p.Script.Args)
	}
	if p.Script.Interpreter != "/usr/bin/php" {
		t.Errorf("the reporting tool is a PHP program; interpreter is %q", p.Script.Interpreter)
	}
	if p.Script.StdinFrom != nil {
		t.Error("the reporting tool reads no stdin")
	}
}

func TestRecoveryKeyReportRefusesWireSuppliedKeys(t *testing.T) {
	p, _ := Lookup("recovery_key_report")

	for _, key := range []string{
		"recovery_public_key", // the A4 substitution vector, in the operation that names the key
		"recovery_pub",        //
		"fingerprint",         // "tell me whether you hold THIS one"
		"set",                 //
		"mode",                // "--report, but let me pick"
		"path",                //
	} {
		if _, err := Validate(p.Params, map[string]interface{}{key: "anything"}); err == nil {
			t.Errorf("a job carrying %q must be refused; there is no pass-through", key)
		}
	}
}

func TestTheReportingToolIsVerifiedAgainstTheCoreManifest(t *testing.T) {
	p, _ := Lookup("recovery_key_report")

	// maintenance_scripts/ ships in the core archive, outside public_html.
	if owner := owningArtifact(p.Script.ScriptPath); owner != "" {
		t.Errorf("the reporting tool resolved to artifact %q; it must verify against the site-root manifest", owner)
	}
	if strings.HasPrefix(p.Script.ScriptPath, "/") {
		t.Error("the script path must be site-root relative, or it resolves outside the verified tree")
	}
}

// --- End to end, against a signed tree ---------------------------------------

func signedReporterRoot(t *testing.T, body string) (string, ManifestVerifier, string) {
	t.Helper()

	p, _ := Lookup("recovery_key_report")
	rel := p.Script.ScriptPath

	root := t.TempDir()
	full := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}

	sum := sha256.Sum256([]byte(body))
	manifest := []byte(hex.EncodeToString(sum[:]) + "  " + rel + "\n")

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewSignedTreeVerifier(root, manifest, ed25519.Sign(priv, manifest), pub)
	if err != nil {
		t.Fatal(err)
	}
	return root, verifier, full
}

func runRecoveryKeyReport(t *testing.T, root string, verifier ManifestVerifier) (map[string]interface{}, error) {
	t.Helper()
	env := &ExecEnv{
		SiteRoot: root,
		WebRoot:  filepath.Join(root, "public_html"),
		Manifest: verifier,
	}
	return Execute(context.Background(), env, ShippedPolicy(), Request{
		JobID:     1,
		Primitive: "recovery_key_report",
	})
}

func TestTheRECOVERYKEYLineReachesThePlane(t *testing.T) {
	// The plane parses this line to decide whether the node may be backed up at
	// all. Losing it does not read as an error; it reads as "not known yet", and
	// every backup then refuses.
	requirePHP(t)
	root, verifier, _ := signedReporterRoot(t,
		"<?php echo \"RECOVERY_KEY=proven 9c674ec8\\n\";\n")

	result, err := runRecoveryKeyReport(t, root, verifier)
	if err != nil {
		t.Fatalf("a verified reporting tool should execute: %v", err)
	}
	if !strings.Contains(result["output"].(string), "RECOVERY_KEY=proven") {
		t.Error("the RECOVERY_KEY line did not reach the result")
	}
}

func TestTheReportPassesOnlyTheReportFlag(t *testing.T) {
	requirePHP(t)
	root, verifier, _ := signedReporterRoot(t,
		"<?php echo 'argc=' . ($argc - 1) . ' argv1=' . ($argv[1] ?? '') . \"\\n\";\n")

	result, err := runRecoveryKeyReport(t, root, verifier)
	if err != nil {
		t.Fatalf("should execute: %v", err)
	}
	got := result["output"].(string)
	if !strings.Contains(got, "argc=1") || !strings.Contains(got, "argv1=--report") {
		t.Errorf("the reporting tool should receive exactly --report. Output: %q", got)
	}
}

func TestAModifiedReportingToolIsRefused(t *testing.T) {
	// It runs as root, and it sits in a tree the web user owns.
	root, verifier, full := signedReporterRoot(t, "<?php echo \"RECOVERY_KEY=none\\n\";\n")

	if err := os.WriteFile(full, []byte("<?php echo \"pwned\\n\";\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	if _, err := runRecoveryKeyReport(t, root, verifier); err == nil {
		t.Fatal("a reporting tool that no longer matches its signed hash must not execute")
	} else if !Refused(err) {
		t.Errorf("a hash mismatch is a refusal, not a run that failed: %v", err)
	}
}

func TestWithoutAManifestTheReportingToolDoesNotRun(t *testing.T) {
	root, _, _ := signedReporterRoot(t, "<?php echo \"RECOVERY_KEY=none\\n\";\n")

	if _, err := runRecoveryKeyReport(t, root, UnavailableVerifier{}); err == nil {
		t.Fatal("with nothing to verify against, it must not execute as root")
	} else if !Refused(err) {
		t.Errorf("an unverifiable script is refused, not attempted: %v", err)
	}
}

func TestTheReportRunsUnderTheDefaultTimeout(t *testing.T) {
	p, _ := Lookup("recovery_key_report")

	// It reads a key file and prints a line. Declaring nothing means it inherits
	// DefaultTimeout, which is the right answer — this asserts that a later edit
	// giving it a long one is deliberate rather than copied from a neighbour.
	if p.Timeout != DefaultTimeout {
		t.Errorf("recovery_key_report declares a %v timeout; reading one file needs no more "+
			"than the default %v", p.Timeout, DefaultTimeout)
	}
}
