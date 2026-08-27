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

// run_plugin_installers is the zero-parameter case, and the tests are about
// that: what it will not accept, that it asks for nothing at all, and that the
// output survives — because the script it runs cannot report failure any other
// way.

func TestRunPluginInstallersAsksForNothing(t *testing.T) {
	// The claim in one assertion. An empty parameter list is not a convenience;
	// it is the reason a compromised plane cannot influence this operation at
	// all. A later "just one small parameter" fails here.
	p, ok := Lookup("run_plugin_installers")
	if !ok {
		t.Fatal("run_plugin_installers should be registered")
	}
	if len(p.Params) != 0 {
		t.Fatalf("run_plugin_installers declares %d parameter(s); it must declare none — "+
			"the node knows its own name and can read its own credentials", len(p.Params))
	}
}

func TestNothingThePlaneSendsIsAccepted(t *testing.T) {
	p, _ := Lookup("run_plugin_installers")

	// The two the SSH builder used to send, plus the shapes a future caller
	// would reach for. With no declared parameters, every one of them is
	// out-of-vocabulary — refused here, not dropped somewhere downstream.
	for _, key := range []string{
		"sitename",    // the plane's belief about what this node is called
		"site_name",   //
		"web_root",    // the same belief, spelled as a path
		"pgpassword",  // the credential sudo used to drop
		"db_password", //
		"env",         //
		"extra_args",  //
		"plugin",      // "just run this one plugin's installer"
	} {
		if _, err := Validate(p.Params, map[string]interface{}{key: "anything"}); err == nil {
			t.Errorf("a job carrying %q must be refused; there is no pass-through", key)
		}
	}

	// And the empty object is the only thing that validates.
	if _, err := Validate(p.Params, nil); err != nil {
		t.Errorf("a job with no parameters is the only well-formed one, and it should validate: %v", err)
	}
}

func TestRunPluginInstallersInvokesTheShippedRunnerWithNoArgv(t *testing.T) {
	p, _ := Lookup("run_plugin_installers")

	if p.Class != ClassOperate {
		t.Errorf("run_plugin_installers is operate, not %q", p.Class)
	}
	if p.Script == nil {
		t.Fatal("run_plugin_installers should be a script primitive")
	}
	if p.Script.ScriptPath != pluginInstallersRunner {
		t.Errorf("should invoke the shipped runner %q, got %q", pluginInstallersRunner, p.Script.ScriptPath)
	}
	if p.Script.Interpreter != "/bin/bash" {
		t.Errorf("the runner is a bash script; interpreter is %q", p.Script.Interpreter)
	}
	if len(p.Script.Args) != 0 {
		t.Errorf("argv should be empty, got %v — an element here is a place for a wire value to appear", p.Script.Args)
	}
	if p.Script.StdinFrom != nil {
		t.Error("the runner reads no stdin; supplying one opens a channel nothing needs")
	}
}

func TestTheRunnerIsVerifiedAgainstTheCoreManifest(t *testing.T) {
	// It lives outside public_html and ships in the core archive, so it must
	// resolve to the manifest at the site root rather than to a plugin's. A
	// path that resolved to a plugin artifact would be verified by a manifest
	// that never listed it — which is to say, not verified.
	if owner := owningArtifact(pluginInstallersRunner); owner != "" {
		t.Errorf("the runner resolved to artifact %q; it ships in the core archive and must "+
			"verify against the site-root manifest", owner)
	}
}

// --- End to end, against a signed tree ---------------------------------------

// signedSiteRoot builds a temp site root holding one script at
// pluginInstallersRunner, with a manifest signed by a throwaway key, and
// returns the root and a verifier for it.
func signedSiteRoot(t *testing.T, body string) (string, ManifestVerifier) {
	t.Helper()

	root := t.TempDir()
	full := filepath.Join(root, filepath.FromSlash(pluginInstallersRunner))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}

	sum := sha256.Sum256([]byte(body))
	manifest := []byte(hex.EncodeToString(sum[:]) + "  " + pluginInstallersRunner + "\n")

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

func runInstallers(t *testing.T, root string, verifier ManifestVerifier) (map[string]interface{}, error) {
	t.Helper()
	env := &ExecEnv{
		SiteRoot: root,
		WebRoot:  filepath.Join(root, "public_html"),
		Manifest: verifier,
	}
	return Execute(context.Background(), env, ShippedPolicy(), Request{
		JobID:     1,
		Primitive: "run_plugin_installers",
	})
}

func TestTheRunnerReceivesNoArgumentsAtAll(t *testing.T) {
	// Argv emptiness asserted against a real process rather than against the
	// template: the framework prepends the script path, and "no arguments"
	// means the runner sees $# of zero.
	root, verifier := signedSiteRoot(t, "#!/bin/bash\necho \"argc=$#\"\n")

	result, err := runInstallers(t, root, verifier)
	if err != nil {
		t.Fatalf("a verified runner should execute: %v", err)
	}
	if got := result["output"].(string); !strings.Contains(got, "argc=0") {
		t.Errorf("the runner was passed arguments; it should receive none. Output: %q", got)
	}
}

func TestTheOutputIsTheRecordEvenOnASilentSuccess(t *testing.T) {
	// The runner is fail-safe by contract: an inactive plugin, an unreachable
	// database and a failed installer all exit 0. A zero exit therefore proves
	// nothing, and every byte the script said — stdout AND stderr — has to reach
	// the caller or the job is unreadable.
	root, verifier := signedSiteRoot(t,
		"#!/bin/bash\necho 'plugin installers: mailbox: ok'\n"+
			"echo 'plugin installers: no active plugins found (or database unreachable) - skipping' >&2\n"+
			"exit 0\n")

	result, err := runInstallers(t, root, verifier)
	if err != nil {
		t.Fatalf("exit 0 is success: %v", err)
	}
	output, _ := result["output"].(string)
	if !strings.Contains(output, "mailbox: ok") {
		t.Error("stdout is missing from the result")
	}
	if !strings.Contains(output, "database unreachable") {
		t.Error("stderr is missing from the result — the skip reasons are written there, " +
			"and they are the only signal a fail-safe script gives")
	}
	if result["output_bytes"] == nil {
		t.Error("the result should report how much the script said, so a truncated run is visible")
	}
}

func TestOutputSurvivesAFailingRunner(t *testing.T) {
	// The one case where the exit code does say something. It must not cost the
	// output, which is where the reason is.
	root, verifier := signedSiteRoot(t, "#!/bin/bash\necho 'core installers: WARNING' >&2\nexit 3\n")

	result, err := runInstallers(t, root, verifier)
	if err == nil {
		t.Fatal("a non-zero exit should surface as an error")
	}
	if Refused(err) {
		t.Error("a script that ran and failed is a failure, not a node refusal")
	}
	if result == nil || !strings.Contains(result["output"].(string), "WARNING") {
		t.Error("the output must come back with the failure; it is where the reason is")
	}
}

func TestAModifiedRunnerIsRefusedBeforeItRunsAsRoot(t *testing.T) {
	// The site tree is writable by the web user while the agent is root. This is
	// the assertion that a web-layer compromise does not become root the next
	// time an operator clicks Run Plugin Installers.
	root, verifier := signedSiteRoot(t, "#!/bin/bash\nexit 0\n")

	full := filepath.Join(root, filepath.FromSlash(pluginInstallersRunner))
	if err := os.WriteFile(full, []byte("#!/bin/bash\necho pwned\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	if _, err := runInstallers(t, root, verifier); err == nil {
		t.Fatal("a runner that no longer matches its signed hash must not execute")
	} else if !Refused(err) {
		t.Errorf("a hash mismatch is a refusal, not a run that failed: %v", err)
	}
}

func TestWithoutAManifestTheRunnerDoesNotRun(t *testing.T) {
	// The Phase 1 production state, and the fail-closed default: no manifest
	// means unavailable, never "unverified but go ahead".
	root, _ := signedSiteRoot(t, "#!/bin/bash\nexit 0\n")

	if _, err := runInstallers(t, root, UnavailableVerifier{}); err == nil {
		t.Fatal("with nothing to verify against, the runner must not execute as root")
	} else if !Refused(err) {
		t.Errorf("an unverifiable script is refused, not attempted: %v", err)
	}
}
