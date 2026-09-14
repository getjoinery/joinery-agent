package primitives

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// host_converge is the second script word in run_plugin_installers' shape, and
// the first to pass the runner an argument. The tests are about that argument:
// that it is the compiled constant and nothing else, that no parameter exists
// through which the wire could touch it, and that a real process sees exactly
// one argv element equal to it.

func TestHostConvergeAsksForNothing(t *testing.T) {
	p, ok := Lookup("host_converge")
	if !ok {
		t.Fatal("host_converge should be registered")
	}
	if len(p.Params) != 0 {
		t.Fatalf("host_converge declares %d parameter(s); it must declare none — "+
			"the installer it runs is a compiled constant, not a choice the plane makes", len(p.Params))
	}
	if p.Class != ClassOperate {
		t.Errorf("host_converge is operate, not %q", p.Class)
	}
}

func TestHostConvergeRefusesEveryKeyACallerWouldReachFor(t *testing.T) {
	p, _ := Lookup("host_converge")

	// The names a caller would try in order to steer which installer runs,
	// or where. With no declared parameters every one of them is
	// out-of-vocabulary — refused here, not dropped somewhere downstream.
	for _, key := range []string{
		"installer", // "run this installer instead"
		"name",      //
		"only",      // the runner's own flag, as a field
		"args",      // an argv of the caller's choosing
		"site_root", // a tree of the caller's choosing
		"path",      //
		"script",    //
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

func TestHostConvergeArgvIsTheCompiledConstant(t *testing.T) {
	p, _ := Lookup("host_converge")

	if p.Script == nil {
		t.Fatal("host_converge should be a script primitive")
	}
	if p.Script.ScriptPath != pluginInstallersRunner {
		t.Errorf("should invoke the shipped runner %q, got %q", pluginInstallersRunner, p.Script.ScriptPath)
	}
	if p.Script.Interpreter != "/bin/bash" {
		t.Errorf("the runner is a bash script; interpreter is %q", p.Script.Interpreter)
	}

	// Exactly one element, and it is the constant. Compared element for
	// element rather than by length so a second element, or a different first
	// one, is named in the failure.
	if len(p.Script.Args) != 1 || p.Script.Args[0] != hostConvergeOnly {
		t.Fatalf("argv template should be exactly [%q], got %v — the installer name is a "+
			"compiled constant and the only thing this word may pass", hostConvergeOnly, p.Script.Args)
	}
	if !strings.HasPrefix(hostConvergeOnly, "--only=") {
		t.Errorf("the constant %q is not the runner's single-installer mode", hostConvergeOnly)
	}

	// No "{slot}" anywhere in the template, and no builder: a slot is the one
	// thing that would let a wire value reach argv, and a builder is the
	// other. Neither exists here, and the refused-keys test above is what
	// makes a slot pointless anyway — but the template is pinned on its own
	// so a slot cannot arrive in the same edit as a parameter.
	for _, element := range p.Script.Args {
		if strings.HasPrefix(element, "{") && strings.HasSuffix(element, "}") {
			t.Errorf("argv contains the slot %q — nothing on the wire may reach the runner's argv", element)
		}
	}
	if p.Script.ArgsFrom != nil {
		t.Error("host_converge composes no argv at run time; the template is the whole of it")
	}
	if p.Script.StdinFrom != nil {
		t.Error("the runner reads no stdin; supplying one opens a channel nothing needs")
	}
}

func TestHostConvergeRunnerIsVerifiedAgainstTheCoreManifest(t *testing.T) {
	// The same runner as run_plugin_installers, so the same manifest: it ships
	// in the core archive and must verify at the site root.
	if owner := owningArtifact(pluginInstallersRunner); owner != "" {
		t.Errorf("the runner resolved to artifact %q; it ships in the core archive and must "+
			"verify against the site-root manifest", owner)
	}
}

// --- End to end, against a signed tree ---------------------------------------

func runHostConverge(t *testing.T, root string, verifier ManifestVerifier) (map[string]interface{}, error) {
	t.Helper()
	env := &ExecEnv{
		SiteRoot: root,
		WebRoot:  filepath.Join(root, "public_html"),
		Manifest: verifier,
	}
	return Execute(context.Background(), env, ShippedPolicy(), Request{
		JobID:     1,
		Primitive: "host_converge",
	})
}

func TestTheRunnerReceivesExactlyTheOneArgument(t *testing.T) {
	// Asserted against a real process rather than the template: the framework
	// prepends the script path, and "one argument" means the runner sees $#
	// of one and $1 equal to the constant, with nothing after it.
	root, verifier := signedSiteRoot(t, "#!/bin/bash\necho \"argc=$# argv1=$1 argv2=$2\"\n")

	result, err := runHostConverge(t, root, verifier)
	if err != nil {
		t.Fatalf("a verified runner should execute: %v", err)
	}
	got := result["output"].(string)
	if !strings.Contains(got, "argc=1 argv1="+hostConvergeOnly+" argv2=") {
		t.Errorf("the runner should see exactly one argument, %q. Output: %q", hostConvergeOnly, got)
	}
}

func TestHostConvergeTranscriptIsTheRecord(t *testing.T) {
	// The runner is fail-safe zero: a failed installer, a refused one and a
	// lock it never got all exit 0. Every line it said, stdout and stderr,
	// has to reach the caller — that transcript is the only verdict there is.
	root, verifier := signedSiteRoot(t,
		"#!/bin/bash\n"+
			"echo 'core installers: running host_housekeeping.sh'\n"+
			"echo 'core installers: WARNING - host_housekeeping.sh failed' >&2\n"+
			"exit 0\n")

	result, err := runHostConverge(t, root, verifier)
	if err != nil {
		t.Fatalf("exit 0 is success at this layer: %v", err)
	}
	output, _ := result["output"].(string)
	if !strings.Contains(output, "running host_housekeeping.sh") {
		t.Error("stdout is missing from the result")
	}
	if !strings.Contains(output, "WARNING - host_housekeeping.sh failed") {
		t.Error("stderr is missing from the result — the failure is written there, " +
			"and it is the only signal a fail-safe runner gives")
	}
}

func TestAModifiedRunnerIsRefusedBeforeHostConvergeRunsAsRoot(t *testing.T) {
	root, verifier := signedSiteRoot(t, "#!/bin/bash\nexit 0\n")

	full := filepath.Join(root, filepath.FromSlash(pluginInstallersRunner))
	if err := os.WriteFile(full, []byte("#!/bin/bash\necho pwned\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	if _, err := runHostConverge(t, root, verifier); err == nil {
		t.Fatal("a runner that no longer matches its signed hash must not execute")
	} else if !Refused(err) {
		t.Errorf("a hash mismatch is a refusal, not a run that failed: %v", err)
	}
}
