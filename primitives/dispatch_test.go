package primitives

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// testEnv is an execution environment with no database and a verifier that
// refuses, which is production's Phase 1 posture.
func testEnv(t *testing.T) *ExecEnv {
	t.Helper()
	return &ExecEnv{SiteRoot: t.TempDir(), Manifest: UnavailableVerifier{}}
}

func openPolicy() *Policy {
	return &Policy{Accept: []Class{ClassObserve, ClassOperate}, source: "the test policy"}
}

func TestUnknownPrimitiveIsRefusedNotFailed(t *testing.T) {
	_, err := Execute(context.Background(), testEnv(t), openPolicy(),
		Request{JobID: 1, Primitive: "rm_rf_slash"})
	if !Refused(err) {
		t.Fatalf("an unknown primitive must be REFUSED (a decision), got %v", err)
	}
	if !strings.Contains(err.Error(), "compiled in") {
		t.Errorf("the refusal should say why the vocabulary cannot be extended; got %q", err)
	}
}

// A plane that sends a shell command by any name gets the same answer as a
// plane that sends gibberish: there is nothing on the node that runs strings.
func TestWireStringsAreNeverExecuted(t *testing.T) {
	for _, name := range []string{"exec", "run_command", "shell", "bash", "eval"} {
		if _, ok := Lookup(name); ok {
			t.Fatalf("the vocabulary contains %q — arbitrary execution must not exist in it at all (A1)", name)
		}
		_, err := Execute(context.Background(), testEnv(t), openPolicy(), Request{Primitive: name})
		if !Refused(err) {
			t.Errorf("primitive %q: expected refusal, got %v", name, err)
		}
	}
}

func TestPolicyRefusalIsRecordedWithAReason(t *testing.T) {
	observeOnly := &Policy{Accept: []Class{ClassObserve}, source: "the test policy"}
	if err := observeOnly.Accepts(ClassOperate); !Refused(err) {
		t.Fatalf("expected a refusal for an unaccepted class, got %v", err)
	} else if !strings.Contains(err.Error(), "the test policy") {
		t.Errorf("a refusal must name the policy that caused it; got %q", err)
	}
	if err := observeOnly.Accepts(ClassObserve); err != nil {
		t.Errorf("an accepted class must not be refused: %v", err)
	}
}

// Accepting the destructive CLASS means "this node is willing to be asked", and
// nothing more. The thing that actually decides is in Execute, and this pins the
// division: a policy that accepts destructive still cannot get a restore run.
func TestAcceptingDestructiveIsNotPermissionToRun(t *testing.T) {
	permissive := &Policy{
		Accept: []Class{ClassObserve, ClassOperate, ClassDestructive},
		source: "a policy file that allows destructive work",
	}
	if err := permissive.Accepts(ClassDestructive); err != nil {
		t.Fatalf("a policy that lists destructive should accept the class: %v", err)
	}

	// And a node with that policy, with no way to ask its operator, still runs
	// nothing. This is the assertion that matters — if it ever passes because
	// the restore RAN, the whole mechanism is gone.
	env := restoreEnv(t)
	env.Approval = nil
	_, err := Execute(context.Background(), env, permissive, Request{
		JobID: 1, Primitive: "restore_database", Params: map[string]interface{}{},
	})
	if !Refused(err) {
		t.Fatalf("destructive work must never run unapproved (A2), got %v", err)
	}
	if !strings.Contains(err.Error(), "approve") {
		t.Errorf("the refusal should say the node cannot ask; got %q", err)
	}
}

// A node that leaves destructive out of its own policy file refuses at the
// class, before anything is asked of anyone. That is the opt-out, and it wins.
func TestAPolicyWithoutDestructiveRefusesOutright(t *testing.T) {
	quiet := &Policy{
		Accept: []Class{ClassObserve, ClassOperate},
		source: "a policy file that wants no destructive work at all",
	}
	err := quiet.Accepts(ClassDestructive)
	if !Refused(err) {
		t.Fatalf("a policy without destructive must refuse it, got %v", err)
	}
	if !strings.Contains(err.Error(), "wants no destructive work") {
		t.Errorf("the refusal must name the policy that caused it; got %q", err)
	}
}

func TestScriptPrimitiveRefusesWithoutAVerifiedManifest(t *testing.T) {
	// Registered here rather than in the shipped vocabulary: it exists to prove
	// the gate holds, and the pin test would (correctly) reject an unpinned
	// shipped primitive.
	p := Primitive{
		Name:   "proof_only_script",
		Class:  ClassOperate,
		Script: &ScriptSpec{Interpreter: "/usr/bin/php", ScriptPath: "public_html/utils/upgrade.php"},
	}

	env := testEnv(t)
	scriptDir := filepath.Join(env.SiteRoot, "public_html", "utils")
	if err := os.MkdirAll(scriptDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(scriptDir, "upgrade.php"), []byte("<?php echo 1;"), 0o644); err != nil {
		t.Fatal(err)
	}

	params, err := Validate(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = runScriptPrimitive(context.Background(), env, p, params)
	if !Refused(err) {
		t.Fatalf("a script that cannot be verified must be refused, not run; got %v", err)
	}
	if !strings.Contains(err.Error(), "manifest") {
		t.Errorf("the refusal should name the missing manifest; got %q", err)
	}
}

func TestScriptPrimitiveRefusesWhenTheEnvironmentHasNoVerifier(t *testing.T) {
	p := Primitive{Name: "proof_only_script2", Class: ClassOperate,
		Script: &ScriptSpec{Interpreter: "/bin/echo", ScriptPath: "x.sh"}}
	params, _ := Validate(nil, nil)
	_, err := runScriptPrimitive(context.Background(), &ExecEnv{SiteRoot: "/tmp"}, p, params)
	if !Refused(err) {
		t.Fatalf("no verifier at all must refuse, not fall through to running; got %v", err)
	}
}

func TestArgvTemplateNeverConcatenates(t *testing.T) {
	specs := []ParamSpec{
		{Name: "archive", Type: ParamString, Pattern: regexp.MustCompile(`^[A-Za-z0-9._-]+$`)},
		{Name: "keep", Type: ParamInt, Min: 1, Max: 99},
	}
	params, err := Validate(specs, map[string]interface{}{"archive": "backup-2026.tar.gz", "keep": float64(7)})
	if err != nil {
		t.Fatal(err)
	}
	argv, err := resolveArgs([]string{"--archive", "{archive}", "--keep", "{keep}", "--absent", "{missing}"}, params)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"--archive", "backup-2026.tar.gz", "--keep", "7", "--absent"}
	if len(argv) != len(want) {
		t.Fatalf("argv = %q, want %q", argv, want)
	}
	for i := range want {
		if argv[i] != want[i] {
			t.Fatalf("argv = %q, want %q", argv, want)
		}
	}
}

// A parameter carrying shell syntax stays one argv element. It is refused
// earlier by the pattern, but the template must not be the thing relied on.
func TestShellSyntaxInAParameterStaysOneArgument(t *testing.T) {
	specs := []ParamSpec{{Name: "label", Type: ParamString}}
	params, err := Validate(specs, map[string]interface{}{"label": "a; rm -rf / #"})
	if err != nil {
		t.Fatal(err)
	}
	argv, err := resolveArgs([]string{"--label", "{label}"}, params)
	if err != nil {
		t.Fatal(err)
	}
	if len(argv) != 2 || argv[1] != "a; rm -rf / #" {
		t.Fatalf("argv = %q — a parameter must remain exactly one argument", argv)
	}
}

func TestCheckStatusIsObserveAndTakesNoParams(t *testing.T) {
	p, ok := Lookup("check_status")
	if !ok {
		t.Fatal("check_status is not registered")
	}
	if p.Class != ClassObserve {
		t.Errorf("check_status must be an observe primitive, got %q", p.Class)
	}
	if p.Script != nil {
		t.Error("check_status must be embedded — it collects without running anything")
	}
	_, err := Execute(context.Background(), testEnv(t), openPolicy(),
		Request{Primitive: "check_status", Params: map[string]interface{}{"target": "/etc/shadow"}})
	if !Refused(err) {
		t.Fatalf("a primitive that declares no parameters must refuse any parameter, got %v", err)
	}
}

func TestCheckStatusCollectsWithoutADatabase(t *testing.T) {
	env := testEnv(t)
	env.WebRoot = env.SiteRoot
	result, err := Execute(context.Background(), env, openPolicy(), Request{Primitive: "check_status"})
	if err != nil {
		t.Fatalf("check_status failed: %v", err)
	}
	for _, key := range []string{"disk_usage_percent", "memory_total_mb", "load_1m", "uptime"} {
		if _, ok := result[key]; !ok {
			t.Errorf("result is missing %q — the key set must match the management API's stats endpoint", key)
		}
	}
	if _, ok := result["postgres_status"]; ok {
		t.Error("with no database configured, postgres_status must be absent rather than guessed")
	}

	// The three disk figures have to add up. They stop adding up the moment
	// used is derived from free-blocks rather than available-blocks, and the
	// difference (the root reserve) is large enough to be noticed and small
	// enough to be dismissed.
	total := parseSize(t, result["disk_total"].(string))
	used := parseSize(t, result["disk_used"].(string))
	avail := parseSize(t, result["disk_available"].(string))
	if diff := total - (used + avail); diff > total/100 || diff < -total/100 {
		t.Errorf("disk_used (%v) + disk_available (%v) does not add up to disk_total (%v)",
			result["disk_used"], result["disk_available"], result["disk_total"])
	}
}

// parseSize reads back the df-style sizes the collector emits.
func parseSize(t *testing.T, s string) float64 {
	t.Helper()
	units := map[byte]float64{'B': 1, 'K': 1 << 10, 'M': 1 << 20, 'G': 1 << 30, 'T': 1 << 40, 'P': 1 << 50}
	if len(s) < 2 {
		t.Fatalf("unreadable size %q", s)
	}
	mult, ok := units[s[len(s)-1]]
	if !ok {
		t.Fatalf("unreadable size unit in %q", s)
	}
	n, err := strconv.ParseFloat(s[:len(s)-1], 64)
	if err != nil {
		t.Fatalf("unreadable size %q: %v", s, err)
	}
	return n * mult
}
