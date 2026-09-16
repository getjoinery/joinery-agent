package recipes

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
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

// The reading of host_report, one row per answer the script can give.

func report(units string, jails string) map[string]interface{} {
	return map[string]interface{}{
		"output": fmt.Sprintf(`{"failed_units":[],"expected_units":{"fail2ban":%s,"apache2":"active"},"fail2ban_jails":%s,"generated_at":1}`, units, jails),
	}
}

func TestFail2banVerdicts(t *testing.T) {
	rows := []struct {
		label  string
		result map[string]interface{}
		err    error
		want   Kind
		reason string
	}{
		{"active with jails", report(`"active"`, `[{"name":"sshd","banned":9},{"name":"apache-auth","banned":0}]`), nil, Pass, "2 jail(s)"},
		{"inactive", report(`"inactive"`, `[]`), nil, Fail, "inactive"},
		{"failed", report(`"failed"`, `[]`), nil, Fail, "failed"},
		{"absent: the installer installs it", report(`"absent"`, `"unknown"`), nil, Fail, "absent"},
		{"active guarding nothing", report(`"active"`, `[]`), nil, Fail, "no jails"},
		{"a container: unknown", report(`"unknown"`, `"unknown"`), nil, Unknown, "unknown"},
		{"active but the jails could not be listed", report(`"active"`, `"unknown"`), nil, Unknown, "could not be listed"},
		{"a state the script never prints", report(`"reloading"`, `[]`), nil, Unknown, "unknown"},
		{"no fail2ban key at all", map[string]interface{}{"output": `{"expected_units":{}}`}, nil, Unknown, "unknown"},
		{"output that is not JSON", map[string]interface{}{"output": "bash: systemctl: not found"}, nil, Unknown, "not the JSON"},
		{"no output key", map[string]interface{}{}, nil, Unknown, "not the JSON"},
		{"the word refused (no runner, no manifest)", nil, &primitives.RefusalError{Reason: "no site root"}, Unknown, "refused"},
		{"the word failed", nil, errors.New("exited 1"), Unknown, "failed"},
	}
	for _, row := range rows {
		got := fail2banVerdict(row.result, row.err)
		if got.Kind != row.want {
			t.Errorf("%s: verdict %s (%s), want %s", row.label, got.Kind, got.Reason, row.want)
		}
		if !strings.Contains(got.Reason, row.reason) {
			t.Errorf("%s: reason %q should mention %q", row.label, got.Reason, row.reason)
		}
	}
}

func TestHostConvergeOutcomeReadsTheTranscriptNotTheExitCode(t *testing.T) {
	ok := "host installers: lock taken (pid 1)\ncore installers: running host_housekeeping.sh\nfail2ban: rendered 3 drop-ins\ncore installers: host_housekeeping.sh: ok\n"
	if detail, err := hostConvergeOutcome(map[string]interface{}{"output": ok}, nil); err != nil || detail == "" {
		t.Errorf("a site transcript ending with the ok line is a repair that ran: %v", err)
	}
	// A machine with no site runs the whole host set and the runner keeps
	// talking after the line this recipe cares about: what the docker-prod
	// host's own converger log ends with, read 2026-09-16. Requiring the ok
	// line LAST would ledger every armed repair there as failed while
	// fail2ban came back (B5).
	machine := "host installers: lock taken (pid 1)\ncore installers: running host_housekeeping.sh\nfail2ban: rendered 3 drop-ins\ncore installers: host_housekeeping.sh: ok\n" +
		"core installers: running install_host_converger.sh\nhost converger: timer already active (every 1 min, systemd)\ncore installers: install_host_converger.sh: ok\nplugin installers: none on a machine with no site\n"
	if detail, err := hostConvergeOutcome(map[string]interface{}{"output": machine}, nil); err != nil || detail == "" {
		t.Errorf("a machine transcript carrying the ok line is a repair that ran: %v", err)
	}
	rows := []struct {
		label  string
		output string
		err    error
		want   string
	}{
		{"a warning", "core installers: running host_housekeeping.sh\ncore installers: WARNING - host_housekeeping.sh failed\n", nil, "WARNING"},
		{"refused by the runner", "installer refused: host_housekeeping.sh is not in the manifest\n", nil, "installer refused"},
		{"another run holds the lock", "host installers: another run holds the lock (pid 4 since T) - waited 600s, leaving it to that one\n", nil, "another run holds the lock"},
		{"the other installer's ok line only", "core installers: running install_host_converger.sh\ncore installers: install_host_converger.sh: ok\nplugin installers: none on a machine with no site\n", nil, "plugin installers: none"},
		{"ok line embedded in another line", "core installers: host_housekeeping.sh: ok (not really)\n", nil, "does not carry"},
		{"a warning after an earlier ok", "core installers: host_housekeeping.sh: ok\ncore installers: WARNING - host_housekeeping.sh failed\n", nil, "WARNING"},
		{"empty", "", nil, "empty transcript"},
		{"the word refused", "", &primitives.RefusalError{Reason: "hash mismatch"}, "refused"},
		{"the word failed", "", errors.New("killed"), "failed"},
	}
	for _, row := range rows {
		_, err := hostConvergeOutcome(map[string]interface{}{"output": row.output}, row.err)
		if err == nil {
			t.Errorf("%s: should not count as a repair that ran", row.label)
			continue
		}
		if !strings.Contains(err.Error(), row.want) {
			t.Errorf("%s: %v should say %q", row.label, err, row.want)
		}
	}
}

// --- End to end, against a signed tree ---------------------------------------

// signedTree writes both scripts the recipe composes into a site root and
// signs them, exactly as a release does, so the recipe runs its real words
// through primitives.Execute and the manifest check.
func signedTree(t *testing.T, hostReport, runner string) *Env {
	t.Helper()
	root := t.TempDir()
	reportPath := scriptPathOf(t, "host_report")
	runnerPath := scriptPathOf(t, "host_converge")

	var manifest strings.Builder
	for _, s := range []struct{ rel, body string }{{reportPath, hostReport}, {runnerPath, runner}} {
		full := filepath.Join(root, filepath.FromSlash(s.rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(s.body), 0o755); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256([]byte(s.body))
		fmt.Fprintf(&manifest, "%s  %s\n", hex.EncodeToString(sum[:]), s.rel)
	}
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := primitives.NewSignedTreeVerifier(root, []byte(manifest.String()), ed25519.Sign(priv, []byte(manifest.String())), pub)
	if err != nil {
		t.Fatal(err)
	}
	return &Env{
		Exec: &primitives.ExecEnv{
			SiteRoot: root,
			WebRoot:  filepath.Join(root, "public_html"),
			Manifest: verifier,
		},
		Policy: primitives.ShippedPolicy(),
	}
}

func scriptPathOf(t *testing.T, word string) string {
	t.Helper()
	p, ok := primitives.Lookup(word)
	if !ok || p.Script == nil {
		t.Fatalf("%s should be a script word", word)
	}
	return p.Script.ScriptPath
}

const downReport = `#!/bin/bash
echo '{"failed_units":["fail2ban.service"],"expected_units":{"fail2ban":"failed"},"fail2ban_jails":[],"generated_at":1}'
`

// A report that answers from a state file, so the runner can "repair" it.
func statefulReport(stateFile string) string {
	return "#!/bin/bash\n" +
		"if [[ -f " + stateFile + " ]]; then\n" +
		`  echo '{"expected_units":{"fail2ban":"active"},"fail2ban_jails":[{"name":"sshd","banned":0}]}'` + "\n" +
		"else\n" +
		`  echo '{"expected_units":{"fail2ban":"failed"},"fail2ban_jails":[]}'` + "\n" +
		"fi\n"
}

func TestTheFail2banRecipeRepairsThroughItsTwoWords(t *testing.T) {
	root := t.TempDir()
	restoreLedger, restoreHold, restoreOut := LedgerDir, HoldDir, OutwardDir
	LedgerDir, HoldDir, OutwardDir = filepath.Join(root, "ledger"), filepath.Join(root, "hold"), ""
	t.Cleanup(func() { LedgerDir, HoldDir, OutwardDir = restoreLedger, restoreHold, restoreOut })

	stateFile := filepath.Join(root, "fail2ban-up")
	runner := "#!/bin/bash\n" +
		`echo "argv=$*"` + "\n" +
		"echo 'core installers: running host_housekeeping.sh'\n" +
		"touch " + stateFile + "\n" +
		"echo 'core installers: host_housekeeping.sh: ok'\n"
	env := signedTree(t, statefulReport(stateFile), runner)

	recipe, ok := Lookup("fail2ban")
	if !ok {
		t.Fatal("fail2ban should be registered")
	}
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
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
	entries := readEntries(t, filepath.Join(LedgerDir, "fail2ban.jsonl"))
	var outcome Entry
	for _, e := range entries {
		if e.Event == EventOutcome {
			outcome = e
		}
	}
	if outcome.Outcome != OutcomeRepaired {
		t.Fatalf("expected the recipe to repair through host_converge and verify through host_report, got %+v\nlog:\n%s", outcome, strings.Join(logs, "\n"))
	}
	if _, err := os.Stat(stateFile); err != nil {
		t.Error("the runner should have run")
	}
	// And the runner saw the compiled constant, and only it.
	var checks int
	for _, e := range entries {
		if e.Event == EventCheck {
			checks++
		}
	}
	if checks < 2 {
		t.Errorf("both failing checks should be ledgered, got %d", checks)
	}
}

func TestTheFail2banRecipeInReportOnlyChangesNothing(t *testing.T) {
	root := t.TempDir()
	restoreLedger, restoreHold, restoreOut := LedgerDir, HoldDir, OutwardDir
	LedgerDir, HoldDir, OutwardDir = filepath.Join(root, "ledger"), filepath.Join(root, "hold"), ""
	t.Cleanup(func() { LedgerDir, HoldDir, OutwardDir = restoreLedger, restoreHold, restoreOut })

	ran := filepath.Join(root, "runner-ran")
	env := signedTree(t, downReport, "#!/bin/bash\ntouch "+ran+"\necho 'core installers: host_housekeeping.sh: ok'\n")
	recipe, _ := Lookup("fail2ban")
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	loop := NewLoop([]Recipe{recipe}, env, Options{Now: func() time.Time { return now }, Logf: func(string, ...interface{}) {}})
	// The release is armed (registry_test pins it); the report-only posture
	// stays proven end to end against the real recipe and a signed tree, so
	// a later release can disarm on a path that never stopped being tested.
	loop.reportOnly = true
	for i := 0; i < 3; i++ {
		now = now.Add(TickInterval)
		loop.Tick(context.Background())
	}
	if _, err := os.Stat(ran); !os.IsNotExist(err) {
		t.Fatal("report-only ran the runner")
	}
	var reportOnly int
	for _, e := range readEntries(t, filepath.Join(LedgerDir, "fail2ban.jsonl")) {
		if e.Event == EventOutcome && e.Outcome == OutcomeReportOnly {
			reportOnly++
		}
	}
	// Two: one after the second failing tick, one ten minutes later — the
	// armed loop's own schedule, recorded without acting.
	if reportOnly != 2 {
		t.Errorf("expected two report-only attempts in three failing ticks, got %d", reportOnly)
	}
}

func TestAnUnverifiableTreeIsUnknownNotFailed(t *testing.T) {
	// A siteless host with no bundle, or a tree whose manifest is unusable:
	// host_report refuses, and a refusal is an answer the recipe cannot read,
	// never a failure it would repair.
	env := &Env{
		Exec:   &primitives.ExecEnv{Manifest: primitives.UnavailableVerifier{}},
		Policy: primitives.ShippedPolicy(),
	}
	recipe, _ := Lookup("fail2ban")
	v := recipe.Check(context.Background(), env)
	if v.Kind != Unknown {
		t.Fatalf("a refused check is unknown, got %s (%s)", v.Kind, v.Reason)
	}
}

func TestAPolicyThatRefusesOperateStopsTheRepairWithAReason(t *testing.T) {
	root := t.TempDir()
	restoreLedger, restoreHold, restoreOut := LedgerDir, HoldDir, OutwardDir
	LedgerDir, HoldDir, OutwardDir = filepath.Join(root, "ledger"), filepath.Join(root, "hold"), ""
	t.Cleanup(func() { LedgerDir, HoldDir, OutwardDir = restoreLedger, restoreHold, restoreOut })

	ran := filepath.Join(root, "runner-ran")
	env := signedTree(t, downReport, "#!/bin/bash\ntouch "+ran+"\necho 'core installers: host_housekeeping.sh: ok'\n")
	env.Policy = &primitives.Policy{Accept: []primitives.Class{primitives.ClassObserve}}
	recipe, _ := Lookup("fail2ban")
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	loop := NewLoop([]Recipe{recipe}, env, Options{Now: func() time.Time { return now }, Logf: func(string, ...interface{}) {}})
	loop.reportOnly = false
	for i := 0; i < 2; i++ {
		now = now.Add(TickInterval)
		loop.Tick(context.Background())
	}
	if _, err := os.Stat(ran); !os.IsNotExist(err) {
		t.Fatal("the node's policy refuses operate words, and the recipe ran one anyway")
	}
	var outcome Entry
	for _, e := range readEntries(t, filepath.Join(LedgerDir, "fail2ban.jsonl")) {
		if e.Event == EventOutcome {
			outcome = e
		}
	}
	if outcome.Outcome != OutcomeFailed || !strings.Contains(outcome.Detail, "does not accept operate") {
		t.Errorf("the attempt should be ledgered as failed with the policy's reason, got %+v", outcome)
	}
}
