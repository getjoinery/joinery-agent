package recipes

import (
	"context"
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

func TestSupervisionVerdicts(t *testing.T) {
	rows := []struct {
		label  string
		result map[string]interface{}
		err    error
		want   Kind
		reason string
	}{
		{"systemd", map[string]interface{}{"supervised": true, "restarted_by": []string{"systemd (Restart=always, back within seconds)"}}, nil, Pass, "systemd"},
		{"both, as JSON would carry them", map[string]interface{}{"supervised": true, "restarted_by": []interface{}{"systemd", "the cron keepalive"}}, nil, Pass, "systemd and the cron keepalive"},
		{"nothing", map[string]interface{}{"supervised": false, "restarted_by": []string{}}, nil, Fail, "nothing would restart"},
		{"no answer", map[string]interface{}{}, nil, Unknown, "did not say"},
		{"refused", nil, &primitives.RefusalError{Reason: "policy"}, Unknown, "refused"},
		{"failed", nil, errors.New("boom"), Unknown, "failed"},
	}
	for _, row := range rows {
		v := supervisionVerdict(row.result, row.err)
		if v.Kind != row.want || !strings.Contains(v.Reason, row.reason) {
			t.Errorf("%s: got %s %q, want %s containing %q", row.label, v.Kind, v.Reason, row.want, row.reason)
		}
	}
}

func TestAgentConvergeOutcomeReadsTheInstallerLine(t *testing.T) {
	ok := "core installers: running install_agent.sh\nagent installer: agent_enabled is on - v1.34.0 already running\ncore installers: install_agent.sh: ok\n"
	if d, err := agentConvergeOutcome(map[string]interface{}{"output": ok}, nil); err != nil || d != "install_agent.sh: ok" {
		t.Errorf("the ok line is a repair that ran: %q %v", d, err)
	}
	for _, row := range []struct{ label, output, want string }{
		{"the housekeeping line is not this installer's", "core installers: host_housekeeping.sh: ok\n", "does not carry"},
		{"a warning", "core installers: WARNING - install_agent.sh failed\n", "WARNING"},
		{"empty", "", "empty transcript"},
	} {
		if _, err := agentConvergeOutcome(map[string]interface{}{"output": row.output}, nil); err == nil || !strings.Contains(err.Error(), row.want) {
			t.Errorf("%s: %v should say %q", row.label, err, row.want)
		}
	}
}

// End to end: an unsupervised agent, the real recipe, the real words through
// primitives.Execute against a signed runner. The runner is asked for exactly
// --only=install_agent.sh, "installs" the keepalive, and the check passes.
func TestTheAgentSupervisionRecipeRepairsThroughItsTwoWords(t *testing.T) {
	root := t.TempDir()
	restoreLedger, restoreHold, restoreOut := LedgerDir, HoldDir, OutwardDir
	LedgerDir, HoldDir, OutwardDir = filepath.Join(root, "ledger"), filepath.Join(root, "hold"), ""
	t.Cleanup(func() { LedgerDir, HoldDir, OutwardDir = restoreLedger, restoreHold, restoreOut })
	restoreSite := HasSite
	HasSite = func() bool { return true }
	t.Cleanup(func() { HasSite = restoreSite })

	sup := filepath.Join(root, "supervision")
	if err := os.MkdirAll(sup, 0o755); err != nil {
		t.Fatal(err)
	}
	supervise := filepath.Join(sup, "joinery-agent-supervise")
	cron := filepath.Join(sup, "cron.d-joinery-agent")
	restore := primitives.SetAgentSupervisionForTests(filepath.Join(sup, "unit"), cron, supervise, filepath.Join(sup, "enabled"), "")
	t.Cleanup(restore)

	// The runner "installs" the keepalive when asked for the agent installer.
	runner := "#!/bin/bash\n" +
		`echo "argv=$*"` + "\n" +
		`if [[ "$1" != "--only=install_agent.sh" ]]; then echo "core installers: WARNING - wrong installer"; exit 0; fi` + "\n" +
		"echo 'core installers: running install_agent.sh'\n" +
		"printf '#!/bin/sh\\n' > " + supervise + " && chmod 755 " + supervise + "\n" +
		"echo '* * * * * root x' > " + cron + "\n" +
		"echo 'core installers: install_agent.sh: ok'\n"
	env := signedTree(t, downReport, runner)

	recipe, ok := Lookup("agent_supervision")
	if !ok {
		t.Fatal("agent_supervision should be registered")
	}
	now := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
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
	entries := readEntries(t, filepath.Join(LedgerDir, "agent_supervision.jsonl"))
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
	if outcome.Outcome != OutcomeRepaired || outcome.Detail != "install_agent.sh: ok" {
		t.Fatalf("expected the recipe to repair through agent_converge and verify through agent_report, got %+v\nlog:\n%s", outcome, strings.Join(logs, "\n"))
	}
	if checks < 2 {
		t.Errorf("both failing checks should be ledgered, got %d", checks)
	}
	if LastVerdict("agent_supervision") != Pass {
		t.Errorf("after the repair's verifying check the claim should say pass, got %q", LastVerdict("agent_supervision"))
	}
	// And the next tick, supervised, does nothing.
	now = now.Add(TickInterval)
	loop.Tick(context.Background())
	if n := len(readEntries(t, filepath.Join(LedgerDir, "agent_supervision.jsonl"))); n != len(entries) {
		t.Errorf("a passing tick after a pass should write nothing; ledger grew from %d to %d", len(entries), n)
	}
}
