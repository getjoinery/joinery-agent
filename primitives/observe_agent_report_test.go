package primitives

import (
	"context"
	"testing"
)

// agent_report answers the same question restart_agent asks before it exits,
// from the same facts, so the two can never disagree.

func TestAgentReportAsksForNothingAndRunsNothing(t *testing.T) {
	p, ok := Lookup("agent_report")
	if !ok {
		t.Fatal("agent_report should be registered")
	}
	if len(p.Params) != 0 {
		t.Fatalf("agent_report declares %d parameter(s); it must declare none", len(p.Params))
	}
	if p.Class != ClassObserve {
		t.Errorf("agent_report is observe, not %q", p.Class)
	}
	if p.Script != nil || p.Run == nil {
		t.Error("agent_report reads four files in-process; it is not a script word")
	}
}

func TestAgentReportSaysWhatRestartAgentWouldFind(t *testing.T) {
	rows := []struct {
		label      string
		build      func(t *testing.T) supervision
		supervised bool
	}{
		{"a bare node", func(t *testing.T) supervision { return supervisionIn(t) }, false},
		{"systemd supervising this process with Restart=always", func(t *testing.T) supervision { return withSystemd(t, supervisionIn(t), "always") }, true},
		{"a restarting unit on disk but systemd did not start this process", func(t *testing.T) supervision {
			s := withSystemd(t, supervisionIn(t), "always")
			s.InvocationID = ""
			return s
		}, false},
		{"systemd supervising with Restart=no", func(t *testing.T) supervision { return withSystemd(t, supervisionIn(t), "no") }, false},
		{"the cron keepalive, switch absent", func(t *testing.T) supervision { return withKeepalive(t, supervisionIn(t)) }, true},
		{"the cron keepalive, switched off", func(t *testing.T) supervision {
			s := withKeepalive(t, supervisionIn(t))
			writeSupervisionFile(t, s.EnabledMarker, "0\n", 0o644)
			return s
		}, false},
	}
	for _, row := range rows {
		s := row.build(t)
		restore := SetAgentSupervisionForTests(s.UnitFile, s.CronFile, s.SupervisePath, s.EnabledMarker, s.InvocationID)
		result, err := runAgentReport(context.Background(), nil, Params{})
		restore()
		if err != nil {
			t.Fatalf("%s: agent_report never errors on a readable answer: %v", row.label, err)
		}
		if got, _ := result["supervised"].(bool); got != row.supervised {
			t.Errorf("%s: supervised = %v, want %v (%v)", row.label, got, row.supervised, result)
		}
		by, _ := result["restarted_by"].([]string)
		if (len(by) > 0) != row.supervised {
			t.Errorf("%s: restarted_by %v disagrees with supervised %v", row.label, by, row.supervised)
		}
		// The same answer restart_agent gives: it refuses exactly when this says unsupervised.
		_, rerr := restartAgentUnder(context.Background(), s)
		ConsumeRestartRequest()
		if (rerr == nil) != row.supervised {
			t.Errorf("%s: restart_agent and agent_report disagree (restart err %v, supervised %v)", row.label, rerr, row.supervised)
		}
	}
}
