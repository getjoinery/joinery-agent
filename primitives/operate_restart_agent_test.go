package primitives

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// restart_agent's whole design is a refusal, so most of what is worth testing is
// what it will NOT do. An agent that exits under no supervisor does not come
// back, and by Phase 3 there is no SSH key left to go and start it with.

// supervisionIn builds a supervision over a temp tree. Nothing exists in it
// until a test says so, which makes "bare node" the default starting point.
func supervisionIn(t *testing.T) supervision {
	t.Helper()
	dir := t.TempDir()
	return supervision{
		UnitFile:      filepath.Join(dir, "joinery-agent.service"),
		CronFile:      filepath.Join(dir, "cron.d-joinery-agent"),
		SupervisePath: filepath.Join(dir, "joinery-agent-supervise"),
		EnabledMarker: filepath.Join(dir, "enabled"),
	}
}

func writeSupervisionFile(t *testing.T, path, body string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// withSystemd makes systemd a genuine supervisor of this process: a unit that
// restarts, AND the invocation id that proves systemd started us.
func withSystemd(t *testing.T, s supervision, restart string) supervision {
	t.Helper()
	writeSupervisionFile(t, s.UnitFile, "[Service]\nExecStart=/usr/local/bin/joinery-agent\nRestart="+restart+"\nRestartSec=5\n", 0o644)
	s.InvocationID = "d1e2f3a4b5c6"
	return s
}

// withKeepalive installs the cron keepalive: the script, executable, and the
// crontab entry that runs it.
func withKeepalive(t *testing.T, s supervision) supervision {
	t.Helper()
	writeSupervisionFile(t, s.SupervisePath, "#!/bin/sh\n", 0o755)
	writeSupervisionFile(t, s.CronFile, "* * * * * root "+s.SupervisePath+"\n", 0o644)
	return s
}

// clearRestartRequest keeps one test's recorded intent from leaking into the
// next — and, in the live agent, is the same call the job loop makes.
func clearRestartRequest(t *testing.T) {
	t.Helper()
	ConsumeRestartRequest()
	t.Cleanup(func() { ConsumeRestartRequest() })
}

func TestAnUnsupervisedAgentRefusesToStopItself(t *testing.T) {
	clearRestartRequest(t)

	_, err := restartAgentUnder(context.Background(), supervisionIn(t))
	if err == nil {
		t.Fatal("an agent with no supervisor must refuse: exiting would take the node off the channel for good")
	}
	if !Refused(err) {
		t.Errorf("that is a refusal — a decision, not a fault — got %T", err)
	}
}

func TestARefusalLeavesNoPendingRestart(t *testing.T) {
	// The dangerous version of this bug: refuse, report the refusal, and exit
	// anyway because the intent was recorded before the check. The node is then
	// dark AND the job says it declined to do the thing that killed it.
	clearRestartRequest(t)

	if _, err := restartAgentUnder(context.Background(), supervisionIn(t)); err == nil {
		t.Fatal("expected a refusal")
	}
	if pending, _ := ConsumeRestartRequest(); pending {
		t.Fatal("a refused restart must not leave the process scheduled to exit")
	}
}

func TestSystemdSupervisionIsAccepted(t *testing.T) {
	clearRestartRequest(t)
	s := withSystemd(t, supervisionIn(t), "always")

	result, err := restartAgentUnder(context.Background(), s)
	if err != nil {
		t.Fatalf("systemd with Restart=always will bring the agent back: %v", err)
	}
	if result["restarting"] != true {
		t.Error("the result should say the agent is going down")
	}
	if pending, why := ConsumeRestartRequest(); !pending {
		t.Error("an accepted restart must record the intent for the job loop")
	} else if why == "" {
		t.Error("the recorded intent should name what will restart the agent")
	}
}

func TestAUnitFileIsNotProofThatSystemdStartedThisProcess(t *testing.T) {
	// The trap: a unit file on disk looks reassuring and proves nothing. An
	// agent launched by hand on a systemd box exits and stays exited.
	clearRestartRequest(t)

	s := withSystemd(t, supervisionIn(t), "always")
	s.InvocationID = "" // started by hand, not by systemd

	if _, err := restartAgentUnder(context.Background(), s); err == nil {
		t.Fatal("a unit file this process was not started from must not count as supervision")
	}
}

func TestAUnitThatDoesNotRestartIsNotSupervision(t *testing.T) {
	clearRestartRequest(t)
	s := withSystemd(t, supervisionIn(t), "no")

	if _, err := restartAgentUnder(context.Background(), s); err == nil {
		t.Fatal("Restart=no means systemd will not bring it back")
	}
}

func TestTheCronKeepaliveCountsAsSupervision(t *testing.T) {
	clearRestartRequest(t)
	s := withKeepalive(t, supervisionIn(t)) // no marker written: absent reads as on

	result, err := restartAgentUnder(context.Background(), s)
	if err != nil {
		t.Fatalf("an installed keepalive will restart the agent within the minute: %v", err)
	}
	by, _ := result["restarted_by"].([]string)
	if len(by) != 1 {
		t.Fatalf("exactly one restarter should have been found, got %v", by)
	}
}

func TestTheMarkerRuleMatchesTheKeepaliveScriptExactly(t *testing.T) {
	// This function predicts what another program will do. A prediction that
	// disagrees with the program is how a node goes dark while a check says it
	// will not — so the cases below are the script's own conditional, not a
	// reasonable-looking approximation of it:
	//
	//   if [ -f marker ] && [ "$(cat marker)" != "1" ]; then exit 0; fi
	cases := []struct {
		name    string
		marker  string // "" means do not create the file
		present bool
		want    bool
	}{
		{"absent reads as on, for agents older than the marker", "", false, true},
		{"on", "1", true, true},
		{"on, with the trailing newline printf writes", "1\n", true, true},
		{"switched off", "0", true, false},
		{"switched off, newline", "0\n", true, false},
		{"anything that is not 1 is off", "yes", true, false},
		{"empty is not 1", "", true, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clearRestartRequest(t)
			s := withKeepalive(t, supervisionIn(t))
			if tc.present {
				writeSupervisionFile(t, s.EnabledMarker, tc.marker, 0o644)
			}

			if got := s.keepaliveWillRestart(); got != tc.want {
				t.Errorf("marker %q (present=%v): keepalive would restart = %v, want %v",
					tc.marker, tc.present, got, tc.want)
			}
		})
	}
}

func TestAnAgentSwitchedOffWillNotBeRestartedSoItRefuses(t *testing.T) {
	// The genuinely dark case, and the reason the marker is read at all: the
	// keepalive is installed and would run, but the machine is switched off, so
	// it will decline to start the agent. Exiting here is permanent.
	clearRestartRequest(t)

	s := withKeepalive(t, supervisionIn(t))
	writeSupervisionFile(t, s.EnabledMarker, "0\n", 0o644)

	if _, err := restartAgentUnder(context.Background(), s); err == nil {
		t.Fatal("a switched-off node has no restarter; the agent must keep running")
	}
}

func TestAKeepaliveScriptThatCannotRunIsNotSupervision(t *testing.T) {
	clearRestartRequest(t)

	s := withKeepalive(t, supervisionIn(t))
	if err := os.Chmod(s.SupervisePath, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	if _, err := restartAgentUnder(context.Background(), s); err == nil {
		t.Fatal("cron cannot execute a non-executable script, so it is not a restarter")
	}
}

func TestAnUninstalledCrontabIsNotSupervision(t *testing.T) {
	clearRestartRequest(t)

	s := supervisionIn(t)
	writeSupervisionFile(t, s.SupervisePath, "#!/bin/sh\n", 0o755) // script but no crontab entry

	if _, err := restartAgentUnder(context.Background(), s); err == nil {
		t.Fatal("a keepalive script nothing invokes will never restart anything")
	}
}

func TestBothSupervisorsAreReportedWhenBothWouldAct(t *testing.T) {
	// They are independent: a container with a cron keepalive is restarted by it
	// whether or not systemd would also do so. Which one caught it is what tells
	// an operator why the node was gone for five seconds or for a minute.
	clearRestartRequest(t)

	s := withKeepalive(t, withSystemd(t, supervisionIn(t), "always"))

	result, err := restartAgentUnder(context.Background(), s)
	if err != nil {
		t.Fatalf("unexpected refusal: %v", err)
	}
	if by, _ := result["restarted_by"].([]string); len(by) != 2 {
		t.Errorf("both restarters should be reported, got %v", by)
	}
}

func TestConsumingTheRestartRequestClearsIt(t *testing.T) {
	// The job loop calls this once per job. A request that survived would exit
	// the agent after some later, unrelated job.
	clearRestartRequest(t)

	if _, err := restartAgentUnder(context.Background(), withKeepalive(t, supervisionIn(t))); err != nil {
		t.Fatalf("unexpected refusal: %v", err)
	}

	if pending, _ := ConsumeRestartRequest(); !pending {
		t.Fatal("the first consume should see the request")
	}
	if pending, _ := ConsumeRestartRequest(); pending {
		t.Fatal("the request must not survive being consumed")
	}
}

func TestRestartAgentTakesNoParameters(t *testing.T) {
	p, ok := Lookup("restart_agent")
	if !ok {
		t.Fatal("restart_agent should be registered")
	}
	if len(p.Params) != 0 {
		t.Errorf("there is nothing to configure about becoming new again, got %v", p.Params)
	}
	// And the vocabulary refuses one anyway, so a plane cannot influence how the
	// node comes back by inventing a parameter for it.
	if _, err := Validate(p.Params, map[string]interface{}{"delay": 30}); err == nil {
		t.Error("an undeclared parameter must be refused; there is no pass-through")
	}
}

func TestRestartAgentIsOperateAndRunsNoScript(t *testing.T) {
	p, _ := Lookup("restart_agent")

	if p.Class != ClassOperate {
		t.Errorf("restart_agent is operate, not %q", p.Class)
	}
	if p.Script != nil {
		t.Error("restart_agent starts no process — it stops one")
	}
}
