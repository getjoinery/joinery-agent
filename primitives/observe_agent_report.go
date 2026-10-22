package primitives

import (
	"context"
	"os"
	"time"
)

// agent_report: what would bring this agent back if it stopped, as one small
// object — the same supervision facts restart_agent proves before it exits,
// read the same way, so a check and a refusal can never disagree about them.
//
// It is the check word of recipe agent_supervision (specs/agent_tier1_recipes.md,
// recipe 2): the agent asking, every ten minutes, "is anything supervising me",
// and answering from the files install_agent.sh writes and from whether systemd
// started this very process.
//
// HOSTILE-CALLER REVIEW (rule 5 of specs/agent_recipes_and_vocabulary.md).
//
// What is the worst a compromised management node can do with this word?
// Learn which supervisor a node has — systemd or the cron keepalive — and
// whether the keepalive's switch is on. That is reconnaissance of the
// thinnest kind: the plane already knows the node's posture (container or
// host) from the join, and the two shapes follow from it.
//
// What it cannot do:
//
//   - Steer anything. NO PARAMETERS, and the paths it reads are the four
//     compiled constants restart_agent owns; there is no "read this unit"
//     here and no argv at all, because nothing runs: this word starts no
//     process, it stats and reads four files.
//   - Change anything. Reads only.
//   - Say more than the four facts and one age. The answer is a fixed set of
//     keys with booleans, one short list of restarter names, and how many
//     seconds ago the heartbeat file was written; no file content ever travels.
func init() {
	Register(Primitive{
		Name:        "agent_report",
		Class:       ClassObserve,
		Machine:     true,
		Description: "What would restart this agent if it stopped: systemd supervising this process with a restarting unit, and/or the cron keepalive with its switch on.",
		Params:      nil,
		Run:         runAgentReport,
	})
}

// AliveFile is where the agent writes the time every half minute while it is
// alive (the liveness watch, liveness.go in package main). Pinned in
// install_agent.sh's keepalive, which restarts an agent whose file has gone
// stale. Under /run, so a reboot clears it and a missing file never reads as a
// hang there.
var AliveFile = "/run/joinery-agent/alive"

// aliveAge is how many seconds ago the heartbeat file was written, or -1 when
// there is none. The agent answering this word is running, so a stale or
// missing file means its heartbeat is not being written and a hang would go
// unnoticed (agent_supervision fails on it).
func aliveAge(now time.Time) int64 {
	st, err := os.Stat(AliveFile)
	if err != nil {
		return -1
	}
	age := int64(now.Sub(st.ModTime()) / time.Second)
	if age < 0 {
		age = 0
	}
	return age
}

// agentSupervision is the source of the facts, a variable so a test can
// point the word at a temp tree; the live agent never sets it.
var agentSupervision = liveSupervision

// SetAgentSupervisionForTests points agent_report at the given files instead
// of the live machine, and returns the restore. Tests only: the recipe's
// end-to-end test in the recipes package needs a supervised and an
// unsupervised machine on demand, and nothing else may reach these paths.
func SetAgentSupervisionForTests(unitFile, cronFile, supervisePath, enabledMarker, invocationID string) func() {
	prev := agentSupervision
	agentSupervision = func() supervision {
		return supervision{UnitFile: unitFile, CronFile: cronFile, SupervisePath: supervisePath, EnabledMarker: enabledMarker, InvocationID: invocationID}
	}
	return func() { agentSupervision = prev }
}

// SetAliveFileForTests points agent_report's heartbeat at the given file and
// returns the restore. Tests only: the recipe's end-to-end test runs where no
// agent writes /run/joinery-agent/alive.
func SetAliveFileForTests(path string) func() {
	prev := AliveFile
	AliveFile = path
	return func() { AliveFile = prev }
}

// SetAgentSupervisionBootLinkForTests is SetAgentSupervisionForTests with the
// unit's boot link checked too.
func SetAgentSupervisionBootLinkForTests(unitFile, cronFile, supervisePath, enabledMarker, invocationID, bootLink string) func() {
	prev := agentSupervision
	agentSupervision = func() supervision {
		return supervision{UnitFile: unitFile, CronFile: cronFile, SupervisePath: supervisePath, EnabledMarker: enabledMarker, InvocationID: invocationID, BootLink: bootLink}
	}
	return func() { agentSupervision = prev }
}

func runAgentReport(_ context.Context, _ *ExecEnv, _ Params) (map[string]interface{}, error) {
	s := agentSupervision()
	restarters := s.restarters()
	if restarters == nil {
		restarters = []string{}
	}
	return map[string]interface{}{
		"supervised":         len(restarters) > 0,
		"restarted_by":       restarters,
		"systemd_restarts":   s.systemdWillRestart(),
		"keepalive_restarts": s.keepaliveWillRestart(),
		"starts_at_boot":     s.startsAtBoot(),
		"alive_age_seconds":  aliveAge(time.Now()),
	}, nil
}
