package recipes

import (
	"context"

	"joinery-agent/primitives"
)

// Recipe agent_supervision: keep the agent's own supervisor standing.
//
// Recipe 2 of specs/agent_tier1_recipes.md. The check is agent_report
// (observe, no parameters): the supervision facts restart_agent proves before
// it will exit — systemd supervising this process with a unit that restarts,
// or the cron keepalive installed, executable and switched on. The repair is
// agent_converge (operate, no parameters): install_agent.sh through the host
// runner, the installer that defines what a supervised agent is on this
// release. Under the job marker a recipe attempt always sets, that installer
// writes supervision and restarts nothing, so the repair cannot kill the
// process running it. Verify is the transcript's ok line and then the check
// again.
//
// What this buys: the host timer's daily converge already runs
// install_agent.sh, so a lost unit file or keepalive was back within a day.
// This recipe makes it minutes (requirement 2 of the spec, "on a minutes
// clock instead of the timer's daily one").
//
// The reading of the check:
//
//   - something would restart this agent: PASS.
//   - nothing would: FAIL. That includes the honest edge where systemd has a
//     restarting unit on disk but did not start THIS process (an agent
//     started by hand on a systemd box): the installer cannot fix that
//     without restarting the agent, which it defers under the marker, so
//     three attempts open a case and a person restarts it. That is the
//     right end: the agent is genuinely unsupervised until they do.
//   - the word refused or failed: UNKNOWN, never repaired.
//
// Site-scoped: install_agent.sh lives in a site tree, and the support bundle
// a machine with no site runs from does not carry it, so on such a machine
// the recipe never ticks and the claim says not-applicable. Both words carry
// their own hostile-caller review in observe_agent_report.go and
// operate_agent_converge.go; this recipe adds no surface.
func init() {
	Register(Recipe{
		Name:        "agent_supervision",
		Scope:       ScopeSite,
		Description: "Something would restart this agent if it stopped (systemd or the cron keepalive); otherwise run install_agent.sh through the host runner.",
		MinInterval: TickInterval,
		CheckWord:   "agent_report",
		RepairWord:  "agent_converge",
		Check: func(ctx context.Context, env *Env) Verdict {
			result, err := env.Run(ctx, "agent_report")
			return supervisionVerdict(result, err)
		},
		Repair: func(ctx context.Context, env *Env) (string, error) {
			result, err := env.Run(ctx, "agent_converge")
			return agentConvergeOutcome(result, err)
		},
	})
}

// supervisionVerdict reads an agent_report result into a verdict.
func supervisionVerdict(result map[string]interface{}, err error) Verdict {
	if err != nil {
		if primitives.Refused(err) {
			return Verdict{Unknown, "agent_report refused: " + err.Error()}
		}
		return Verdict{Unknown, "agent_report failed: " + err.Error()}
	}
	supervised, ok := result["supervised"].(bool)
	if !ok {
		return Verdict{Unknown, "agent_report did not say whether the agent is supervised"}
	}
	if !supervised {
		return Verdict{Fail, "nothing would restart this agent if it stopped: systemd is not supervising this process with a restarting unit, and the cron keepalive is not installed or is switched off"}
	}
	by := ""
	switch v := result["restarted_by"].(type) {
	case []string:
		by = joinNames(v)
	case []interface{}:
		names := make([]string, 0, len(v))
		for _, x := range v {
			if s, ok := x.(string); ok {
				names = append(names, s)
			}
		}
		by = joinNames(names)
	}
	if by == "" {
		by = "a supervisor"
	}
	return Verdict{Pass, "the agent would be restarted by " + by}
}

func joinNames(names []string) string {
	out := ""
	for i, n := range names {
		if i > 0 {
			out += " and "
		}
		out += n
	}
	return out
}

// agentConvergeOutcome reads an agent_converge result: the transcript must
// carry the runner's ok line for install_agent.sh and not its failure line.
func agentConvergeOutcome(result map[string]interface{}, err error) (string, error) {
	return installerOutcome("agent_converge", "install_agent.sh", result, err)
}
