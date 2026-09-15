package recipes

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"joinery-agent/primitives"
)

// Recipe fail2ban: keep the guard in front of the host standing.
//
// It composes slices 3 and 4 of specs/agent_tier1_recipes.md and nothing
// else. The check is host_report (observe, no parameters): fail2ban's unit
// state and its jail list, read off one bounded JSON object. The repair is
// host_converge (operate, no parameters): host_housekeeping.sh through the
// host runner, the installer that defines what a correct fail2ban is on this
// release, run under the runner lock. Verify is the transcript's last line
// and then the check again.
//
// The reading of the check (owner may reverse, recorded 2026-09-14):
//
//   - active, with at least one jail: PASS.
//   - inactive, failed: FAIL — the unit exists and is not running.
//   - absent: FAIL, not unknown. host_housekeeping.sh installs fail2ban, so
//     a host without it is a host the installer has not made correct, and
//     the definition of correct is the installer's. An operator who removed
//     fail2ban on purpose says so with the hold marker.
//   - active with no jails: FAIL. A fail2ban guarding nothing is the
//     configuration fault the installer's drop-ins fix.
//   - the string unknown, which is what a container and a box without
//     systemd answer, or a report that could not be read, or a unit that is
//     active but whose jails could not be listed: UNKNOWN. Never repaired.
//
// See the package header for the hostile-caller review; this recipe adds no
// surface to it. Its two words are reviewed in observe_host_report.go and
// operate_host_converge.go.
func init() {
	Register(Recipe{
		Name:        "fail2ban",
		Scope:       ScopeHost,
		Description: "fail2ban is active with at least one jail; otherwise run host_housekeeping.sh through the host runner.",
		MinInterval: TickInterval,
		CheckWord:   "host_report",
		RepairWord:  "host_converge",
		Check: func(ctx context.Context, env *Env) Verdict {
			result, err := env.Run(ctx, "host_report")
			return fail2banVerdict(result, err)
		},
		Repair: func(ctx context.Context, env *Env) (string, error) {
			result, err := env.Run(ctx, "host_converge")
			return hostConvergeOutcome(result, err)
		},
	})
}

// hostConvergeOK is the runner's own line for the one installer this recipe
// runs; the transcript must end with it. The exit code says nothing (the
// runner is fail-safe zero by contract), so this line is the whole of what
// "the repair ran" means before the check is asked again.
const hostConvergeOK = "core installers: host_housekeeping.sh: ok"

// fail2banVerdict reads a host_report result into a verdict.
func fail2banVerdict(result map[string]interface{}, err error) Verdict {
	if err != nil {
		if primitives.Refused(err) {
			return Verdict{Unknown, "host_report refused: " + err.Error()}
		}
		return Verdict{Unknown, "host_report failed: " + err.Error()}
	}
	output, _ := result["output"].(string)
	var report struct {
		ExpectedUnits map[string]interface{} `json:"expected_units"`
		Jails         json.RawMessage        `json:"fail2ban_jails"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(output)), &report); err != nil {
		return Verdict{Unknown, "host_report output is not the JSON object it should be"}
	}
	state, _ := report.ExpectedUnits["fail2ban"].(string)
	switch state {
	case "inactive", "failed", "absent":
		return Verdict{Fail, "fail2ban is " + state}
	case "active":
		// fall through to the jails
	default:
		return Verdict{Unknown, "fail2ban's unit state is unknown"}
	}

	var jails []struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(report.Jails, &jails); err != nil {
		// The string "unknown", or nothing at all.
		return Verdict{Unknown, "fail2ban is active but its jails could not be listed"}
	}
	if len(jails) == 0 {
		return Verdict{Fail, "fail2ban is active with no jails"}
	}
	names := make([]string, 0, len(jails))
	for _, j := range jails {
		names = append(names, j.Name)
	}
	return Verdict{Pass, fmt.Sprintf("fail2ban is active with %d jail(s): %s", len(jails), strings.Join(names, ", "))}
}

// hostConvergeOutcome reads a host_converge result: the transcript must end
// with the runner's ok line for host_housekeeping.sh. Anything else the
// runner said instead — a WARNING, a refusal, another run holding the lock —
// is the reason the attempt failed, and the last line is quoted so the
// ledger says which.
func hostConvergeOutcome(result map[string]interface{}, err error) (string, error) {
	if err != nil {
		if primitives.Refused(err) {
			return "", fmt.Errorf("host_converge refused: %v", err)
		}
		return "", fmt.Errorf("host_converge failed: %v", err)
	}
	output, _ := result["output"].(string)
	last := lastLine(output)
	if last != hostConvergeOK {
		if last == "" {
			return "", fmt.Errorf("host_converge returned an empty transcript")
		}
		return "", fmt.Errorf("the transcript does not end with %q; its last line is %q", hostConvergeOK, last)
	}
	return "host_housekeeping.sh: ok", nil
}

// lastLine is the last non-blank line of text, trimmed.
func lastLine(text string) string {
	lines := strings.Split(text, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if line := strings.TrimSpace(lines[i]); line != "" {
			return line
		}
	}
	return ""
}
