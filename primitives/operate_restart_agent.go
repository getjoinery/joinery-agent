package primitives

import (
	"context"
	"os"
	"strings"
	"sync"
)

// restart_agent: stop this agent so its supervisor starts it again, clean.
//
// The primitive exists because of a real morning. A container node inherited an
// flock on the site's .upgrade.lock across a fork and held it for hours, so every
// later upgrade on that node was refused by a lock whose holder was the agent
// itself. The agent was healthy enough to poll and take work — it simply needed
// to be the process it was five minutes ago. Fixing it needed a human with an SSH
// key on three separate nodes, which is the exact errand this whole migration is
// meant to end.
//
// TAKES NO PARAMETERS. There is nothing to configure about "become new again",
// and a parameter here would only be a way for the plane to influence how the
// node comes back.
//
// IT REFUSES UNLESS IT CAN PROVE SOMETHING WILL RESTART IT. This is the whole
// design, and without it the primitive is worse than the errand it replaces: an
// agent that exits under no supervisor does not come back, and the node goes dark
// with no remaining way in — the plane cannot reach an agent that is not running,
// and by Phase 3 there is no SSH key left to fall back on. So the proof runs
// first, and a node that cannot name its restarter keeps the agent it has. That
// is the same fail-closed shape as UnavailableVerifier and the policy loader:
// the boundary is shut by default and opens only on evidence.
func init() {
	Register(Primitive{
		Name:        "restart_agent",
		Class:       ClassOperate,
		Description: "Restart this node's agent, if a supervisor can be proven to bring it back.",
		Params:      nil,
		Run:         runRestartAgent,
	})
}

// Where supervision lives, as install_agent.sh writes it. Compiled in, not
// parameters: see the note above about what a parameter here would be for.
const (
	systemdUnitPath   = "/etc/systemd/system/joinery-agent.service"
	cronKeepalivePath = "/etc/cron.d/joinery-agent"
	supervisePath     = "/usr/local/bin/joinery-agent-supervise"
	enabledMarkerPath = "/etc/joinery-agent/enabled"
)

// supervision is the set of facts that decide whether this agent comes back.
// Held as a struct with paths so the decision can be exercised against a temp
// tree; the primitive itself can only ever pass the constants above.
type supervision struct {
	UnitFile      string
	CronFile      string
	SupervisePath string
	EnabledMarker string

	// InvocationID is systemd's INVOCATION_ID for this process. Set only when
	// systemd started us as a service, which is the difference between "a unit
	// file exists on this box" and "systemd is supervising THIS process".
	InvocationID string
}

func liveSupervision() supervision {
	return supervision{
		UnitFile:      systemdUnitPath,
		CronFile:      cronKeepalivePath,
		SupervisePath: supervisePath,
		EnabledMarker: enabledMarkerPath,
		InvocationID:  os.Getenv("INVOCATION_ID"),
	}
}

// restarters names everything that will independently start this agent again.
//
// Both are checked even when one is found, and the result reports all of them:
// the two supervisors are genuinely independent — a container with a cron
// keepalive restarts the agent whether or not systemd also would — and knowing
// which one caught it is what tells an operator why the node was gone for five
// seconds or for a minute.
func (s supervision) restarters() []string {
	var found []string
	if s.systemdWillRestart() {
		found = append(found, "systemd (Restart=always, back within seconds)")
	}
	if s.keepaliveWillRestart() {
		found = append(found, "the cron keepalive (back within a minute)")
	}
	return found
}

// systemdWillRestart reports whether systemd is supervising this process AND
// its unit says to restart it.
//
// Both halves matter. A unit file on disk proves nothing about how this process
// was started — an agent launched by hand on a systemd box would exit and stay
// exited while the unit sat there looking reassuring.
func (s supervision) systemdWillRestart() bool {
	if s.InvocationID == "" {
		return false
	}
	body, err := os.ReadFile(s.UnitFile)
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "Restart=") {
			continue
		}
		value := strings.TrimSpace(strings.TrimPrefix(line, "Restart="))
		if value != "" && value != "no" {
			return true
		}
	}
	return false
}

// keepaliveWillRestart reports whether the cron keepalive will start the agent
// on its next minute.
//
// The marker rule below MIRRORS the keepalive script's own rule exactly, and
// that exactness is the point rather than pedantry: this function is a
// prediction of what another program will do, and a prediction that disagrees
// with the program is how a node goes dark while a check says it will not.
// The script reads:
//
//	if [ -f marker ] && [ "$(cat marker)" != "1" ]; then exit 0; fi
//
// So an ABSENT marker means it runs — an agent installed before the marker
// existed is running legitimately — and only a present marker holding something
// other than "1" stops it.
func (s supervision) keepaliveWillRestart() bool {
	if !isExecutableFile(s.SupervisePath) {
		return false
	}
	if _, err := os.Stat(s.CronFile); err != nil {
		return false
	}

	body, err := os.ReadFile(s.EnabledMarker)
	if err != nil {
		// Absent, or unreadable. Absent reads as on, per the script.
		return os.IsNotExist(err)
	}
	return strings.TrimSpace(string(body)) == "1"
}

func isExecutableFile(path string) bool {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	return info.Mode().Perm()&0o111 != 0
}

func runRestartAgent(ctx context.Context, _ *ExecEnv, _ Params) (map[string]interface{}, error) {
	return restartAgentUnder(ctx, liveSupervision())
}

// restartAgentUnder is the body, with the supervision facts as an argument so
// the refusal can be exercised. The registered primitive above passes the live
// one and nothing else can: a job has no way to reach this.
func restartAgentUnder(_ context.Context, s supervision) (map[string]interface{}, error) {
	found := s.restarters()
	if len(found) == 0 {
		return nil, refusedf(
			"this agent will not stop itself: nothing on this node would start it again. " +
				"systemd is not supervising this process (or its unit does not restart it), and the cron " +
				"keepalive is not installed, not executable, or switched off at /etc/joinery-agent/enabled. " +
				"Exiting here would take the node off the channel with no way back")
	}

	// The process does NOT exit here. This primitive's result has to reach the
	// plane first, or the job it came from sits claimed until the plane's timeout
	// returns it to pending and a second agent runs it again — a restart that
	// reports as a hang, and then repeats. The request is recorded; the caller
	// exits once the result is posted.
	requestRestart(strings.Join(found, " and "))

	return map[string]interface{}{
		"restarting":   true,
		"restarted_by": found,
	}, nil
}

// The restart request, and why it is a package variable rather than a return
// value: the thing that must exit is the process, and the primitive framework
// deliberately hands a primitive no way to reach it (see ExecEnv — everything a
// primitive may touch is named there, and process lifecycle is not). So the
// primitive records an intent and the agent's job loop acts on it after the
// result is delivered.
var (
	restartMu     sync.Mutex
	restartReason string
)

func requestRestart(reason string) {
	restartMu.Lock()
	defer restartMu.Unlock()
	restartReason = reason
}

// ConsumeRestartRequest reports whether a primitive asked this process to
// restart, clearing the request as it does. Called by the job loop once a
// result has been posted.
func ConsumeRestartRequest() (bool, string) {
	restartMu.Lock()
	defer restartMu.Unlock()
	if restartReason == "" {
		return false, ""
	}
	reason := restartReason
	restartReason = ""
	return true, reason
}
