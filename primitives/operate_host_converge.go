package primitives

// host_converge — run the host's housekeeping through the host runner and
// return the transcript (specs/agent_tier1_recipes.md, slice 4 and item 6b).
//
// Operate, no parameters, and the argv is a compiled constant picked by the
// machine's POSTURE, never by the caller:
//
//   - a site node runs the runner with --only=host_housekeeping.sh: one
//     core installer out of the site's tree, nothing else;
//   - a machine with no site (a Docker host, a relay) runs it with --machine:
//     the runner rooted at the agent's verified support bundle, over the host
//     installer set (housekeeping and the host timer), which is how such a
//     machine gets its timer at all.
//
// Nothing over the wire chooses between them: the plane sends host_converge
// with no parameters, and ExecEnv.SiteRoot being empty is the fact that this
// machine has no site. Both constants are pinned in the test beside this
// file, and the runner refuses --machine with a site name and --only with a
// site installer under --machine, so a wrong pairing fails closed.

import (
	"context"
	"time"
)

func init() {
	Register(Primitive{
		Name:        "host_converge",
		Class:       ClassOperate,
		Description: "Run host_housekeeping.sh (fail2ban and the host's daily housekeeping) through the host runner, and return the transcript.",
		Params:      nil,
		Script: &ScriptSpec{
			Interpreter: "/bin/bash",
			ScriptPath:  pluginInstallersRunner,
			ArgsFrom:    hostConvergeArgv,
			StdinFrom:   nil,
		},
		Timeout: 15 * time.Minute,
	})
}

// The two argv constants. A site's is one installer's name in the runner's
// single-installer mode; a machine's is the runner's machine mode.
const (
	hostConvergeOnly    = "--only=host_housekeeping.sh"
	hostConvergeMachine = "--machine"
)

// hostConvergeArgv answers the argv for this machine's posture. Params are
// ignored: the word takes none (pinned), so there is nothing to read.
func hostConvergeArgv(_ context.Context, env *ExecEnv, _ Params) ([]string, error) {
	if env != nil && env.SiteRoot == "" {
		return []string{hostConvergeMachine}, nil
	}
	return []string{hostConvergeOnly}, nil
}
