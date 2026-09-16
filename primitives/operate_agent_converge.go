package primitives

// agent_converge — run the agent's own installer through the host runner and
// return the transcript (specs/agent_tier1_recipes.md, recipe 2).
//
// Operate, no parameters, and the argv is one compiled constant: the runner's
// single-installer mode naming install_agent.sh. That installer is the one
// definition of "this agent is supervised" on a release — the unit file, the
// cron keepalive, the enabled switch — and running it converges those and
// nothing else while a job marker is set: it writes supervision, and it
// defers any swap or restart of the running agent to the agent's own signed
// self-update (install_agent.sh 2.7). A recipe attempt always holds the
// marker, so the repair this word is composed into can never kill the
// process running it.
//
// A machine with no site has no install_agent.sh to run — the support bundle
// carries the host installers only — so the word REFUSES there rather than
// guessing, and the recipe that composes it is site-scoped and never ticks
// there. Nothing over the wire chooses: the plane sends the name and nothing
// else, and an empty site root is the fact that decides.
//
// HOSTILE-CALLER REVIEW (rule 5 of specs/agent_recipes_and_vocabulary.md).
//
// What is the worst a compromised management node can do with this word?
// Make the node run its own agent installer, out of its own verified tree,
// under the runner lock — the same thing run_plugin_installers already lets
// it do for every installer at once, and the same thing the host timer does
// daily. Without a job marker set the installer may restart the agent into
// the binary the tree ships if the running one is stale; a plane job always
// sets the marker, so from the wire this word converges supervision and
// restarts nothing.
//
// What it cannot do: name another installer (no parameters, no argv slot,
// the constant is pinned), run anything not in the signed manifest (the
// runner refuses), or run at all on a machine with no site.

import (
	"context"
	"time"
)

func init() {
	Register(Primitive{
		Name:        "agent_converge",
		Class:       ClassOperate,
		Description: "Run install_agent.sh (this agent's supervision: unit file, cron keepalive, enabled switch) through the host runner, and return the transcript.",
		Params:      nil,
		Script: &ScriptSpec{
			Interpreter: "/bin/bash",
			ScriptPath:  pluginInstallersRunner,
			ArgsFrom:    agentConvergeArgv,
			StdinFrom:   nil,
		},
		Timeout: 15 * time.Minute,
	})
}

// agentConvergeOnly is the one argv constant: the runner's single-installer
// mode naming the agent installer, which is in the runner's CORE_INSTALLERS.
const agentConvergeOnly = "--only=install_agent.sh"

// agentConvergeArgv answers the argv, or refuses on a machine with no site.
// Params are ignored: the word takes none (pinned).
func agentConvergeArgv(_ context.Context, env *ExecEnv, _ Params) ([]string, error) {
	if env == nil || env.SiteRoot == "" {
		return nil, refusedf("agent_converge needs a site tree: install_agent.sh is not in the support bundle a machine with no site runs from")
	}
	return []string{agentConvergeOnly}, nil
}
