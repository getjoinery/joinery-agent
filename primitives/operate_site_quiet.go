package primitives

// site_quiet {action: on|off}: freeze this site for a switch-over, or let it
// run again (specs/site_copy.md WP5). The machine does the freezing
// (maintenance_scripts/sysadmin_tools/site_quiet.sh, over _site_state.sh);
// this word chooses the one flag the script needs and nothing else.
//
//   - on sets `quiet switchover` and waits until the web user runs no
//     command-line PHP. It never sets `quiet copy`: only the installer does.
//   - off clears either reason, and a copy only once this machine holds the
//     node id of the site it is a copy of (the dormant install recorded it).
//     That is the whole of what stops a copy going live beside its source, so
//     the check is here, where the node id lives, and the script is told the
//     answer with --copy-promoted.
//
// HOSTILE-CALLER REVIEW (rule 5).
//
// What is the worst a compromised management node can do with this word? Take
// a live site down: on turns every page into a maintenance page and stops its
// scheduled tasks until off. That is an outage, visible at once to the owner,
// and nothing is lost: the state file, the held cron file and every setting
// quiet changed are put back by off. An operator with this word can already
// do as much with restart_unit apache2 in a loop. Accepted.
//
// What it cannot do:
//
//   - Make a copy go live. off over `quiet copy` refuses unless this machine's
//     own identity says it has taken its source's node id, which only the
//     node-id word does.
//   - Name anything. One enum, two values; argv is composed here.

import (
	"context"
	"time"
)

const siteQuietScript = "maintenance_scripts/sysadmin_tools/site_quiet.sh"

func init() {
	Register(Primitive{
		Name:        "site_quiet",
		Class:       ClassOperate,
		Description: "Freeze this site for a switch-over (on: every page a maintenance page, nothing sent, no scheduled task, no installer) or let it run again (off).",
		Params: []ParamSpec{
			{Name: "action", Type: ParamEnum, Required: true, Values: []string{"on", "off"}},
		},
		Script: &ScriptSpec{
			Interpreter: "/bin/bash",
			ScriptPath:  siteQuietScript,
			ArgsFrom:    siteQuietArgv,
		},
		// Up to ten minutes for the host runner lock, then up to five for the
		// web user's command-line PHP to finish.
		Timeout: 16 * time.Minute,
		Quiet:   QuietAny,
	})
}

func siteQuietArgv(_ context.Context, env *ExecEnv, p Params) ([]string, error) {
	if env == nil || env.SiteRoot == "" {
		return nil, refusedf("site_quiet: this machine has no site to quiet")
	}
	if p.String("action") == "on" {
		return []string{"on"}, nil
	}
	st, err := ReadSiteState(env)
	if err != nil {
		return nil, refusedf("site_quiet: %v", err)
	}
	if st.Reason != "copy" {
		return []string{"off"}, nil
	}
	if st.CopyOf == 0 {
		return nil, refusedf("site_quiet: this site is a dormant copy with no record of its source's node id, so nothing can say it has taken it; it stays quiet")
	}
	if env.NodeID == nil {
		return nil, refusedf("site_quiet: this agent cannot read its own node id; a copy stays quiet")
	}
	id, err := env.NodeID()
	if err != nil {
		return nil, refusedf("site_quiet: cannot read this machine's node id (%v); a copy stays quiet", err)
	}
	if id != st.CopyOf {
		return nil, refusedf("site_quiet: this site is a dormant copy of node %d and this machine is still node %d; "+
			"it clears only once it has taken its source's node id", st.CopyOf, id)
	}
	return []string{"off", "--copy-promoted"}, nil
}
