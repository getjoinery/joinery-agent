package primitives

import "time"

// site_converger: whether one site container's host converger is running, read
// from the host it runs on — when it last ran and how that ended, whether its
// converge stamp is there, the site's code check, whether the container
// carries the converger's cron entry and has cron running, and the last N
// lines of its converger log, redacted on this machine before they leave it.
//
// The word specs/agent_recipes_and_vocabulary.md's running list asked for on
// 2026-10-31. A machine on the site container engine raised "a site's code has
// not been checked" for sa, a container site with no agent of its own. The
// host's agent could read the stale code check (host_report) and nothing that
// said why: whether the converger had stopped, refused, or never been started.
// The answer — cron in the container never loaded the converger's entry, which
// was written in the second cron loaded its folder — took a root password
// reset and a serial console to find. Every fact it needed is here.
//
// A SCRIPT WORD, because only script.go may start a process and this word
// asks the container engine which container is the site's and where its
// volumes are. The whole of what runs is
// maintenance_scripts/sysadmin_tools/site_converger.sh, shipped in the
// platform tree and verified against the signed release manifest before it
// runs as root, with two argv elements and no stdin.
//
// HOSTILE-CALLER REVIEW (rule 5 of specs/agent_recipes_and_vocabulary.md).
//
// What is the worst a compromised management node can do with this word? Read,
// on a machine whose owner has left log access on, the last 200 redacted lines
// of one site container's converger log, and a handful of compiled facts
// about that site's converger. The converger's transcript is installer
// output, narrower than the site's error log that site_log already reads,
// and it is masked by the same redactor.
//
// What it cannot do:
//
//   - Name a file. There is no path parameter. The site is a name of the
//     compiled container shape, and the script reads only that container's
//     named volumes mounted at the site's own folders and its running root's
//     /etc/cron.d, at file names compiled into the script.
//   - Name a container that is not a site. The script refuses a name that is
//     not a container on this host whose SITENAME is that name.
//   - Follow the site out of its own files. Every file it reads is the site's
//     to plant, and it is read as root: a link is never followed, a folder on
//     the way that is a link is not entered, a bind mount is never read.
//   - Carry the cron entry. Only whether it is there, whether it runs this
//     site's converger, and when it and its folder last changed.
//   - Read without the owner's leave. RequiresLogAccess: the dispatcher checks
//     the agent_log_access switch before this word runs.
//   - Carry anything unmasked. ScriptSpec.Redact runs the node's redactor over
//     the script's output before it is returned.
//   - Change anything. The engine's ps and inspect, /proc, and bounded reads.
//     Starting a converge is a different word (host_converge, operate).
//
// OBSERVE, and the classification does real work: a node whose policy accepts
// only observe words has to be able to trust that this one writes nothing.
func init() {
	Register(Primitive{
		Name:        "site_converger",
		Class:       ClassObserve,
		Machine:     true,
		Description: "Whether one site container's host converger is running: its last run and outcome, its stamp, the code check, its cron entry and cron, and the last lines of its log, redacted on the node; refused unless log access is allowed.",
		Params: []ParamSpec{
			{Name: "site", Type: ParamString, Required: true, MaxLen: 50, Pattern: holdContainerName},
			{Name: "lines", Type: ParamInt, Min: 1, Max: siteConvergerMaxLines},
		},
		RequiresLogAccess: true,

		Script: &ScriptSpec{
			Interpreter: "/bin/bash",
			ScriptPath:  siteConvergerScript,

			// The only two things a caller supplies, both already validated
			// against the spec above.
			Args: []string{"{site}", "{lines}"},

			// The converger log is text this machine did not compose.
			Redact: true,

			StdinFrom: nil,
		},

		// A few engine calls and bounded reads; the script bounds each at 20 seconds.
		Timeout: 2 * time.Minute,
	})
}

const (
	// siteConvergerMaxLines is the agent's cap; the script clamps to the same
	// figure, and the plane offers no more.
	siteConvergerMaxLines = 200

	// siteConvergerScript is the shipped reader, site-root relative.
	siteConvergerScript = "maintenance_scripts/sysadmin_tools/site_converger.sh"
)
