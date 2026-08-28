package primitives

import "time"

// run_plugin_installers: run this node's host installers — core's own first,
// then every active plugin's.
//
// The platform already runs these at its root moments: container start, site
// install, code upgrade. This primitive exists for the moment a bare-metal node
// otherwise lacks — an operator activates a plugin whose host_installer
// configures a system service (mailbox → Postfix, core → the agent itself), and
// nothing on that machine will next be root until the following upgrade.
//
// IT TAKES NO PARAMETERS, AND THAT IS THE ENTIRE DESIGN.
//
// The SSH builder it replaces sent two things, and neither was a decision the
// plane was entitled to make:
//
//   - The SITE NAME, computed on the plane as basename(dirname(web_root)) from a
//     column in the plane's own database. That column is the plane's belief about
//     what the node is called. The node knows what it is called: the agent has
//     its own SiteRoot, and the script's absolute path is derived from it right
//     here. A node told its own name by a remote party is a node whose identity
//     is only as correct as a row someone else can edit — and, since the name
//     becomes a filesystem path, only as safe.
//
//   - PGPASSWORD, injected because sudo does not forward the caller's
//     environment. The agent has no such gap: it is already root on this machine,
//     and the site's database credentials are in the site config it can read.
//     A control plane holding a node's database password so it can hand it back
//     to that node is the SSH era's shape, not this one's.
//
// So the whole vocabulary of this operation is: its name. There is no parameter
// through which a compromised plane can influence which tree is touched, which
// database is read, or which installers run. The declared list is a security
// boundary, not documentation (§3.2), and the strongest list is the empty one.
//
// THE RUNNER MEETS IT THERE, which is what makes the empty vocabulary workable
// rather than merely principled: _plugin_installers_start.sh 1.3 derives its own
// site root from its own location and reads its own database credentials out of
// the site config over PDO, so it needs neither an argument nor anything in the
// environment. See "Node-side prerequisites" at the bottom of this file.
//
// SUCCESS IS NOT THE EXIT CODE. The runner is fail-safe by contract: a plugin
// that is absent, a plugin that is inactive, an unreachable database, and an
// installer that fails all exit 0, deliberately, so a broken installer can never
// block a container from starting. The OUTPUT is therefore the record of what
// ran, and the framework already carries every byte of stdout and stderr into
// the result under "output" (capped, and reporting the cap). Nothing here may
// summarise it into a verdict, because there is no verdict in the exit code to
// summarise.
func init() {
	Register(Primitive{
		Name:        "run_plugin_installers",
		Class:       ClassOperate,
		Description: "Run this node's core and active-plugin host installers.",

		// Empty on purpose. See above; every parameter not declared here is one
		// the plane can never abuse.
		Params: nil,

		Script: &ScriptSpec{
			Interpreter: "/bin/bash",

			// Site-root relative, and outside public_html: the runner ships in
			// the core archive, so it resolves to the manifest at the site root
			// (owningArtifact returns "" for anything that is not a plugin or a
			// theme). It is verified there before it runs as root.
			ScriptPath: pluginInstallersRunner,

			// No argv at all. Not an empty-looking template with a slot in it —
			// nothing, so there is no element for a future edit to make
			// wire-supplied.
			Args: nil,

			// No stdin. The runner reads none, and a channel that exists is a
			// channel someone will find a use for.
			StdinFrom: nil,
		},
		// The same 900s the SSH step allowed. Installers configure system
		// services (Postfix, certbot, the agent itself) and apt can be slow, but
		// one that is still going after fifteen minutes is stuck, not busy.
		Timeout: 15 * time.Minute,
	})
}

// pluginInstallersRunner is the shipped runner, site-root relative. Named as a
// constant so the test asserts the same string the registration uses rather
// than a copy of it that can drift.
const pluginInstallersRunner = "maintenance_scripts/install_tools/_plugin_installers_start.sh"

// --- Node-side prerequisites -------------------------------------------------
//
// What the runner has to be able to do on its own for the empty parameter list
// above to be workable rather than merely principled. Both are met by
// _plugin_installers_start.sh 1.3.
//
//  1. IT DERIVES ITS OWN SITE ROOT, from its own BASH_SOURCE two levels up,
//     rather than rebuilding /var/www/html/$1 from an argument. An explicit
//     SITENAME still wins where /var/www/html/$SITENAME exists, because
//     install.sh runs the script from the source tree it is installing FROM —
//     but this primitive passes none, and the derived answer is the right one.
//     It also retires the /var/www/html assumption, which is wrong on any node
//     installed elsewhere.
//
//  2. IT READS ITS OWN DATABASE CREDENTIALS out of the site config over PDO,
//     the way install_agent.sh in the same directory always has, instead of
//     running `psql -U postgres` and depending on PGPASSWORD being in the
//     environment. That dependency failed invisibly: ACTIVE_PLUGINS came back
//     empty, the script printed "no active plugins found (or database
//     unreachable) - skipping" and exited 0, after the core loop had already
//     run — so a half-run read as a clean one. 1.3 also splits that message
//     into "could not read the site database" and "no active plugins - nothing
//     to run", which are different facts.
//
// THE RESTART, which this primitive shares with apply_update. The first thing
// the runner does is run install_agent.sh, whose job is to converge and restart
// the agent — this process. It defers both while a job is running, on the
// marker the agent writes for the life of the job; see jobmarker.go and
// operate_apply_update.go. Without that, running this primitive on a node with
// a fresh agent artifact would kill the job that asked for it.
