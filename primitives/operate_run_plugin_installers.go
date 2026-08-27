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
// WHAT THE NODE MUST STILL SUPPLY ITSELF. The shipped runner takes SITENAME as
// argv[1] and expects PGPASSWORD in its environment; given neither it exits 0
// having done part of its work. That is a script-side prerequisite recorded in
// full at the bottom of this file — not something to paper over with a
// parameter, which would put the plane back in the sentence.
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
// Recorded here because they are what stands between this primitive and doing
// its whole job, and because the fix belongs on the node in both cases.
//
// 1. THE RUNNER MUST DERIVE ITS OWN SITE ROOT. _plugin_installers_start.sh 1.2
//    reads SITENAME from argv[1] and rebuilds SITE_ROOT as /var/www/html/$1;
//    with no argument it prints "no SITENAME given - skipping" and exits 0. It
//    does not need to be told: it already computes SCRIPT_DIR from its own
//    BASH_SOURCE for the core-installer loop, and the site root is two levels
//    above that. Deriving it also retires the /var/www/html assumption, which is
//    wrong on any node installed elsewhere.
//
// 2. THE RUNNER MUST SOURCE ITS OWN DATABASE CREDENTIALS. It greps only dbname
//    out of the site config and then runs `psql -U postgres`, which on a
//    password-authenticated cluster fails without PGPASSWORD in the environment.
//    The failure is invisible: ACTIVE_PLUGINS comes back empty, the script
//    prints "no active plugins found (or database unreachable) - skipping" and
//    exits 0 — after the CORE installer loop has already run, so the output
//    reads like a successful run that simply had nothing to do.
//
//    The mechanism it needs is in the same directory. install_agent.sh — which
//    this very script invokes — reads dbname, dbusername and dbpassword out of
//    the site config and connects over PDO. The runner reading its own
//    credentials the same way removes the plane's last reason to hold them.
//
// Until both land, this primitive runs the core installer loop and silently
// skips the plugin loop. It is registered now regardless: every script primitive
// is refused anyway on a node whose artifact ships no signed manifest, and a
// primitive that exists is a primitive whose parameter list is pinned before
// anyone is tempted to add one.
