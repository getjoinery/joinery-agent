package primitives

import "time"

// apply_update: bring this node's Joinery installation up to the version its
// own configured upgrade source offers.
//
// This is the most-used operation in the system — 511 jobs over the fleet's
// lifetime — and it was the last big one still crossing by SSH, where the plane
// composed `cd {web_root} && php utils/upgrade.php --verbose` from a column in
// its own database and sent it as a string to be run as root.
//
// IT TAKES NO PARAMETERS, for the same reason run_plugin_installers takes none.
// A node upgrades from the source IT is configured with; the plane does not get
// to say which release a machine installs, and there is no parameter here
// through which it could learn to. The web root the SSH string carried was the
// plane's belief about where the node keeps its site — the node knows, and
// ExecEnv.SiteRoot is where that answer comes from now.
//
// THE RESTART PROBLEM, which is the part of this primitive that is not obvious.
//
// An upgrade runs the platform's host installers, and the first of those is
// install_agent.sh — the script that installs and restarts THIS PROCESS. Under
// SSH that was free: the upgrade was a child of sshd, so restarting the agent
// disturbed nothing. Under this transport the agent is the process running the
// job. A restart mid-job would kill the reporter before it reports: the job sits
// in 'running' until the plane's claim budget expires, is requeued, and the node
// upgrades a second time. Worse, it does that having already succeeded, so the
// job's own record of the outcome is a timeout.
//
// The fix is a division of labour, not a special case:
//
//   - install_agent.sh (2.7) refuses to swap or restart the agent while that
//     agent is running a job. It reads /etc/joinery-agent/job-running, written
//     by the agent for exactly as long as it holds the job lock, and says out
//     loud that it deferred rather than skipping in silence.
//   - The agent then converges itself, through the self-update path that already
//     exists for this: signature verified against the key baked into this
//     binary, previous binary kept as .bak, swap refused mid-job by the same job
//     lock, and a watchdog that rolls back a version that never reaches a
//     healthy start. It checks every 60 seconds, so a delivered upgrade is
//     picked up about a minute after the job that delivered it reports.
//
// The deferral covers the BINARY as well as the restart, and that detail is
// load-bearing. Updater.install() takes its rollback backup by reading whatever
// file is at the install path; if install_agent.sh had already written the new
// binary there, the .bak would be a copy of the new version and the watchdog's
// rollback would restore the thing it was rolling back from. Leaving the swap
// entirely to the updater keeps the backup meaning what it says.
//
// The suppression is conditional on a LIVE job, never permanent. An agent that
// died mid-job leaves a marker naming a pid that is gone; the installer treats
// that as stale, clears it, and converges normally. The one case the deferral
// must not cover is an agent that cannot self-update out of its situation —
// which is why install_agent.sh keeps every one of its existing restart paths
// for every moment when no job is running.
//
// WHY NOT AN ENVIRONMENT VARIABLE. The signal has to survive upgrade.php's
// shell-outs, and upgrade.php runs the host installers through `sudo -n` on any
// node whose deploy user is not root. sudo strips the environment; upgrade.php's
// own comment at the call site records that it already loses PGPASSWORD there.
// A marker file crosses sudo, su, and every intermediate shell, and can be read
// by a human diagnosing a node.
func init() {
	Register(Primitive{
		Name:        "apply_update",
		Class:       ClassOperate,
		Description: "Apply the Joinery upgrade this node's configured source offers.",

		// Empty on purpose. See above.
		Params: nil,

		Script: &ScriptSpec{
			Interpreter: "/usr/bin/php",

			// Core ships utils/, so this resolves to the manifest at the site
			// root and is verified there before running as root.
			ScriptPath: upgradeScript,

			// The one flag the SSH step carried. Fixed, not a parameter: the
			// plane cannot make an upgrade quiet, and the verbose transcript is
			// what JobResultProcessor reads to tell a halted two-pass upgrade
			// from a finished one.
			Args: []string{"--verbose"},

			StdinFrom: nil,
		},

		// An upgrade downloads a release, deploys it, runs migrations, runs the
		// deploy-tier test suite against the deployed tree, and then runs every
		// host installer. The SSH step allowed an hour for the same work and no
		// upgrade has come close; this keeps that ceiling rather than trimming
		// it, because the cost of being wrong in the tight direction is a root
		// process killed part-way through deploying a release.
		//
		// ManagementJob::PRIMITIVE_CLAIM_BUDGETS must stay above this, and
		// primitive_transport_parity_test fails the build if it does not.
		Timeout: 60 * time.Minute,
	})
}

// upgradeScript is the platform upgrader, site-root relative. A constant so the
// test asserts the string the registration uses rather than a copy of it.
const upgradeScript = "public_html/utils/upgrade.php"
