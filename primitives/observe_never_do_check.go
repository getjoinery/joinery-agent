package primitives

import "time"

// never_do_check: the never-do list of specs/node_unexplained_root.md (§ 5.1),
// as one bounded JSON object. Things with no legitimate source on a machine
// Joinery runs, seen as they stand now: a setuid program no package installed
// (or one a package installed and something changed), an account other than
// root with uid 0, a kernel tainted by an out-of-tree, unsigned or forced
// module, a program running from /tmp, /var/tmp, /dev/shm or from memory, a
// root program whose file is gone, /etc/ld.so.preload with anything in it.
// Beside them, the lists that are only wrong when they change: SSH keys, login
// accounts, sudoers, the files that start things, listening TCP ports and the
// size of the login logs.
//
// THE MACHINE KEEPS NO MEMORY OF ITS OWN LISTS, and that is the design. The
// management node keeps the last accepted list and compares each report with
// it, so an attacker who owns this machine cannot rewrite what it used to be.
// A change the plane's own job history explains (an upgrade, an installer run)
// is taken into the list; anything else opens an incident.
//
// A SCRIPT WORD for the same reason as host_report: only script.go may start
// a process, and this needs find, dpkg's lists, ss and ssh-keygen. The whole of
// what runs is maintenance_scripts/sysadmin_tools/never_do_check.sh, verified
// against the signed release manifest before it runs as root, with no argv and
// no stdin; tests/integration/never_do_check_gate.sh on the platform pins it.
//
// HOSTILE-CALLER REVIEW (rule 5 of specs/agent_recipes_and_vocabulary.md).
//
// What is the worst a compromised management node can do with this word?
// Learn the machine's login accounts, its SSH key FINGERPRINTS, the paths of
// its unit and cron files and its listening ports: reconnaissance of the same
// kind host_report and listening_sockets already give it, which the accepted
// limits table grants the plane.
//
// What it cannot do:
//
//   - Steer anything. NO PARAMETERS: not a path, not a list, not a threshold.
//     Params is nil, so a job carrying any field is refused before the script
//     is reached, and Args is nil.
//   - Read content. A key is its fingerprint, never its comment; a file is its
//     path and sixteen hex of its sha256; a process is its uid and program
//     path, never its arguments (beyond the script an interpreter was handed
//     from a scratch directory); a log is its inode and size. No file's bytes
//     travel.
//   - Change anything. Every command reads.
//   - Quiet it. The plane can stop ASKING, which the node page shows as a stale
//     check; it cannot make this word report less than the machine holds.
//   - Flood the plane. Every list is capped in the script and says so.
//
// OBSERVE: it writes nothing.
func init() {
	Register(Primitive{
		Name:        "never_do_check",
		Class:       ClassObserve,
		Machine:     true,
		Description: "The never-do list: setuid programs no package installed, extra uid-0 accounts, a tainted kernel, programs running from scratch directories or memory, root programs whose file is gone, ld.so.preload; and the SSH keys, accounts, sudoers, startup files, listening ports and login-log sizes the management node compares.",

		Params: nil,

		Script: &ScriptSpec{
			Interpreter: "/bin/bash",
			ScriptPath:  neverDoCheckScript,
			Args:        nil,
			StdinFrom:   nil,
		},

		// The setuid walk is the long part: every file on every local
		// filesystem, at idle IO priority, bounded at 150 s by the script.
		Timeout: 4 * time.Minute,
	})
}

// neverDoCheckScript is the shipped check, site-root relative.
const neverDoCheckScript = "maintenance_scripts/sysadmin_tools/never_do_check.sh"
