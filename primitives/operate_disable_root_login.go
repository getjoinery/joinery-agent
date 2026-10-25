package primitives

import "time"

// disable_root_login: turn root SSH login off on this machine, for good, and
// report what sshd will do now.
//
// The word specs/implemented/beta_break_glass_root_access.md 5.3 asks for. The agent had
// no operation that changes sshd: restart_unit refuses sshd by design, and the
// only thing that turned root login off was the management node's
// retire_install_password session, which logs in with the password. This one
// needs no password and no vault: a kept box whose holder's vault is lost, a
// box whose cleanup failed, or any machine an operator wants closed to root.
//
// A SCRIPT WORD: only script.go may start a process. What runs is
// maintenance_scripts/sysadmin_tools/disable_root_login.sh, verified against
// the signed release manifest, with no argv and no stdin. It writes
// PermitRootLogin no in a drop-in that sorts first, checks it with sshd -t,
// reloads a running sshd, and is done only when sshd -T reads no.
//
// HOSTILE-CALLER REVIEW (rule 5 of specs/agent_recipes_and_vocabulary.md).
//
// What is the worst a compromised management node can do with this word?
// Close root SSH login on every machine it reaches. It grants nobody
// anything. On a hosted box the provider's console still logs in; on a
// self-hosted box the owner's way back is a sudo account or the console, the
// word exists only on a plane the owner connected, and install.sh already
// warns when root is the only way in. Accepted.
//
// What it cannot do:
//
//   - Open anything. NO PARAMETERS: the one value it writes is no, compiled
//     in the script. It never removes a file, so it cannot undo itself or
//     anyone's setting; it changes no other account's login, no password and
//     no key.
//   - Lock out open sessions: a reload restarts sshd's listener only.
//   - Reach a server from inside a site container. Machine: true lets a
//     siteless host agent report the word; it does not stop a site agent from
//     reporting it, so the management node refuses a container node, and the
//     script refuses in a container too.
//
// OPERATE, not destructive: it changes a setting and loses no data (rule 9).
func init() {
	Register(Primitive{
		Name:        "disable_root_login",
		Class:       ClassOperate,
		Machine:     true,
		Description: "Turn root SSH login off on this machine for good (PermitRootLogin no in a drop-in that sorts first), checked with sshd -t, reloading a running sshd, done only when sshd -T reads no; refused in a site container.",

		// Empty on purpose. See the review above.
		Params: nil,

		Script: &ScriptSpec{
			Interpreter: "/bin/bash",
			ScriptPath:  disableRootLoginScript,
			Args:        nil,
			StdinFrom:   nil,
		},

		// sshd -t, a reload and two sshd -T reads, each bounded at 20 seconds.
		Timeout: 3 * time.Minute,
	})
}

// disableRootLoginScript is the shipped script, site-root relative.
const disableRootLoginScript = "maintenance_scripts/sysadmin_tools/disable_root_login.sh"
