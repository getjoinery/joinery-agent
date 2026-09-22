package primitives

import "time"

// host_report: the machine this agent runs on, as one bounded JSON object —
// failed units, the expected units and their state, fail2ban's jails and how
// many addresses each has banned, how many SSH logins failed in the last day,
// sshd's password and root-login posture, disk, memory, swap, whether a reboot
// is pending, and when unattended-upgrades last ran.
//
// It is the first observe word of specs/agent_tier1_recipes.md, and it is
// deliberately NOT part of check_status (settled question Q2 there). They
// differ in subject: check_status is the SITE — web-root disk, load, the
// Joinery version, the database list, the certificate — with keys pinned to
// the management API's stats endpoint. host_report is the MACHINE: units,
// jails, sshd, the journal, reboot-required, unattended-upgrades. It repeats
// disk, memory and swap on purpose, so a recipe reads one word per check; that
// overlap is by design and is not to be deduplicated.
//
// A SCRIPT WORD, not an embedded one, because of the gate: only script.go may
// start a process, and this word needs systemctl, fail2ban-client, sshd -T and
// journalctl. So the whole of what runs is maintenance_scripts/sysadmin_tools/
// host_report.sh, shipped in the platform tree, verified against the signed
// release manifest before it runs as root, with no argv and no stdin. The
// agent's part is this registration; the shape of the answer is the script's,
// and tests/integration/host_report_gate.sh on the platform pins it.
//
// HOSTILE-CALLER REVIEW (rule 5 of specs/agent_recipes_and_vocabulary.md).
//
// What is the worst a compromised management node can do with this word?
// Learn the node's sshd posture, which jails run and how full they are, and
// which units have failed — reconnaissance. The owner accepted that on
// 2026-09-13 (agent_tier1_recipes.md, "Accepted risk" under Burn-in) as the
// price of the Host card: the accepted-limits table already grants the plane
// sight of the machine, and a card that cannot see sshd or fail2ban cannot say
// whether the guard in front of the host is standing.
//
// What it cannot do:
//
//   - Steer anything. NO PARAMETERS: not a unit name, not a jail, not a line
//     count, not a path. Params is nil, so a job carrying any field at all is
//     refused on the node before the script is reached, and Args is nil, so
//     there is no argv element for a future edit to make wire-supplied.
//   - Read what it likes. The script reads a COMPILED list of facts and prints
//     a COMPILED set of keys; there is no "read this file" and no "run this
//     unit's journal" here (unit_journal and file_head are later words with
//     closed lists of their own). What sshd -T prints is reduced to two
//     values; the config file itself never travels.
//   - Change anything. Every command the script runs is a read: systemctl
//     show/list-units, fail2ban-client status, sshd -T, journalctl, df, /proc,
//     stat. The sshd posture is reported, never written.
//   - Learn who is attacking the node, or from where. The SSH auth-failure
//     figure is a COUNT and nothing else — no usernames, no source addresses,
//     ever. The spec records that line, and the platform gate pins the script
//     to it: a report whose journal section carries anything but a number
//     fails the gate.
//   - Flood the plane. Every list is capped in the script (20 units, 20 jails),
//     every string is capped, a fact the script cannot read is the string
//     "unknown" for that key and never an error for the whole report, and the
//     framework's 64 KiB output cap sits above all of it as a backstop that is
//     never the thing that bounds the answer.
//
// OBSERVE, and that classification is doing real work: a node whose policy
// accepts only observe words has to be able to trust that this one writes
// nothing, and it does not.
func init() {
	Register(Primitive{
		Name:        "host_report",
		Class:       ClassObserve,
		Machine:     true,
		Description: "Failed units, expected units, fail2ban jails, SSH auth-failure count, sshd posture, disk, memory, swap, reboot-required, unattended-upgrades: the machine, as one bounded JSON object.",

		// Empty on purpose. See the review above: every parameter not declared
		// here is one the plane can never abuse.
		Params: nil,

		Script: &ScriptSpec{
			Interpreter: "/bin/bash",

			// Site-root relative, outside public_html: sysadmin_tools ships
			// whole in the core archive, so it resolves to the manifest at the
			// site root and is verified there before it runs as root. On a
			// siteless machine it resolves against the support bundle, which
			// lists it for the same reason.
			ScriptPath: hostReportScript,

			// No argv at all, and no stdin. The script reads nothing from its
			// caller; a channel that exists is a channel someone will find a
			// use for.
			Args:      nil,
			StdinFrom: nil,
		},

		// Short. Every read the script makes is local and answers in
		// milliseconds; the one that can stall is journalctl over a large
		// journal, and a report still running after a minute is a report the
		// caller should stop waiting for. The script itself bounds each
		// command tighter than this.
		Timeout: 1 * time.Minute,
	})
}

// hostReportScript is the shipped report, site-root relative. A constant so the
// test asserts the same string the registration uses rather than a copy that
// can drift.
const hostReportScript = "maintenance_scripts/sysadmin_tools/host_report.sh"
