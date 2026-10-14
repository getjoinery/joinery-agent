package primitives

import "time"

// reboot_machine: reboot this machine a few seconds from now, so the job that
// asked reports first, or refuse and say why.
//
// The word specs/agent_recipes_and_vocabulary.md's running list asked for on
// 2026-10-10. A data root move ends with a reboot (the old copies stay until
// the host has booted with the data root working), nothing on the plane could
// reboot a machine, and every production host had shown "Reboot required" for
// one to seven days. The owner rebooted from the provider's console, and on a
// server outside our accounts only its owner could.
//
// A SCRIPT WORD: only script.go may start a process. What runs is
// maintenance_scripts/sysadmin_tools/reboot_machine.sh, verified against the
// signed release manifest, with no argv and no stdin. The reboot itself is a
// transient systemd timer twenty seconds out, outside this job's process
// group, so the job ends and reports before the machine goes down.
//
// HOSTILE-CALLER REVIEW (rule 5 of specs/agent_recipes_and_vocabulary.md).
//
// What is the worst a compromised management node can do with this word?
// Take the machine's sites down for the length of a reboot, as often as it
// asks. That is an outage it could already cause by stopping a unit
// (restart_unit) or a container, and it is the same thing the provider's
// console grants whoever holds the account; nothing is lost, and every
// service comes back the way the machine's own boot brings it.
//
// What it cannot do:
//
//   - Choose anything. NO PARAMETERS: not a delay, not a kernel, not "power
//     off" or "halt". One reboot, REBOOT_DELAY seconds out, compiled in the
//     script. A reboot already scheduled is reported, not doubled.
//   - Strand an encrypted machine. Rule 3, fail closed: the script refuses
//     where the boot would wait for a person to type a recovery key (an
//     encrypted data root naming no escrow holder, or one being encrypted,
//     decrypted or re-keyed), where a package is half-installed, and where
//     the host's installers or the data root script hold their lock.
//   - Reach a server from inside a site container. A container is not a
//     machine; the script refuses there, and its server reboots from its own
//     node.
//
// OPERATE, not destructive: it changes running state and loses no data (rule
// 9). A node whose policy accepts only observe words refuses it.
func init() {
	Register(Primitive{
		Name:        "reboot_machine",
		Class:       ClassOperate,
		Machine:     true,
		Description: "Reboot this machine twenty seconds from now, after this job reports; refused in a site container, while packages install or the host's installers run, and where an encrypted data root would wait at boot for its recovery key.",

		// Empty on purpose. See the review above.
		Params: nil,

		Script: &ScriptSpec{
			Interpreter: "/bin/bash",
			ScriptPath:  rebootMachineScript,
			Args:        nil,
			StdinFrom:   nil,
		},

		// The script may wait up to thirty seconds for each of two locks
		// before it refuses; scheduling the timer takes a moment.
		Timeout: 3 * time.Minute,
	})
}

// rebootMachineScript is the shipped script, site-root relative.
const rebootMachineScript = "maintenance_scripts/sysadmin_tools/reboot_machine.sh"
