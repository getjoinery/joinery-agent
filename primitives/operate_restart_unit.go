package primitives

import "time"

// restart_unit: restart one of the host's expected units, and report its
// state before and after.
//
// The word specs/agent_recipes_and_vocabulary.md § First words names, and the
// repair of the service_health recipe (Settled 2026-09-23): a unit that runs
// and does not answer, or that systemd has given up restarting. systemd
// already restarts a crashed unit; this is for the two cases it cannot see.
//
// A SCRIPT WORD, for the gate's reason: only script.go may start a process.
// What runs is maintenance_scripts/sysadmin_tools/restart_unit.sh, verified
// against the signed release manifest, with one argv element.
//
// HOSTILE-CALLER REVIEW (rule 5).
//
// What is the worst a compromised management node can do with this word?
// Restart one of five services — Apache, PHP-FPM, PostgreSQL, cron,
// fail2ban — as often as it can dispatch jobs: a site that drops its
// connections every few seconds. That is an outage, not a loss: a restart
// keeps every file and row, and the plane could already cause the same
// outage with apply_update. Accepted, as restart_agent was.
//
// What it cannot do:
//
//   - Name a unit. `unit` is an ENUM of the expected units host_report
//     reads, and the script re-validates against its own copy. The agent is
//     not among them: joinery-agent is restarted only through restart_agent,
//     which proves the new binary answers first (rule 3). sshd is not among
//     them either: a restart that fails is a machine nobody can reach.
//   - Stop without starting, disable, or mask. The script's only changing
//     verb is restart, pinned by its gate.
//   - Read anything. It prints compiled states; no redaction, no log switch.
func init() {
	Register(Primitive{
		Name:        "restart_unit",
		Class:       ClassOperate,
		Machine:     true,
		Description: "Restart one of the host's expected units (fail2ban, Apache, PHP-FPM, cron, PostgreSQL), reporting its state before and after; never the agent, never sshd.",
		Params: []ParamSpec{
			{Name: "unit", Type: ParamEnum, Required: true, Values: restartUnitUnits},
		},

		Script: &ScriptSpec{
			Interpreter: "/bin/bash",
			ScriptPath:  restartUnitScript,
			Args:        []string{"{unit}"},
			StdinFrom:   nil,
		},

		// A PostgreSQL restart flushes; the script bounds the restart at 90
		// seconds and each read at 20.
		Timeout: 4 * time.Minute,
	})
}

// restartUnitUnits is the closed list: host_report.sh's expected units, in
// its order, and a MIRROR of UNITS in restart_unit.sh and of
// RESTART_UNIT_UNITS on the plane. php-fpm is resolved by the script to the
// versioned unit file the host runs.
var restartUnitUnits = []string{
	"fail2ban",
	"apache2",
	"php-fpm",
	"cron",
	"postgresql",
}

const restartUnitScript = "maintenance_scripts/sysadmin_tools/restart_unit.sh"
