package primitives

import "time"

// reset_failed_unit: clear systemd's record that one unit failed, and report
// the unit's state before and after.
//
// The counterpart of unit_journal (specs/disk_headroom_and_unit_diagnosis.md
// § 9). A unit that failed once stays named as failed until a human logs in or
// the machine reboots — man-db.service, after one full disk, would be named on
// the Host card for ever — and logging in is the thing this fleet is built to
// avoid. unit_journal answers why; this clears the record once the answer is
// known.
//
// A SCRIPT WORD for the same reason as unit_journal: only script.go may start
// a process. What runs is maintenance_scripts/sysadmin_tools/reset_failed_unit.sh,
// verified against the signed release manifest, with one argv element.
//
// HOSTILE-CALLER REVIEW (rule 5 of specs/agent_recipes_and_vocabulary.md).
//
// What is the worst a compromised management node can do with this word?
// Clear the failed record of one unit from the same compiled list of twelve
// that unit_journal reads — making a failure disappear from the next host
// report until the unit fails again. That hides a fact; it changes nothing
// that runs.
//
// What it cannot do:
//
//   - Name a unit. `unit` is the SAME enum as unit_journal's, and the script
//     re-validates against its own copy: either refuses alone. In particular
//     it can never run `systemctl reset-failed` with no unit, which clears
//     every unit on the machine.
//   - Start, stop, restart or reload anything. reset-failed clears a record;
//     a unit that is still broken fails again on its next start, which is the
//     honest outcome, and the next host report says so.
//   - Read anything. It prints a state, a sub-state and a result before and
//     after — compiled facts, reduced to a safe character set — and nothing
//     from a journal, so it needs neither the owner's log switch nor the
//     redactor.
//
// OPERATE, not observe: it changes what the machine reports about itself. A
// node whose policy accepts only observe words refuses it, and the job record
// on both ends is its ledger, as for every operate word the plane dispatches.
// It is deliberately not folded into host_converge: clearing a failure should
// be something somebody chose to do, not a side effect of housekeeping.
func init() {
	Register(Primitive{
		Name:        "reset_failed_unit",
		Class:       ClassOperate,
		Description: "Clear systemd's failed record for one unit from a compiled list (systemctl reset-failed), reporting its state before and after; starts, stops and restarts nothing.",
		Params: []ParamSpec{
			{Name: "unit", Type: ParamEnum, Required: true, Values: unitJournalUnits},
		},

		Script: &ScriptSpec{
			Interpreter: "/bin/bash",
			ScriptPath:  resetFailedUnitScript,
			Args:        []string{"{unit}"},
			StdinFrom:   nil,
		},

		// Three local systemctl calls; the script bounds each at 20 seconds.
		Timeout: 2 * time.Minute,
	})
}

// resetFailedUnitScript is the shipped script, site-root relative.
const resetFailedUnitScript = "maintenance_scripts/sysadmin_tools/reset_failed_unit.sh"
