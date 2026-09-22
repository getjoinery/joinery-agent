package primitives

import "time"

// unit_journal: why one systemd unit is in the state it is in — its state, the
// result systemd recorded, its exit status, and the last N lines of its
// journal, redacted on this machine before they leave it.
//
// The word specs/agent_recipes_and_vocabulary.md § First words named and
// nothing built. It exists because of a morning the running list records: a
// node's host report named man-db.service as failed, the plane could render
// that name on a card, and there was no way to ask the node why. The whole
// diagnosis had to be reconstructed from job rows on the management node, and
// the answer — a disk that was full for fifteen minutes — was one journal read
// away on the machine itself.
//
// A SCRIPT WORD, not an embedded one, because of the gate: only script.go may
// start a process, and this word needs systemctl and journalctl. The whole of
// what runs is maintenance_scripts/sysadmin_tools/unit_journal.sh, shipped in
// the platform tree, verified against the signed release manifest before it
// runs as root, with two argv elements and no stdin.
//
// HOSTILE-CALLER REVIEW (rule 5 of specs/agent_recipes_and_vocabulary.md).
//
// What is the worst a compromised management node can do with this word? Read,
// on a node whose owner has left log access on, up to 200 redacted journal
// lines of ONE unit from a compiled list of twelve. That is narrower than
// site_log, which is already accepted: a unit's journal is a smaller thing
// than the site's error log, and both are masked by the same redactor before
// they leave.
//
// What it cannot do:
//
//   - Name a unit. `unit` is an ENUM of twelve compiled names, and the script
//     re-validates against its own copy of the list: either refuses alone.
//     There is no pattern, no "all units", no path, and no way to reach a
//     unit that is not here — including sshd, whose journal is a list of who
//     connected from where and is deliberately absent.
//   - Read the whole journal. The line count is 1..200 in the enum spec and
//     clamped again in the script; the script caps each line too, so the
//     agent's 64 KiB output cap is never the thing that bounds the answer.
//   - Read without the owner's leave. RequiresLogAccess: the dispatcher checks
//     the agent_log_access switch before this word runs, and a switch that
//     cannot be read reads OFF.
//   - Carry anything unmasked. ScriptSpec.Redact runs the node's redactor over
//     the script's output before it is returned — credentials, the personal
//     half of an address, IP literals and opaque tokens are masked here, on
//     the machine that produced them.
//   - Change anything. systemctl show and journalctl are reads. Clearing a
//     failed unit is a different word, of a different class
//     (reset_failed_unit, operate), on purpose.
//
// OBSERVE, and the classification does real work: a node whose policy accepts
// only observe words has to be able to trust that this one writes nothing.
func init() {
	Register(Primitive{
		Name:        "unit_journal",
		Class:       ClassObserve,
		Description: "One unit's state, result, exit status and last journal lines, from a compiled list of units, redacted on the node; refused unless the site's owner allows log access.",
		Params: []ParamSpec{
			{Name: "unit", Type: ParamEnum, Required: true, Values: unitJournalUnits},
			{Name: "lines", Type: ParamInt, Min: 1, Max: unitJournalMaxLines},
		},
		RequiresLogAccess: true,

		Script: &ScriptSpec{
			Interpreter: "/bin/bash",
			ScriptPath:  unitJournalScript,

			// The only two things a caller supplies, both already validated
			// against the spec above. A "{param}" slot can emit nothing but a
			// value the enum or the range allowed.
			Args: []string{"{unit}", "{lines}"},

			// The journal is the one thing in this vocabulary a script prints
			// that the script did not compose.
			Redact: true,

			StdinFrom: nil,
		},

		// Short. Two local reads; the script bounds each at 20 seconds.
		Timeout: 1 * time.Minute,
	})
}

// unitJournalUnits is the closed list, and a MIRROR of the UNITS array in
// unit_journal.sh and of UNIT_JOURNAL_UNITS on the plane. Three copies on
// purpose: the plane offers the list, this validates against it, and the node
// refuses anything outside it whatever the other two say.
//
// Four of the five units the Host card names (sshd is not among them and is
// not added: its journal is a record of who connected from where, which is
// exactly what host_report refuses to carry), the agent itself, and the
// housekeeping units that turn up failed on an ordinary Debian box.
var unitJournalUnits = []string{
	"fail2ban",
	"apache2",
	"cron",
	"postgresql",
	"joinery-agent",
	"man-db",
	"unattended-upgrades",
	"logrotate",
	"apt-daily",
	"apt-daily-upgrade",
	"fstrim",
	"e2scrub_all",
}

const (
	// unitJournalMaxLines is the agent's cap; the script clamps to the same
	// figure, and the plane offers no more.
	unitJournalMaxLines = 200

	// unitJournalScript is the shipped reader, site-root relative. A constant
	// so the test asserts the same string the registration uses.
	unitJournalScript = "maintenance_scripts/sysadmin_tools/unit_journal.sh"
)
