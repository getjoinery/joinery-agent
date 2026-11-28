package primitives

import "time"

// mail_log_summary: what this machine's own Postfix did with the mail sent to
// the site over the last hours, compiled from the journal into counts — how
// many connections came, how many messages were delivered, deferred, refused
// by the delivery handler or refused by Postfix and why — and the newest 20
// outcomes with their time and the sender's and recipient's domains
// (specs/mailbox_diagnosis_words.md WP3).
//
// It exists because of beta tester Ian's node: a test message from Gmail and
// no way to ask what the mail server did with it. Postfix's raw lines are not
// something to carry: each names both full addresses, the sending server's
// address, hostname and greeting name, and the Message-ID.
//
// A SCRIPT WORD, as unit_journal is: only script.go may start a process
// (TestOnlyScriptFileStartsProcesses), and this word needs journalctl. What
// runs is maintenance_scripts/sysadmin_tools/mail_log_summary.php, verified
// against the signed release manifest before it runs as root, with one argv
// element, the hours, and no stdin. The script reads the journal and composes
// the whole answer; this file only registers the word, and the parse ships
// with the site release.
//
// HOSTILE-CALLER REVIEW (rule 5 of specs/agent_recipes_and_vocabulary.md).
//
// The worst a compromised management node can do, on a node whose owner has
// left log access on: learn, over at most the last week, how much mail the
// site was sent, how much was refused and why, and the domain of each of the
// last 20 senders. For a one-person domain that names the sender, so this is
// "which domains wrote, and for a personal domain who"; less than
// log_table_tail table=requests already returns behind the same switch.
//
// What it cannot do:
//
//   - Name a unit, a file or a pattern. `hours` (1 to 168) is the only
//     parameter, checked again by the script; the journal matches are
//     compiled there.
//   - Read message content. Postfix logs none here (no header_checks, no
//     SASL), and the delivery handler returns only an exit code.
//   - Reach a remote server's text. Every output value is a compiled word, a
//     count, a time to the minute, or a domain read from a fixed field and
//     checked against the ASCII domain pattern (a recipient domain only when
//     it is one of the site's own). No IP, hostname, local part, Message-ID or
//     queue id is put in the answer, so Redact is false: there is nothing for
//     the redactor to find, and it would mangle the domains.
//   - Read without the owner's leave. RequiresLogAccess, and not a machine
//     word: on a siteless container host the word is not offered at all.
//   - Flood the plane. 20 recent rows and a fixed set of counts.
//
// OBSERVE: journalctl is a read.
func init() {
	Register(Primitive{
		Name:        "mail_log_summary",
		Class:       ClassObserve,
		Description: "What this machine's Postfix did with mail sent to the site over the last hours (1 to 168): connections, deliveries, deferrals, the handler's refusals and Postfix's refusals by compiled reason, and the newest 20 outcomes with their time and domains; never an address, IP, hostname or remote text. Refused unless the site's owner allows log access.",
		Params: []ParamSpec{
			{Name: "hours", Type: ParamInt, Min: 1, Max: mailLogSummaryMaxHours},
		},
		RequiresLogAccess: true,

		Script: &ScriptSpec{
			Interpreter: "/usr/bin/php",
			ScriptPath:  mailLogSummaryScript,
			Args:        []string{"{hours}"},
			// Every value the script prints is compiled or pattern-checked.
			Redact:    false,
			StdinFrom: nil,
		},

		// One journal read of at most 50,000 entries.
		Timeout: 2 * time.Minute,
	})
}

const (
	mailLogSummaryScript   = "maintenance_scripts/sysadmin_tools/mail_log_summary.php"
	mailLogSummaryMaxHours = 168
)
