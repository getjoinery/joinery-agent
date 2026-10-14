package primitives

import "time"

// spam_learning_status: whether what this site's members mark as spam or not
// spam reaches its spam filter. Counts only.
//
// The word specs/agent_recipes_and_vocabulary.md's running list asked for on
// 2026-10-03. Whether a member's Mark as spam on jeremytunnell reached the
// filter took read-only SSH and a hand-written query against the mailbox's
// tables, because the cron log's "Taught 0" cannot tell a correction already
// taught from one never recorded.
//
// A SCRIPT WORD: the counts are the mailbox plugin's own (SpamLearning::status,
// which knows what "pending" and "sealed to a member's window" mean), so the
// platform answers and this word carries it. What runs is
// maintenance_scripts/sysadmin_tools/spam_learning_status.php, verified
// against the signed release manifest, with no argv and no stdin.
//
// HOSTILE-CALLER REVIEW (rule 5 of specs/agent_recipes_and_vocabulary.md).
//
// What is the worst a compromised management node can do with this word?
// Learn how many messages the site's members marked spam or not spam in the
// last week, how many of those were taught, how big the spam corpus is, and
// whether filtering and learning are on. Aggregates of the grade page_probe's
// sizes and site_census's row counts already grant.
//
// What it cannot do:
//
//   - Choose anything. NO PARAMETERS: not a window, not a mailbox, not a user.
//   - Read mail. Counts and two booleans; never a subject, a sender, an
//     address, a token or a row id (rule 8: no member data crosses).
//   - Change anything. The script reads; it teaches nothing and clears
//     nothing.
//
// No owner switch: it reads no log and no message. Not redacted: every value
// is a number, a boolean or a time the script composed.
//
// OBSERVE, and the classification does real work: a node whose policy accepts
// only observe words has to be able to trust that this one writes nothing.
func init() {
	Register(Primitive{
		Name:        "spam_learning_status",
		Class:       ClassObserve,
		Description: "Whether members' spam corrections reach the spam filter: the last week's corrections taught, waiting or skipped, the corpus's size and newest token, and the two policy switches. Counts only.",

		// Empty on purpose. See the review above.
		Params: nil,

		Script: &ScriptSpec{
			Interpreter: "/usr/bin/php",
			ScriptPath:  spamLearningStatusScript,
			Args:        []string{},
		},

		// Two indexed counts and the corpus's size.
		Timeout: 2 * time.Minute,
	})
}

// spamLearningStatusScript is the shipped script, site-root relative.
const spamLearningStatusScript = "maintenance_scripts/sysadmin_tools/spam_learning_status.php"
