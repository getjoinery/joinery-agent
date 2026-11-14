package primitives

import (
	"regexp"
	"time"
)

// mail_test_send: send one fixed test message from one of this site's own
// ordinary mail domains to the one probe mailbox, so a receiver's SPF, DKIM
// and DMARC verdicts on real mail can be read without a person reading
// headers.
//
// The word specs/agent_recipes_and_vocabulary.md's running list asked for on
// 2026-11-14 ("does mail from this domain pass at a receiver"). What runs is
// maintenance_scripts/sysadmin_tools/mail_test_send.php, verified against the
// signed release manifest, with the domain as its one argument, as the site's
// web user. It answers with the token in the message's subject; the verdicts
// are read at the receiver.
//
// HOSTILE-CALLER REVIEW (rule 5; reviewed by reviewer2 2026-11-14).
//
// What is the worst a compromised management node can do with this word?
// Make a site send one fixed message, as one of its own ordinary domains, to
// one mailbox we own, at most once per domain per ten minutes. It cannot reach
// a third party, choose a word of the message, or send as a protected domain.
// The cost it can impose is a little of the site's mail provider quota.
//
// What it cannot do:
//
//   - Choose the recipient, the sender's local part, the subject or the body:
//     all compiled into the script. The token is made on the node.
//   - Send as a domain the site does not host, an IMAP-source domain, or a
//     protected domain: refused before anything is sent. A protected domain's
//     mail leaves only through its owner's signed-in session; no word goes
//     round that.
//   - Send while the site's email test mode or dry run is on, where the
//     answer would be the trap's, not a receiver's.
//   - Send often: one per domain per ten minutes, kept on the node.
//
// OPERATE: it sends mail, which is an effect outside the machine. Not
// destructive (rule 9): nothing is deleted.
func init() {
	Register(Primitive{
		Name:        "mail_test_send",
		Class:       ClassOperate,
		Description: "Send one fixed test message from one of this site's own ordinary mail domains to the one probe mailbox, so a receiver's SPF, DKIM and DMARC verdicts can be read. Refused for a protected domain, while email test mode or dry run is on, and more than once per domain per ten minutes.",

		Params: []ParamSpec{
			// One of the site's own ordinary mail domains; the script refuses
			// any other before anything is sent.
			{Name: "domain", Type: ParamString, Required: true, MaxLen: 253, Pattern: mailTestSendDomainPattern},
		},

		Script: &ScriptSpec{
			Interpreter: "/usr/bin/php",
			ScriptPath:  mailTestSendScript,
			Args:        []string{"{domain}"},
			AsSiteUser:  true,
		},

		Timeout: 2 * time.Minute,
	})
}

const mailTestSendScript = "maintenance_scripts/sysadmin_tools/mail_test_send.php"

// mailTestSendDomainPattern is the shape the script checks again for itself.
var mailTestSendDomainPattern = regexp.MustCompile(`^[a-z0-9.-]+\.[a-z]{2,}$`)
