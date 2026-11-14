package primitives

import (
	"regexp"
	"time"
)

// mailbox_status: what this site's mailbox knows about its own mail, read
// without changing anything.
//
// With no domain: whether members' spam corrections reach the spam filter
// (counts only) and the list of the site's own mail domains. With a domain,
// one of those: the Setup tab's domain rows (id, status, severity, label),
// the domain's send-protection flags, a fixed list of its DNS names read
// through this machine's resolver beside each of the zone's authoritative
// nameservers, and how the domain's mail left the site.
//
// The words specs/agent_recipes_and_vocabulary.md's running list asked for on
// 2026-10-03 (spam learning) and 2026-11-14 (send protection on the owner's
// production node: the Setup cards stayed red after the DNS was right, and
// nothing could read what the node saw). This word is spam_learning_status
// widened, under the owner's 2026-11-14 suspension of rule 11 to the beta.
//
// A SCRIPT WORD: what runs is
// maintenance_scripts/sysadmin_tools/mailbox_status.php, verified against the
// signed release manifest, with the domain as its one argument. It runs as the
// site's web user, so a row about a file the web user cannot read says what
// the Setup tab says.
//
// HOSTILE-CALLER REVIEW (rule 5 of specs/agent_recipes_and_vocabulary.md;
// reviewed by reviewer2 2026-11-14, B2-B7).
//
// What is the worst a compromised management node can do with this word?
// Learn the site's mail domains, each domain's Setup verdicts and
// send-protection flags, the public DNS for a fixed set of that domain's
// names, and counts of how its mail left. All of it is configuration or
// public DNS; aggregates at the grade site_census already grants.
//
// What it cannot do:
//
//   - Name a host to look up. The domain must match the compiled pattern
//     here, and the script refuses one that is not a live hosted domain of
//     this site before any lookup, so the node is never a DNS lookup service.
//     The names read under it are a fixed list the script composes.
//   - Read member data. A check row carries its compiled id, status, severity
//     and label, never its summary or detail (which can name a recipient) or
//     its fix (values to publish). No row id, no owner id (owner set: yes or
//     no), no key, no published DKIM value.
//   - Make the site call out or write. The checks run in the engine's
//     read-only mode: no fleet service claim, verification or filing, no
//     provider API, no setting written. DNS queries go to the domain's own
//     nameservers and this machine's resolver only.
//   - Run long. One domain, a fixed name list, the script's own caps.
//
// No owner switch: it reads no log and no message. Not redacted: the script
// composes every value from compiled strings, flags, counts and public DNS.
//
// OBSERVE, and the classification does real work: a node whose policy accepts
// only observe words has to be able to trust that this one writes nothing.
func init() {
	Register(Primitive{
		Name:        "mailbox_status",
		Class:       ClassObserve,
		Description: "This site's mailbox: with no domain, the spam-learning counts and the site's own mail domains; with one of those domains, its Setup rows (id, status, label), send-protection flags, its DNS read here beside the zone's own nameservers, and how its mail left. Changes nothing; calls no outside service.",

		Params: []ParamSpec{
			// One of the site's own mail domains; the script refuses any
			// other before a lookup.
			{Name: "domain", Type: ParamString, Required: false, MaxLen: 253, Pattern: mailboxStatusDomainPattern},
		},

		Script: &ScriptSpec{
			Interpreter: "/usr/bin/php",
			ScriptPath:  mailboxStatusScript,
			Args:        []string{"{domain}"},
			AsSiteUser:  true,
		},

		// The domain rows, a few DNS lookups to the zone's nameservers.
		Timeout: 2 * time.Minute,
	})
}

const mailboxStatusScript = "maintenance_scripts/sysadmin_tools/mailbox_status.php"

// mailboxStatusDomainPattern is the shape the script checks again for itself.
var mailboxStatusDomainPattern = regexp.MustCompile(`^[a-z0-9.-]+\.[a-z]{2,}$`)
