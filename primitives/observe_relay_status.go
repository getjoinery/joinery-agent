package primitives

import "time"

// relay_status: this site's view of its mail relay. The relay has no agent
// and no shell by design; when mail stops, the question is which side
// stopped, and the site's own record answers most of it: the version and
// health the relay last reported, when this site last pushed its map, when it
// last pulled and whether that pull emptied the queue, how much is held, which
// kind of transport key mail is sealed to, and whether mail is arriving.
//
// A SCRIPT WORD: the record is the mailbox plugin's (RelayStatusReport::status,
// which knows what each column means), so the platform answers and this word
// carries it. What runs is maintenance_scripts/sysadmin_tools/relay_status.php,
// verified against the signed release manifest, with no argv and no stdin.
//
// HOSTILE-CALLER REVIEW (rule 5 of specs/agent_recipes_and_vocabulary.md).
//
// What is the worst a compromised management node can do with this word?
// Learn the relay's version, whether it answered, when mail was pushed and
// pulled, how many messages arrived in the last hour and day, and whether the
// transport key is the old kind or the new. Operational aggregates of the
// grade check_status already carries.
//
// What it cannot do:
//
//   - Choose anything. NO PARAMETERS: not a relay, not a mailbox, not a window.
//   - Read mail or learn who it is for. Versions, times, counts, booleans and
//     short state words; never an address, a domain, a subject or the relay's
//     free-text detail (rule 8: no member data crosses).
//   - Learn a key. It says which KIND the transport key is, never the key.
//   - Reach the relay. The script reads this site's database; the relay is
//     not asked.
//   - Change anything. The script never rebuilds the map, because building it
//     can mint a transport key.
//
// No owner switch: it reads no log and no message. Not redacted: every value
// is one the script composed.
//
// OBSERVE: a node whose policy accepts only observe words can trust that this
// one writes nothing. Not a machine word: the record is a site's.
func init() {
	Register(Primitive{
		Name:        "relay_status",
		Class:       ClassObserve,
		Description: "This site's view of its mail relay: the version and health it last reported, the map push, pickup and held mail, the transport key's kind and generation, and mail arriving in the last hour and day. No addresses, no keys.",

		// Empty on purpose. See the review above.
		Params: nil,

		Script: &ScriptSpec{
			Interpreter: "/usr/bin/php",
			ScriptPath:  relayStatusScript,
			Args:        []string{},
		},

		// A handful of column reads and two indexed counts.
		Timeout: 2 * time.Minute,
	})
}

// relayStatusScript is the shipped script, site-root relative.
const relayStatusScript = "maintenance_scripts/sysadmin_tools/relay_status.php"
