package primitives

import "time"

// v1_census: what on this site is still on an old X25519 (v1) key, before the
// release that removes every v1 opener (strategy/v1_key_retirement.md, § Before
// the deletion release). TEMPORARY: the deletion release removes this word,
// its script and the plane's handling of it, together with the v1 code.
//
// A SCRIPT WORD: what counts as a v1 key is the platform's, so the platform
// answers and this word carries it. What runs is
// maintenance_scripts/sysadmin_tools/v1_census.php, verified against the
// signed release manifest, with no argv and no stdin.
//
// HOSTILE-CALLER REVIEW (rule 5 of specs/agent_recipes_and_vocabulary.md).
//
// What is the worst a compromised management node can do with this word?
// Learn how many vaults are on the old key and the ids and permission levels of
// their owners, which tables hold how many old sealed values, how many retired
// keys vault chains keep, the kind of each relay transport key, whose key the
// break-glass copy is sealed to, and the backup keys' kinds. Counts, ids and
// kinds: the grade check_status and recovery_key_report already carry.
//
// What it cannot do:
//
//   - Choose anything. NO PARAMETERS: not a table, not a user, not a column.
//   - Read a value. It counts values by their first characters; no sealed
//     value, key, address or name leaves the node (rule 8).
//   - Change anything. The script runs in a READ ONLY transaction.
//
// No owner switch: it reads no log and no message. Not redacted: every value
// is one the script composed.
//
// OBSERVE: a node whose policy accepts only observe words can trust that this
// one writes nothing. Not a machine word: the record is a site's.
func init() {
	Register(Primitive{
		Name:        "v1_census",
		Class:       ClassObserve,
		Description: "Count what this site still holds on an old X25519 (v1) key: vaults, sealed values by table, vault chains, relay transport keys, break-glass copies and backup keys. Counts, ids and kinds only.",

		// Empty on purpose. See the review above.
		Params: nil,

		Script: &ScriptSpec{
			Interpreter: "/usr/bin/php",
			ScriptPath:  v1CensusScript,
			Args:        []string{},
		},

		// One prefix scan of every text column. The script stops scanning at
		// four minutes and names the tables it did not finish.
		Timeout: 5 * time.Minute,
	})
}

// v1CensusScript is the shipped script, site-root relative.
const v1CensusScript = "maintenance_scripts/sysadmin_tools/v1_census.php"
