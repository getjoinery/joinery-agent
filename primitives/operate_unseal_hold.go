package primitives

import "time"

// unseal_hold: drop every open vault window on this node and hold the unseal
// daemon, so no Private vault opens until root lifts the hold
// (specs/unseal_daemon.md § The sentinel's hold).
//
// The sentinel's word for an open infiltration case: a member's window ends
// on their next request, and the daemon refuses every open while the hold
// stands. The hold file survives a crash of the daemon (it restarts held)
// and stops the site from falling back to holding keys in its pool.
//
// A SCRIPT WORD: what runs is
// maintenance_scripts/install_tools/joinery_unseal/launch.sh, verified against
// the signed release manifest, with the two literal arguments `hold --all`. It
// writes /run/joinery-unseal/KEY.hold for every site whose daemon is
// installed here and sends that daemon SIGUSR1.
//
// HOSTILE-CALLER REVIEW (rule 5 of specs/agent_recipes_and_vocabulary.md).
//
// What is the worst a compromised management node can do with this word?
// Lock every member of this node out of their Private vault until root lifts
// the hold: an outage of encrypted mail and files, with nothing read and
// nothing lost (every key is still wrapped in the database under the
// member's own unlockers). Accepted: that is exactly the word's job when a
// case is open, and the hold is visible on the node's health page, its
// admin notice and the fleet dashboard.
//
// What it cannot do:
//
//   - Lift a hold. There is deliberately no lift word: lifting is root's
//     alone (/var/lib/joinery-unseal/KEY/launch lift --all), so a compromised plane cannot
//     undo the sentinel's hold during the case that set it.
//   - Read or write a key. The daemon's answer to SIGUSR1 is to zero every
//     key it holds; nothing comes back.
//   - Name a site, a path or a signal. It takes no parameters.
//
// OPERATE: it changes what the node does (every Private unlock refused).
func init() {
	Register(Primitive{
		Name:        "unseal_hold",
		Class:       ClassOperate,
		Description: "Drop every open vault window on this node and hold the unseal daemon, so no Private vault opens until root lifts the hold; takes no parameters, and there is no lift word.",
		Params:      nil,

		Script: &ScriptSpec{
			Interpreter: "/bin/bash",
			ScriptPath:  unsealLaunchScript,
			Args:        []string{"hold", "--all"},
			StdinFrom:   nil,
		},

		// A file and a signal per site.
		Timeout: 1 * time.Minute,
	})
}

// unsealLaunchScript is the shipped launcher, site-root relative.
const unsealLaunchScript = "maintenance_scripts/install_tools/joinery_unseal/launch.sh"
