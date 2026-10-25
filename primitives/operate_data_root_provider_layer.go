package primitives

import (
	"regexp"
	"time"
)

// data_root_provider_layer: record on this machine what its management node
// knows of the provider's own disk encryption under it (enabled or disabled),
// the one fact about it nothing on the machine can read from the provider
// (specs/site_copy_final_test.md E2, B114).
//
// One layer is the rule: a machine whose provider encrypts its disk is copied
// onto a new server born with ours and the provider's off, never encrypted
// where it stands. The management node refuses that on its own node page; the
// machine's site has its own Backups page, which asks root, and root runs
// joinery_data_root.sh encrypt. With the fact recorded here, that script
// refuses too, unless --keep-provider-layer (a management node, which never
// copies itself), and the site's page says why.
//
// SCRIPT WORDS: maintenance_scripts/install_tools/joinery_data_root.sh,
// verified against the signed release manifest, run as `provider-layer
// enabled|disabled`. It writes one file, /etc/joinery/data-root/provider_layer.
//
// HOSTILE-CALLER REVIEW (rule 5 of specs/agent_recipes_and_vocabulary.md).
//
// What is the worst a compromised management node can do with this word?
// Say disabled where the provider's layer is on: the owner may then encrypt
// in place and hold two layers, which costs a key to keep and exposes
// nothing. Say enabled where it is off: the owner's own Backups page points
// them at a copy instead of encrypting in place. Neither reads, moves or
// unlocks anything; the data stays as readable to its owner as it was.
// Accepted.
//
// What it cannot do: name a path, a key or another value. The one parameter
// is enabled or disabled, matched here and again by the script; it touches
// no volume, no key slot and no recipient.
//
// It runs on a quiet site too (QuietAny), as data_root_recipient does: the
// provider's layer is the machine's, never the site's.
//
// OPERATE, not destructive: it changes a recorded fact and loses no data.
func init() {
	Register(Primitive{
		Name:        "data_root_provider_layer",
		Class:       ClassOperate,
		Machine:     true,
		Quiet:       QuietAny,
		Description: "Record what this machine's management node knows of the provider's own disk encryption under it (enabled or disabled); encrypting the data root where it stands is refused while it is enabled, unless the management node keeps both layers.",
		Params: []ParamSpec{
			{Name: "layer", Type: ParamString, Required: true, MaxLen: 8, Pattern: providerLayerPattern},
		},
		Script: &ScriptSpec{
			Interpreter: "/bin/bash",
			ScriptPath:  dataRootMigrateScript,
			Args:        []string{"provider-layer", "{layer}"},
		},
		Timeout: 1 * time.Minute,
	})
}

// providerLayerPattern is the two values the script takes; unknown is never
// recorded, only the absence of a record.
var providerLayerPattern = regexp.MustCompile(`^(enabled|disabled)$`)
