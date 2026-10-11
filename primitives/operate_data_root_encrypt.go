package primitives

import (
	"context"
	"time"
)

// data_root_encrypt, data_root_decrypt: encrypt this machine's data root
// where it stands, or undo it (specs/hosted_data_promise_disk_encryption.md
// D5, WP3). data_root_rekey: re-encrypt it under a new volume key, after a
// recovery key that may have leaked (D8, WP7).
//
// SCRIPT WORDS: maintenance_scripts/install_tools/joinery_data_root.sh,
// verified against the signed release manifest, run as `encrypt` (with
// --keep-provider-layer when asked), `decrypt` or `rekey`. The script's start is the
// whole of the downtime, seconds; the encryption itself then runs for hours in
// joinery-data-encrypt.service, at idle I/O priority, and outlives this word.
// It is not a detached unit in DetachedUnits' sense: the machine serves and
// takes other work while it runs.
//
// The keys never cross: the script makes the volume key and the driving slot's
// secret on the machine, seals both to the recovery recipient already on the
// machine, and keeps them in /run.
//
// HOSTILE-CALLER REVIEW (rule 5).
//
// What is the worst a compromised management node can do with these words?
// Encrypt the data root to the recovery key the machine already holds (the
// owner's, or the operator's), or decrypt it back: the data stays readable to
// its owner either way, and the site is down for the seconds of the start.
// Re-encrypt it under a new volume key, sealed to that same recovery key:
// hours of disk work at idle priority, and its escrow slot made again with a
// new secret. None names a key, a path or a recipient. Accepted.
func init() {
	Register(Primitive{
		Name:        "data_root_encrypt",
		Class:       ClassOperate,
		Machine:     true,
		Description: "Encrypt this machine's data root where it stands: its services stop for seconds, then it encrypts online, at idle priority, for hours.",
		Params: []ParamSpec{
			// The five machines that predate the one-layer rule keep the
			// provider's disk encryption as well (D-L); the management node
			// says so here, and nothing else does.
			{Name: "keep_provider_layer", Type: ParamBool},
		},
		Script: &ScriptSpec{
			Interpreter: "/bin/bash",
			ScriptPath:  dataRootMigrateScript,
			ArgsFrom: func(ctx context.Context, env *ExecEnv, p Params) ([]string, error) {
				if p.Bool("keep_provider_layer") {
					return []string{"encrypt", "--keep-provider-layer"}, nil
				}
				return []string{"encrypt"}, nil
			},
		},
		Timeout: 15 * time.Minute,
	})
	Register(Primitive{
		Name:        "data_root_decrypt",
		Class:       ClassOperate,
		Machine:     true,
		Description: "Undo the data root's encryption: back to plain, online, from wherever it stands.",
		Params:      []ParamSpec{},
		Script: &ScriptSpec{
			Interpreter: "/bin/bash",
			ScriptPath:  dataRootMigrateScript,
			Args:        []string{"decrypt"},
		},
		Timeout: 15 * time.Minute,
	})
	Register(Primitive{
		Name:        "data_root_rekey",
		Class:       ClassOperate,
		Machine:     true,
		Description: "Re-encrypt the data root under a new volume key, online, at idle priority, for hours: a recovery key that may have been seen no longer opens a copy of its disk made from then on.",
		Params:      []ParamSpec{},
		Script: &ScriptSpec{
			Interpreter: "/bin/bash",
			ScriptPath:  dataRootMigrateScript,
			Args:        []string{"rekey"},
		},
		Timeout: 15 * time.Minute,
	})
}
