package primitives

import (
	"regexp"
	"time"
)

// A recovery public key as the Backups page shows it: 32 bytes, base64.
var recoveryPublicKeyPattern = regexp.MustCompile(`^[A-Za-z0-9+/]{43}=$`)

// data_root_recipient: the recovery public key this machine's encrypted data
// root's break-glass copy is sealed to (specs/hosted_data_promise_disk_encryption.md
// D2, D8). A hosted machine's is its management node's own proven recovery
// key, which the management node sends; a self-hosted site sets its own from
// its Backups page. A SCRIPT WORD: joinery_data_root.sh recipient
// --set-by=operator KEY, which checks the key's shape and records who set it
// (the site's page says whose key it is). Under a volume already sealed to
// another key, the next tick seals the break-glass copy again to this one.
//
// HOSTILE-CALLER REVIEW (rule 5). A compromised management node could name a
// key it holds before an encryption, so that the break-glass copy opens for
// it. It already holds the escrow secret of every machine it manages, which
// opens the volume outright; this widens nothing. Accepted.
//
// It runs on a quiet site too (QuietAny), as data_root_enrol does: the
// machine's break-glass copy is the machine's, never the site's.
func init() {
	Register(Primitive{
		Name:        "data_root_recipient",
		Class:       ClassOperate,
		Machine:     true,
		Quiet:       QuietAny,
		Description: "Set the recovery public key this machine's encrypted data root is sealed to.",
		Params: []ParamSpec{
			{Name: "public_key", Type: ParamString, Required: true, MaxLen: 44, Pattern: recoveryPublicKeyPattern},
		},
		Script: &ScriptSpec{
			Interpreter: "/bin/bash",
			ScriptPath:  dataRootMigrateScript,
			Args:        []string{"recipient", "--set-by=operator", "{public_key}"},
		},
		Timeout: 1 * time.Minute,
	})
}
