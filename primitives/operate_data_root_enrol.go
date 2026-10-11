package primitives

import (
	"context"
	"errors"
	"time"
)

// data_root_enrol: enrol this machine's encrypted data root with its
// management node as escrow holder (specs/hosted_data_promise_disk_encryption.md
// D3, WP2).
//
// The management node queues it once the machine has joined and reported an
// encrypted, open data root with no escrow there. It carries nothing: the
// machine signs its enrolment with its unlock identity and with its node key,
// which is what tells the holder the identity is this node's; the holder mints
// the secret and hands it over once, in answer, over TLS; the machine adds it
// as a key slot and says which. The secret is never in this job, its row or
// its log.
func init() {
	Register(Primitive{
		Name:        "data_root_enrol",
		Class:       ClassOperate,
		Machine:     true,
		Description: "Enrol the encrypted data root with this management node, which then opens it at boot.",
		Run: func(ctx context.Context, env *ExecEnv, p Params) (map[string]interface{}, error) {
			if env.DataRootEnrol == nil {
				return nil, errors.New("this agent cannot enrol an encrypted data root")
			}
			return env.DataRootEnrol(ctx)
		},
		// A slot at the standard count is a second of PBKDF2 or so, and two
		// requests to the holder.
		Timeout: 2 * time.Minute,
	})
}
