package primitives

import (
	"context"
	"errors"
	"regexp"
	"time"
)

// move_to_plane: ask another management node to adopt this machine.
//
// A machine with a site moves from its own admin page; a machine with no site
// (a Docker host) has no page, so its management node asks for it. The node
// stages a fresh keypair for the named management node and files the join
// there, the ask `joinery-agent join --no-wait` makes, and answers the
// fingerprint the operator compares before approving it on the new side. The
// connection in use stays up until then; the running agent finishes the move
// once it is approved.
//
// What crosses is an address and a name. The address is https only: this
// machine will hand its new key to whatever answers there, and that party
// becomes its management node only when a person approves it.
func init() {
	Register(Primitive{
		Name:        "move_to_plane",
		Class:       ClassOperate,
		Machine:     true,
		Description: "Ask another management node to adopt this machine; the current one stays until that is approved.",
		Params: []ParamSpec{
			{Name: "management_node", Type: ParamString, Required: true, MaxLen: 255, Pattern: moveToPlaneURLPattern},
			// What the new management node's pending list calls this machine,
			// and so the name and slug an approval gives it there: the name it
			// has here, so its backups keep their place.
			{Name: "name", Type: ParamString, Required: true, MaxLen: 100, Pattern: moveToPlaneNamePattern},
		},
		Run: func(ctx context.Context, env *ExecEnv, p Params) (map[string]interface{}, error) {
			if env.MoveToPlane == nil {
				return nil, errors.New("this agent cannot move to another management node")
			}
			return env.MoveToPlane(ctx, p.String("management_node"), p.String("name"))
		},
		Timeout: 1 * time.Minute,
	})
}

// moveToPlaneURLPattern: https, a host name and an optional port, nothing
// after it, the shape of the upgrade_source setting.
var moveToPlaneURLPattern = regexp.MustCompile(`^https://[A-Za-z0-9.\-]+(:[0-9]{1,5})?/?$`)

// moveToPlaneNamePattern: a node name as the plane makes one, letters,
// digits and . _ - only.
var moveToPlaneNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._\-]{0,99}$`)
