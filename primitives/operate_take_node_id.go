package primitives

// take_node_id {node_id, node_slug}: a dormant copy takes over the node id of
// the site it is a copy of, keeping its own key (specs/site_copy.md D4,
// step 10). The management node swaps the two node rows when it records this
// word's result: the node keeps its id, slug and history and takes this
// machine's key and host; the copy's row takes the source's key and becomes the
// retired source. This machine then answers as the node.
//
// TWO HALVES, AND THE ORDER IS THE DESIGN. The word only STAGES the new
// identity: the same key under the new id, written beside the live identity.
// The live identity changes after the result is posted, and only when the
// management node's answer to that post confirms it swapped the rows
// (remote.go). Changing it any earlier strands the machine either way:
//
//   - before the post, the result is signed as the source's node and checked
//     against the source's row, which still holds the source's key: refused,
//     and the rows are never swapped;
//   - after a post the management node did not act on, this machine signs as
//     the source with a key the source's row does not hold: every poll refused.
//
// Without the confirmation the staged file is deleted and nothing changed.
//
// HOSTILE-CALLER REVIEW (rule 5).
//
// What is the worst a compromised management node can do with this word? Make
// a dormant copy answer as the node it is a copy of, which it would need anyway
// to finish a switch-over. The copy stays quiet: the word clears nothing, and
// site_quiet off is a separate word.
//
// What it cannot do:
//
//   - Make a machine take any other node's id. The only id accepted is the one
//     the dormant install recorded (copy_of), so a copy can become its own
//     source and nothing else, and a live site has no record to match.
//   - Take a key. The staged identity keeps this machine's key; there is no
//     parameter that carries one.
//   - Take the machine off the channel. It refuses unless something is proven
//     to start the agent again (restart_agent's rule), because the new identity
//     takes effect at a restart.

import (
	"context"
	"regexp"
	"sync"
	"time"
)

func init() {
	Register(Primitive{
		Name:        "take_node_id",
		Class:       ClassOperate,
		Description: "Take over the node id of the site this dormant copy is a copy of, keeping this machine's own key. It takes effect once the management node confirms it has swapped the two node records.",
		Params: []ParamSpec{
			{Name: "node_id", Type: ParamInt, Required: true, Min: 1, Max: 1<<62 - 1},
			{Name: "node_slug", Type: ParamString, Required: true, MaxLen: 50,
				Pattern: regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)},
		},
		Run:     takeNodeIDRun,
		Timeout: 1 * time.Minute,
		Quiet:   QuietCopy,
	})
}

func takeNodeIDRun(_ context.Context, env *ExecEnv, params Params) (map[string]interface{}, error) {
	return takeNodeIDUnder(env, params, liveSupervision())
}

// takeNodeIDUnder is the body, with the supervision facts as an argument so
// the refusals can be exercised; the registered primitive passes the live one.
func takeNodeIDUnder(env *ExecEnv, params Params, s supervision) (map[string]interface{}, error) {
	if env == nil || env.SiteRoot == "" {
		return nil, refusedf("take_node_id: this machine has no site, so it is nobody's copy")
	}
	st, err := ReadSiteState(env)
	if err != nil {
		return nil, refusedf("take_node_id: %v", err)
	}
	if st.Reason != "copy" {
		return nil, refusedf("take_node_id runs only on a dormant copy (quiet copy), and this site is not one")
	}
	want := params.Int("node_id")
	if st.CopyOf <= 0 {
		return nil, refusedf("take_node_id: this copy does not record which node it is a copy of, so it can take no id")
	}
	if want != st.CopyOf {
		return nil, refusedf("take_node_id: this machine is a copy of node %d, not node %d; a copy takes only its own source's id",
			st.CopyOf, want)
	}
	if env.NodeID == nil || env.StageNodeID == nil {
		return nil, refusedf("take_node_id: this agent cannot read or stage its identity here")
	}
	current, err := env.NodeID()
	if err != nil {
		return nil, refusedf("take_node_id: cannot read this machine's node id: %v", err)
	}
	if current <= 0 {
		return nil, refusedf("take_node_id: this machine has not joined a management node")
	}
	if current == want {
		return nil, refusedf("take_node_id: this machine is already node %d", want)
	}
	found := s.restarters()
	if len(found) == 0 {
		return nil, refusedf("take_node_id: the new id takes effect when the agent starts again, and nothing on " +
			"this machine is proven to start it (see restart_agent); the copy keeps its own id")
	}
	slug := params.String("node_slug")
	if err := env.StageNodeID(want, slug); err != nil {
		return nil, err
	}
	requestIdentityTake(want)
	return map[string]interface{}{
		"staged":       true,
		"from_node_id": current,
		"node_id":      want,
		"node_slug":    slug,
		"restarted_by": found,
	}, nil
}

// The take request, a package variable for the reason the restart request is
// one (operate_restart_agent.go): the identity belongs to the job loop, which
// acts on the request after the result is posted and the management node has
// answered.
var (
	identityTakeMu sync.Mutex
	identityTakeID int64
)

func requestIdentityTake(id int64) {
	identityTakeMu.Lock()
	defer identityTakeMu.Unlock()
	identityTakeID = id
}

// ConsumeIdentityTake reports the node id a job staged, or 0, clearing the
// request as it does. Called by the job loop once the result is posted.
func ConsumeIdentityTake() int64 {
	identityTakeMu.Lock()
	defer identityTakeMu.Unlock()
	id := identityTakeID
	identityTakeID = 0
	return id
}
