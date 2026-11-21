package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
)

// A management node can let a machine go from its own side: its owner stops
// the management of their site there, or an administrator removes the node.
// It forgets the agent's key, and from then on answers every poll with a 401.
// Nothing told the machine, so its Management Node page read "Managed" for
// ever, and its owner could not see why connecting again was not offered.
//
// The agent does not leave on that answer. A management node whose database
// was restored from before the join, or that is broken, gives the same answer
// to machines it should still manage, and an agent that dropped its key then
// would take the whole fleet off it. It records what the management node
// says, and since when, in the connection it reports (agent_join_state), and
// the page shows that with the way out, which is the owner's press.

// The management node's own words for a machine it does not know
// (AgentChannelEndpoint): its node is gone, or the node holds no agent key.
var disownedAnswers = []string{
	"This node has not paired an agent with this plane.",
	"Unknown node.",
}

// planeDisowns returns the management node's words when err is its answer
// that it does not know this machine, else "".
func planeDisowns(err error) string {
	var pe *planeStatusError
	if !errors.As(err, &pe) || pe.Status != http.StatusUnauthorized {
		return ""
	}
	for _, words := range disownedAnswers {
		if strings.Contains(pe.msg, words) {
			return words
		}
	}
	return ""
}

// disowned is what the management node last said of this machine: the time it
// first answered that it does not know it, and its words. Empty while it
// answers as a management node that knows the machine.
var disowned struct {
	sync.Mutex
	since  string
	reason string
}

// disownedNow returns the recorded answer, or two empty strings.
func disownedNow() (since, reason string) {
	disowned.Lock()
	defer disowned.Unlock()
	return disowned.since, disowned.reason
}

// noteDisowned records the management node's latest answer and says whether
// it changed. An empty reason is a poll it answered as usual. earlier is the
// time already on record in the reported state, kept across a restart.
func noteDisowned(reason, earlier string) bool {
	disowned.Lock()
	defer disowned.Unlock()
	if reason == "" {
		changed := disowned.since != ""
		disowned.since, disowned.reason = "", ""
		return changed
	}
	if disowned.since != "" {
		if disowned.reason == reason {
			return false
		}
		disowned.reason = reason
		return true
	}
	disowned.since = earlier
	if disowned.since == "" {
		disowned.since = gmNow()
	}
	disowned.reason = reason
	return true
}

// reportDisowned is the poll's hook (RemoteSource.planeAnswered): it records
// the answer and rewrites the reported connection when it changed.
func reportDisowned(db *DB, identity *NodeIdentity, reason string) {
	earlier := ""
	if reason != "" {
		if since, _ := disownedNow(); since == "" {
			current, _ := readAgentSetting(db, settingJoinState)
			earlier = disownedSinceIn(current, identity)
		}
	}
	if !noteDisowned(reason, earlier) {
		return
	}
	body, err := json.Marshal(connectionState(identity))
	if err != nil {
		return
	}
	_ = writeAgentSetting(db, settingJoinState, string(body))
}

// disownedSinceIn reads the time a reported state of this same connection
// already carries, so a restart does not move it.
func disownedSinceIn(state string, identity *NodeIdentity) string {
	var st map[string]interface{}
	if json.Unmarshal([]byte(state), &st) != nil {
		return ""
	}
	id, _ := st["node_id"].(float64)
	if st["status"] != "connected" || st["url"] != identity.PlaneURL || int64(id) != identity.NodeID {
		return ""
	}
	since, _ := st["disowned_time"].(string)
	return since
}
