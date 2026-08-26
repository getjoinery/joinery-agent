package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Node-side disconnect (decision A7's symmetry): the machine being managed can
// end the arrangement without the plane's cooperation. The local admin page
// writes the managed setting agent_leave_request; this watcher — running only
// while the agent is connected — honours it: one best-effort signed goodbye so
// the plane forgets this node's key immediately, then the identity is deleted
// and the agent restarts into local-only service. The goodbye failing changes
// nothing: leaving is unilateral, and a plane that missed it simply sees the
// agent go silent until someone disconnects the node there too.

const (
	pathLeave = "/api/v1/agent/leave"

	// settingLeaveRequest is written by the admin page: {"requested_time"}.
	// Any non-empty value is the instruction — there is nothing to negotiate.
	settingLeaveRequest = "agent_leave_request"

	leaveCheckInterval = 5 * time.Second
)

// LeaveWatcher waits for the local admin page to ask for a disconnect.
type LeaveWatcher struct {
	db       *DB
	identity *NodeIdentity
	jobLock  *sync.Mutex
}

// Run loops until a leave request arrives or the context ends.
func (w *LeaveWatcher) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(leaveCheckInterval):
		}

		value, err := readAgentSetting(w.db, settingLeaveRequest)
		if err != nil || strings.TrimSpace(value) == "" {
			continue
		}

		log.Printf("leave: the local admin asked to disconnect from %s", w.identity.PlaneURL)

		// Taken and never released: a job mid-run finishes first, no new one
		// starts, and the next thing this process does after leaving is exit.
		w.jobLock.Lock()

		if err := performLeave(ctx, newPlaneClient(w.identity.TLSInsecure), w.identity); err != nil {
			// The identity is still on disk, so the connection still stands;
			// the request stays recorded and the next tick tries again.
			log.Printf("ERROR: leave: %v", err)
			w.jobLock.Unlock()
			continue
		}

		// The identity is already gone, so a crash between these writes leaves
		// only stale settings — and a disconnected agent clears those on start.
		writeAgentSetting(w.db, settingLeaveRequest, "")
		writeAgentSetting(w.db, settingJoinState, "")

		log.Printf("leave: disconnected — restarting into local-only service")
		os.Exit(0)
	}
}

// performLeave is the disconnect itself: one best-effort signed goodbye, then
// the identity (and any staged keypair) is deleted. Separate from the watcher
// so the boundary is testable without a database. The only failure it can
// return is the one that matters — an identity still on disk, which would mean
// restarting into a connection the admin just ended.
func performLeave(ctx context.Context, client *http.Client, id *NodeIdentity) error {
	body, _ := json.Marshal(map[string]interface{}{"node_id": id.NodeID})
	if _, err := signedPlanePost(ctx, client, id, pathLeave, body); err != nil {
		log.Printf("leave: could not tell %s this node is leaving (leaving anyway — disconnect it on that side too): %v",
			id.PlaneURL, err)
	} else {
		log.Printf("leave: %s was told, and forgets this node's key", id.PlaneURL)
	}

	if err := os.Remove(IdentityPath()); err != nil {
		return err
	}
	discardStagedIdentity()
	return nil
}

// clearStaleLeaveRequest runs when the agent starts DISCONNECTED: a leave
// request that outlived its disconnect (or was written while there was nothing
// to leave) must not ambush the next join.
func clearStaleLeaveRequest(db *DB) {
	value, err := readAgentSetting(db, settingLeaveRequest)
	if err != nil || strings.TrimSpace(value) == "" {
		return
	}
	writeAgentSetting(db, settingLeaveRequest, "")
}
