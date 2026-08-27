package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// The run switch, from the agent's side (spec §10.3, O-2 and O-3/O-7).
//
// Whether this machine runs an agent is one setting, agent_enabled. Two things
// follow that this file implements.
//
// First, PROJECTION. The setting lives in the site database, and the things that
// decide whether the agent runs — the cron keepalive, the installer, and the
// agent itself — must keep working when that database does not. So the setting
// is projected one-way into a root-owned marker file: whoever can read the
// database writes the marker, and everyone reads the marker. The installer
// projects at root moments; the agent projects whenever its connection is up,
// which is what makes an off from the admin page take effect in seconds instead
// of waiting for the next container start.
//
// Second, GOING QUIET. An agent that is switched off while paired would simply
// stop answering, and the plane cannot tell a machine that was switched off from
// one that died. So it says so first: a signed going-quiet message, an ack
// required, bounded retry — and then it stops regardless, because the operator
// asked and the plane's availability is not a veto. An undelivered goodbye is
// recorded and replayed on next contact, so the gap gets explained late rather
// than never. This is NOT a leave: the pairing stands and the identity survives.

var errNotAcknowledged = errors.New("the plane did not acknowledge the going-quiet message")

const (
	pathQuiet = "/api/v1/agent/quiet"

	settingAgentEnabled = "agent_enabled"

	// How often the agent re-reads the switch. Matches the join/leave watchers:
	// an admin who turns the agent off should see it stop, not wonder.
	switchCheckInterval = 5 * time.Second

	// How long the goodbye keeps trying before the agent stops anyway.
	quietRetryWindow   = 120 * time.Second
	quietRetryInterval = 10 * time.Second
)

// markerPath is the projected switch: present and truthy means "run".
func markerPath() string { return filepath.Join(agentStateDir(), "enabled") }

// undeliveredQuietPath records a goodbye the plane never acknowledged.
func undeliveredQuietPath() string { return filepath.Join(agentStateDir(), "quiet_undelivered") }

func agentStateDir() string {
	if dir := os.Getenv("AGENT_STATE_DIR"); dir != "" {
		return dir
	}
	return "/etc/joinery-agent"
}

// switchOn reads a stored agent_enabled value the way every other reader does.
// The spellings are shared with install_agent.sh and the admin page, and pinned
// equal by installer_contract_test — one setting read three ways is how a
// machine ends up disagreeing with the page that configured it.
func switchOn(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// projectSwitch writes the marker from a setting value. One-way, always: nothing
// reads the marker back into the setting, so the database stays the operator's
// truth and the file is only ever its shadow.
func projectSwitch(on bool) error {
	if err := os.MkdirAll(agentStateDir(), 0755); err != nil {
		return err
	}
	if on {
		return os.WriteFile(markerPath(), []byte("1\n"), 0644)
	}
	return os.WriteFile(markerPath(), []byte("0\n"), 0644)
}

// markerSaysRun reports the projected switch. A missing marker reads as ON: an
// agent that is running with no marker yet predates the projection, and stopping
// it on that basis would switch off working agents on upgrade.
func markerSaysRun() bool {
	data, err := os.ReadFile(markerPath())
	if err != nil {
		return true
	}
	return switchOn(string(data))
}

// SwitchWatcher keeps the marker in step with the setting and stops the agent
// when the switch goes off.
type SwitchWatcher struct {
	db       *DB
	jobLock  *sync.Mutex
	identity *NodeIdentity // nil when this agent is not paired
}

func (w *SwitchWatcher) Run(ctx context.Context) {
	// A goodbye that never landed is replayed the moment there is someone to
	// tell — before anything else, so a switch-off that follows does not queue
	// behind it.
	w.replayUndeliveredQuiet(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(switchCheckInterval):
		}

		on := w.readSwitch()
		if on {
			continue
		}

		log.Printf("switch: agent_enabled is off — going quiet")

		// Taken and never released: a running job finishes, nothing new starts,
		// and the next thing this process does is exit.
		w.jobLock.Lock()

		if w.identity != nil {
			w.sayGoingQuiet(ctx)
		}

		log.Printf("switch: stopped by the operator's switch")
		os.Exit(0)
	}
}

// readSwitch prefers the database, because that is where an operator changed it,
// and falls back to the marker when the database cannot be read — which is the
// whole reason the marker exists. Projecting on every successful read keeps the
// fallback current for the supervisor, which has no database at all.
func (w *SwitchWatcher) readSwitch() bool {
	value, err := readAgentSetting(w.db, settingAgentEnabled)
	if err != nil {
		return markerSaysRun()
	}

	on := switchOn(value)
	if err := projectSwitch(on); err != nil {
		log.Printf("WARNING: could not project the run switch to %s: %v", markerPath(), err)
	}
	return on
}

// sayGoingQuiet tells the plane this node was switched off, so its dashboard can
// say "switched off" rather than leaving an operator to guess at silence.
//
// It retries within a bounded window and then stops anyway. The operator asked
// for the agent to stop; a plane that cannot be reached does not get a vote, and
// the record left behind is what keeps the fact from being lost.
func (w *SwitchWatcher) sayGoingQuiet(ctx context.Context) {
	quietTime := time.Now().UTC().Format("2006-01-02 15:04:05")
	client := newPlaneClient(w.identity.TLSInsecure)

	deadline := time.Now().Add(quietRetryWindow)
	for attempt := 1; ; attempt++ {
		if err := postGoingQuiet(ctx, client, w.identity, quietTime); err == nil {
			log.Printf("switch: %s acknowledged that this node is switched off", w.identity.PlaneURL)
			os.Remove(undeliveredQuietPath())
			return
		} else {
			log.Printf("switch: could not tell %s this node is going quiet (attempt %d): %v",
				w.identity.PlaneURL, attempt, err)
		}

		if time.Now().After(deadline) {
			break
		}
		select {
		case <-ctx.Done():
			// Shutting down mid-retry. Fall through to the record rather than
			// returning: the whole point of the flag is that a goodbye which
			// could not be delivered is not lost, and a cancelled context is
			// one of the ways it fails to be delivered.
			goto record
		case <-time.After(quietRetryInterval):
		}
	}

record:

	// Never acknowledged. Stop regardless, and leave the fact where the next
	// contact will find it: the plane will show this node as unreachable until
	// then, which is honest — nobody told it otherwise.
	if err := os.MkdirAll(agentStateDir(), 0755); err == nil {
		if err := os.WriteFile(undeliveredQuietPath(), []byte(quietTime+"\n"), 0600); err != nil {
			log.Printf("WARNING: could not record the undelivered goodbye: %v", err)
		}
	}
	log.Printf("switch: stopping without an acknowledgement — the goodbye will be replayed on next contact")
}

// replayUndeliveredQuiet delivers a goodbye that an earlier switch-off could not.
// The recorded time travels with it, so the plane records when the node actually
// went quiet rather than when it got around to saying so.
func (w *SwitchWatcher) replayUndeliveredQuiet(ctx context.Context) {
	if w.identity == nil {
		return
	}
	data, err := os.ReadFile(undeliveredQuietPath())
	if err != nil {
		return
	}
	quietTime := strings.TrimSpace(string(data))
	if quietTime == "" {
		os.Remove(undeliveredQuietPath())
		return
	}

	if err := postGoingQuiet(ctx, newPlaneClient(w.identity.TLSInsecure), w.identity, quietTime); err != nil {
		log.Printf("switch: an earlier going-quiet is still undelivered: %v", err)
		return
	}
	log.Printf("switch: delivered the going-quiet from %s that could not be sent at the time", quietTime)
	os.Remove(undeliveredQuietPath())
}

// postGoingQuiet sends the signed message and requires an acknowledgement. A
// transport success with no acknowledgement is not delivery: it usually means
// something answered that was not the plane.
func postGoingQuiet(ctx context.Context, client *http.Client, id *NodeIdentity, quietTime string) error {
	body, _ := json.Marshal(map[string]interface{}{
		"node_id":    id.NodeID,
		"quiet_time": quietTime,
	})
	raw, err := signedPlanePost(ctx, client, id, pathQuiet, body)
	if err != nil {
		return err
	}

	var ack struct {
		Acknowledged bool `json:"acknowledged"`
	}
	if err := json.Unmarshal(raw, &ack); err != nil || !ack.Acknowledged {
		return errNotAcknowledged
	}
	return nil
}
