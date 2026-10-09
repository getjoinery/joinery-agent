package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

// Moving a connected machine to another management node (move_to_plane).
//
// A machine with a site moves from its own admin page: Disconnect there, then
// Connect to the new address. A machine with no site has no page, so until
// this it moved only from a shell (`joinery-agent leave`, then `join`). Now
// the management node that manages it asks instead. The word stages a fresh
// keypair for the new management node and files the join there, the ask
// `joinery-agent join --no-wait` makes, and answers the fingerprint the
// operator compares on the new side.
//
// The current connection stays up while the new one is decided, so an ask
// that is rejected or never answered loses nothing. MoveWatcher finishes an
// approved one: the new credential replaces the old, the old management node
// is told goodbye (it forgets this machine's key), and the agent restarts onto
// the new one. `joinery-agent leave` cancels a move in flight, since it
// discards the staged keypair.

// moveToPlaneFor is the MoveToPlane hook on the ExecEnv.
func moveToPlaneFor(cfg *Config) func(ctx context.Context, planeURL, claimedName string) (map[string]interface{}, error) {
	return func(ctx context.Context, planeURL, claimedName string) (map[string]interface{}, error) {
		planeURL = strings.TrimSuffix(strings.TrimSpace(planeURL), "/")
		claimedName = strings.TrimSpace(claimedName)
		if !strings.HasPrefix(planeURL, "https://") {
			return nil, fmt.Errorf("the management node to move to must be an https address, not %q", planeURL)
		}

		current, err := LoadIdentity(IdentityPath())
		if err != nil || current == nil {
			return nil, fmt.Errorf("this machine is not connected to a management node, so there is nothing to move")
		}
		if strings.EqualFold(strings.TrimSuffix(current.PlaneURL, "/"), planeURL) {
			return nil, fmt.Errorf("this machine is already managed by %s", planeURL)
		}

		// One ask at a time. A staged keypair for anything else (another
		// move, or a CLI join to some other plane) is discarded rather than
		// presenting the same key to two planes; the same move asked again
		// keeps its key, so the fingerprint the operator compares holds.
		staged := loadStagedIdentity()
		if staged != nil && (!staged.Moving || staged.PlaneURL != planeURL) {
			discardStagedIdentity()
			staged = nil
		}
		if staged == nil {
			pub, priv, err := GenerateIdentityKeys()
			if err != nil {
				return nil, fmt.Errorf("could not generate a keypair: %v", err)
			}
			staged = &stagedIdentity{
				PlaneURL:      planeURL,
				PublicKey:     pub,
				PrivateKey:    priv,
				RequestedTime: time.Now().UTC().Format(time.RFC3339),
				ClaimedName:   claimedName,
				Moving:        true,
			}
			if err := staged.save(); err != nil {
				return nil, fmt.Errorf("could not store the staged keypair at %s: %v", stagedIdentityPath(), err)
			}
		} else if claimedName != "" && claimedName != staged.ClaimedName {
			staged.ClaimedName = claimedName
			if err := staged.save(); err != nil {
				return nil, fmt.Errorf("could not update the staged keypair at %s: %v", stagedIdentityPath(), err)
			}
		}

		fingerprint, err := stagedFingerprint(staged)
		if err != nil {
			discardStagedIdentity()
			return nil, fmt.Errorf("the staged keypair was unusable and has been discarded; ask again: %v", err)
		}
		name := staged.ClaimedName
		if name == "" {
			name, _ = os.Hostname()
		}

		caller := &JoinWatcher{cfg: cfg, agentVersion: version}
		status, err := caller.callJoin(ctx, planeURL, staged, name, true)
		if err != nil {
			// The key stays staged, and MoveWatcher renews an ask the new plane
			// does not hold, so a plane that was briefly down still gets it.
			return nil, err
		}
		log.Printf("move: asked %s to adopt this machine as %q (fingerprint %s); still managed by %s until it is approved",
			planeURL, name, fingerprint, current.PlaneURL)
		return map[string]interface{}{
			"management_node": planeURL,
			"claimed_name":    name,
			"fingerprint":     fingerprint,
			"status":          status.Status,
			"managed_by":      current.PlaneURL,
		}, nil
	}
}

// moveCheckInterval is how often a connected machine with a staged move asks
// the new management node whether it has been approved.
const moveCheckInterval = 30 * time.Second

// moveWatcherInterval and moveWatcherExit are what a MoveWatcher uses when its
// own fields are unset: the poll interval, and how the process ends after a
// finished move (the supervisor starts it again on the new credential).
// Package variables so a test can drive the watcher startConnectedWatchers
// starts.
var (
	moveWatcherInterval = moveCheckInterval
	moveWatcherExit     = func() { os.Exit(0) }
)

// MoveWatcher finishes a move_to_plane once the new management node approves
// it. It runs while this machine is connected, on both postures, and does
// nothing until a staged move exists.
type MoveWatcher struct {
	cfg          *Config
	jobLock      *sync.Mutex
	agentVersion string
	// identity is the connection in use now: the one told goodbye.
	identity *NodeIdentity
	// interval overrides moveCheckInterval (tests); zero means the default.
	interval time.Duration
	// exit overrides how the process ends after a finished move (tests); nil
	// means os.Exit(0), and the supervisor starts it again on the new credential.
	exit func()
}

// Run loops until a move is finished or the context ends.
func (w *MoveWatcher) Run(ctx context.Context) {
	interval := w.interval
	if interval <= 0 {
		interval = moveWatcherInterval
	}
	caller := &JoinWatcher{cfg: w.cfg, agentVersion: w.agentVersion}
	lastWarning := ""
	rejectedSaid := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
		staged := loadStagedIdentity()
		if staged == nil || !staged.Moving {
			continue
		}
		name := staged.ClaimedName
		if name == "" {
			name, _ = os.Hostname()
		}
		status, err := caller.callJoin(ctx, staged.PlaneURL, staged, name, false)
		if err != nil {
			if err.Error() != lastWarning {
				log.Printf("move: %v (will keep checking)", err)
				lastWarning = err.Error()
			}
			continue
		}
		lastWarning = ""
		switch status.Status {
		case "approved":
			if w.finish(ctx, staged, status) {
				return
			}
		case "rejected":
			if !rejectedSaid {
				log.Printf("move: %s rejected this machine's request; staying with %s and checking in case it is reopened",
					staged.PlaneURL, w.identity.PlaneURL)
				rejectedSaid = true
			}
		case "expired", "unknown":
			rejectedSaid = false
			if _, err := caller.callJoin(ctx, staged.PlaneURL, staged, name, true); err != nil {
				log.Printf("move: could not renew the request with %s: %v", staged.PlaneURL, err)
			} else {
				log.Printf("move: renewed the request with %s (the fingerprint is unchanged)", staged.PlaneURL)
			}
		default:
			rejectedSaid = false
		}
	}
}

// finish swaps the credential for the approved one, tells the old management
// node goodbye, and ends the process. False when the swap could not be made;
// the old connection then stands and the next tick tries again.
func (w *MoveWatcher) finish(ctx context.Context, staged *stagedIdentity, status *joinStatusResponse) bool {
	if status.NodeID <= 0 {
		log.Printf("move: %s approved without naming a node; ask its administrator to retry the approval", staged.PlaneURL)
		return false
	}
	// Taken and never released: a job mid-run finishes first, no new one
	// starts, and the next thing this process does is exit.
	w.jobLock.Lock()

	identity, err := identityFromApproval(staged.PlaneURL, staged, status, w.cfg.PlaneTLSInsecure)
	if err != nil {
		log.Printf("move: the staged keypair is unusable and has been discarded; ask again: %v", err)
		discardStagedIdentity()
		w.jobLock.Unlock()
		return false
	}
	// The new credential is stored before the old management node is told,
	// so a failure in between leaves a machine that restarts onto the new
	// one, never a machine with no credential at all.
	if err := identity.Save(IdentityPath()); err != nil {
		log.Printf("move: approved by %s, but the credential could not be stored at %s: %v", staged.PlaneURL, IdentityPath(), err)
		w.jobLock.Unlock()
		return false
	}
	discardStagedIdentity()

	body, _ := json.Marshal(map[string]interface{}{"node_id": w.identity.NodeID})
	if _, err := signedPlanePost(ctx, newPlaneClient(w.identity.TLSInsecure), w.identity, pathLeave, body); err != nil {
		log.Printf("move: could not tell %s this machine has moved (moved anyway; remove it on that side): %v", w.identity.PlaneURL, err)
	} else {
		log.Printf("move: %s was told, and forgets this machine's key", w.identity.PlaneURL)
	}
	log.Printf("move: this is now node #%d (%s) of %s; restarting onto it", status.NodeID, status.NodeSlug, staged.PlaneURL)
	if w.exit != nil {
		w.exit()
	} else {
		moveWatcherExit()
	}
	return true
}
