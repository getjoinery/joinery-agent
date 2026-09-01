package main

import (
	"context"
	"log"
	"os"
	"sync"
	"time"
)

// stagedPollInterval is how often a machine with a staged keypair asks the
// plane whether its join has been decided. An approval can be hours away, and
// join_status is an unauthenticated endpoint, so this is deliberately slower
// than the sited watcher's poll.
const stagedPollInterval = 30 * time.Second

// StagedJoinWatcher finishes a join on a machine that has no settings table.
//
// A sited node's JoinWatcher reads the admin page's request from stg_settings
// and completes the join itself. A siteless machine asks through the CLI
// instead — and the CLI cannot sit at a terminal for an approval that may be
// hours away, nor should an operator have to come back to one. So the running
// agent watches the staged keypair the CLI left behind and completes the join
// the moment the plane approves it, starting the remote source in this
// process without a restart. It also notices a credential the CLI finished on
// its own (an operator who did wait), for the same reason: a join that is
// approved must become a working channel without anyone touching the box.
//
// Nothing here is a second ask. A staged keypair is one request; it is
// re-sent only when the plane says it has expired, and a rejection discards
// it — the same node-side rules the sited watcher follows.
type StagedJoinWatcher struct {
	cfg          *Config
	db           *DB
	jobLock      *sync.Mutex
	agentVersion string

	// interval overrides stagedPollInterval (tests); zero means the default.
	interval time.Duration
	// start overrides how the remote source is started once the credential
	// exists (tests); nil means startRemoteSource.
	start func()
}

// Run loops until a credential exists and the remote source has been started,
// or the context ends.
func (w *StagedJoinWatcher) Run(ctx context.Context) {
	interval := w.interval
	if interval <= 0 {
		interval = stagedPollInterval
	}
	start := w.start
	if start == nil {
		start = func() { startRemoteSource(w.cfg, w.db, w.jobLock, w.agentVersion) }
	}
	caller := &JoinWatcher{cfg: w.cfg, agentVersion: w.agentVersion}
	lastWarning := ""

	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}

		// The CLI may have completed the join on its own. Then the credential
		// is on disk and the source must start now, not at the next restart.
		if identity, err := LoadIdentity(IdentityPath()); err == nil && identity != nil {
			log.Printf("join: a credential for %s is in place; starting the remote source", identity.PlaneURL)
			start()
			return
		}

		staged := loadStagedIdentity()
		if staged == nil {
			continue
		}
		name := staged.ClaimedName
		if name == "" {
			name, _ = os.Hostname()
		}

		status, err := caller.callJoin(ctx, staged.PlaneURL, staged, name, false)
		if err != nil {
			// Transient, most likely: the plane is restarting, or the network
			// blinked. Say so once per distinct reason, not once per poll.
			if err.Error() != lastWarning {
				log.Printf("join: %v (will keep checking)", err)
				lastWarning = err.Error()
			}
			continue
		}
		lastWarning = ""

		switch status.Status {
		case "approved":
			if status.NodeID <= 0 {
				log.Printf("join: %s approved without naming a node; ask its administrator to retry the approval", staged.PlaneURL)
				continue
			}
			identity, err := identityFromApproval(staged.PlaneURL, staged, status, w.cfg.PlaneTLSInsecure)
			if err != nil {
				log.Printf("join: the staged keypair is unusable and has been discarded; run join again: %v", err)
				discardStagedIdentity()
				continue
			}
			if err := identity.Save(IdentityPath()); err != nil {
				log.Printf("join: approved, but the identity could not be stored at %s: %v", IdentityPath(), err)
				continue
			}
			discardStagedIdentity()
			log.Printf("join: approved — this is node #%d (%s) of %s; credential stored at %s",
				status.NodeID, status.NodeSlug, staged.PlaneURL, IdentityPath())
			start()
			return
		case "rejected":
			// The key was declined; it is never presented again.
			log.Printf("join: %s rejected this machine's request; the staged key has been discarded", staged.PlaneURL)
			discardStagedIdentity()
		case "expired", "unknown":
			// The plane no longer holds the ask (its hour passed, or it was
			// rebuilt). Ask again with the SAME key: the fingerprint the
			// human compares does not change, so an approval that comes
			// later still lands on this machine.
			if _, err := caller.callJoin(ctx, staged.PlaneURL, staged, name, true); err != nil {
				log.Printf("join: could not renew the request with %s: %v", staged.PlaneURL, err)
			} else {
				log.Printf("join: renewed the request with %s (the fingerprint is unchanged)", staged.PlaneURL)
			}
		}
	}
}
