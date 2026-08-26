package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"joinery-agent/primitives"
)

// Version numbering note: agents deployed before the 2026-07 repo reset carry
// the old 1.x line (1.1.0 in the field, no self-updater). The shipped version
// must stay ABOVE 1.1.0 forever - install_agent.sh's downgrade guard sorts
// with sort -V and refuses to replace a "newer" binary, so anything below
// 1.1.0 strands those agents permanently.
var version = "1.4.0"

// How often the idle loop looks at the shipped agent_dist manifest. Update
// checks never run while a job is executing.
const updateCheckInterval = 60 * time.Second

// fatalInit handles a fatal initialisation error. If this binary was just
// self-installed and a backup of the previous one exists, the previous binary
// is restored (and this version marked rejected) so the supervisor restarts
// into a working agent instead of crash-looping on a bad release.
func fatalInit(updater *Updater, err error) {
	log.Printf("FATAL: %v", err)
	if updater != nil {
		updater.RestoreBackupBinary()
	}
	os.Exit(1)
}

// startRemoteSource brings up node posture: poll the joined management node
// for primitive jobs. Returns nil when this agent has no node identity, which
// is the normal state of an agent that has never been connected to one.
//
// Enrollment itself is NOT here: it is the node-initiated join (join.go),
// driven by the local admin page — no env-file credential exists (A6).
//
// Every failure here is a log line and a nil return, never a fatal: an agent
// that cannot reach its management node must keep serving its local job queue.
func startRemoteSource(cfg *Config, db *DB, jobLock *sync.Mutex, agentVersion string) *RemoteSource {
	identity, err := LoadIdentity(IdentityPath())
	if err != nil {
		log.Printf("ERROR: node identity unusable, so this agent takes no remote work: %v", err)
		return nil
	}
	if identity == nil {
		return nil
	}

	policy, err := primitives.LoadPolicy(cfg.PolicyPath)
	if err != nil {
		log.Printf("ERROR: acceptance policy unusable: %v", err)
		return nil
	}

	env := &primitives.ExecEnv{
		SiteRoot: cfg.SiteRoot,
		WebRoot:  cfg.WebRoot,
		DB:       db.SQL(),
		// Phase 1: the release pipeline signs the agent bundle but not a
		// per-file tree manifest, so nothing can be verified and every
		// script-invoking primitive is unavailable rather than unverified.
		Manifest: primitives.UnavailableVerifier{},
	}

	source := NewRemoteSource(identity, policy, env, jobLock)
	go source.Run(context.Background())
	return source
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--version" {
		fmt.Printf("joinery-agent %s\n", version)
		os.Exit(0)
	}

	log.SetFlags(log.Ldate | log.Ltime | log.LUTC)
	log.Printf("starting joinery-agent v%s", version)

	cfg, err := LoadConfig()
	if err != nil {
		fatalInit(NewUpdater(nil, version), err)
	}

	updater := NewUpdater(cfg, version)

	db, err := NewDB(cfg)
	if err != nil {
		fatalInit(updater, err)
	}
	defer db.Close()

	log.Printf("connected to PostgreSQL %s/%s", cfg.DBHost, cfg.DBName)

	// Verify the plugin schema exists before doing anything else
	if err := db.ValidateSchema(); err != nil {
		fatalInit(updater, err)
	}
	log.Printf("schema validated — all required tables present")

	// Fully initialised: a just-installed binary is now proven good.
	updater.ConfirmHealthy()

	runner := NewRunner(db, cfg.SecretBoxKey)

	// One job at a time on this machine. A control plane paired to itself runs
	// both job sources in one process, and neither source's concurrency guard
	// was built expecting the other.
	var jobLock sync.Mutex

	// Node posture. An agent with an identity polls its management node; one
	// without watches for the local admin page to name one (the node-initiated
	// join, Phase 1.5) — either way the local loop below is unchanged.
	if remote := startRemoteSource(cfg, db, &jobLock, version); remote != nil {
		log.Printf("node posture active — remote job source polling %s", remote.identity.PlaneURL)
		leaver := &LeaveWatcher{db: db, identity: remote.identity, jobLock: &jobLock}
		go leaver.Run(context.Background())
	} else {
		clearStaleLeaveRequest(db)
		watcher := &JoinWatcher{cfg: cfg, db: db, jobLock: &jobLock, agentVersion: version}
		go watcher.Run(context.Background())
	}

	// Recover stale running jobs on startup, then replay their teardown
	// steps — those jobs never reached teardown and never will otherwise.
	// Skipped in node-posture-only mode: this agent does not serve the local
	// queue, so the jobs in it belong to an agent that does, and force-failing
	// another agent's running work would be a fine way to break it.
	stale, err := []*Job{}, error(nil)
	if cfg.LocalJobs {
		stale, err = db.RecoverStaleJobs()
	}
	if err != nil {
		log.Printf("WARNING: failed to recover stale jobs: %v", err)
	} else if len(stale) > 0 {
		log.Printf("recovered %d stale running job(s) — marked as failed", len(stale))
		for _, job := range stale {
			log.Printf("replaying teardown for stale job #%d", job.ID)
			runner.ReplayTeardown(job)
		}
	}

	// Signal handling
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	// Heartbeat goroutine
	go func() {
		for {
			bundled, updateState := updater.HeartbeatInfo()
			if err := db.UpdateHeartbeat(cfg.AgentName, version, bundled, updateState); err != nil {
				log.Printf("WARNING: heartbeat update failed: %v", err)
			}
			time.Sleep(cfg.HeartbeatInterval)
		}
	}()

	if cfg.LocalJobs {
		log.Printf("agent ready — polling the local job queue every %s", cfg.PollInterval)
	} else {
		log.Printf("agent ready — node posture only, not serving a local job queue")
	}

	// Main poll loop
	ticker := time.NewTicker(cfg.PollInterval)
	defer ticker.Stop()
	lastUpdateCheck := time.Time{}

	for {
		select {
		case sig := <-sigCh:
			log.Printf("received signal %v — shutting down", sig)
			os.Exit(0)
		case <-ticker.C:
			if !cfg.LocalJobs {
				continue
			}
			// Self-update check runs between jobs only. A swap exits cleanly;
			// the supervisor (systemd Restart=always, or the cron keepalive)
			// restarts into the new binary.
			if time.Since(lastUpdateCheck) >= updateCheckInterval {
				lastUpdateCheck = time.Now()
				if updater.CheckAndApply() {
					os.Exit(0)
				}
			}

			jobLock.Lock()
			job, err := db.ClaimNextJob()
			if err == nil && job == nil {
				jobLock.Unlock()
			}
			if err != nil {
				jobLock.Unlock()
				// Distinguish transient DB errors from permanent ones
				errStr := err.Error()
				if strings.Contains(errStr, "does not exist") {
					log.Printf("ERROR: database schema issue: %v", err)
					log.Printf("  The server_manager plugin tables may not be installed.")
					log.Printf("  Install and activate the plugin from /admin/admin_plugins, then restart the agent.")
				} else {
					log.Printf("ERROR claiming job: %v", err)
				}
				continue
			}
			if job == nil {
				continue
			}

			log.Printf("claimed job #%d (type=%s, node=%d)", job.ID, job.JobType, job.NodeID)
			runner.Execute(job)
			jobLock.Unlock()
		}
	}
}
