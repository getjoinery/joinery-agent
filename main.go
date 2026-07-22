package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

var version = "0.3.1"

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

	runner := NewRunner(db)

	// Recover stale running jobs on startup, then replay their teardown
	// steps — those jobs never reached teardown and never will otherwise.
	stale, err := db.RecoverStaleJobs()
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

	log.Printf("agent ready — polling every %s", cfg.PollInterval)

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
			// Self-update check runs between jobs only. A swap exits cleanly;
			// the supervisor (systemd Restart=always, or the cron keepalive)
			// restarts into the new binary.
			if time.Since(lastUpdateCheck) >= updateCheckInterval {
				lastUpdateCheck = time.Now()
				if updater.CheckAndApply() {
					os.Exit(0)
				}
			}

			job, err := db.ClaimNextJob()
			if err != nil {
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
		}
	}
}
