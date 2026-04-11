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

var version = "dev"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--version" {
		fmt.Printf("joinery-agent %s\n", version)
		os.Exit(0)
	}

	log.SetFlags(log.Ldate | log.Ltime | log.LUTC)
	log.Printf("starting joinery-agent v%s", version)

	cfg, err := LoadConfig()
	if err != nil {
		log.Fatalf("FATAL: %v", err)
	}

	db, err := NewDB(cfg)
	if err != nil {
		log.Fatalf("FATAL: %v", err)
	}
	defer db.Close()

	log.Printf("connected to PostgreSQL %s/%s", cfg.DBHost, cfg.DBName)

	// Verify the plugin schema exists before doing anything else
	if err := db.ValidateSchema(); err != nil {
		log.Fatalf("FATAL: %v", err)
	}
	log.Printf("schema validated — all required tables present")

	// Recover stale running jobs on startup
	recovered, err := db.RecoverStaleJobs()
	if err != nil {
		log.Printf("WARNING: failed to recover stale jobs: %v", err)
	} else if recovered > 0 {
		log.Printf("recovered %d stale running job(s) — marked as failed", recovered)
	}

	runner := NewRunner(db)

	// Signal handling
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	// Heartbeat goroutine
	go func() {
		for {
			if err := db.UpdateHeartbeat(cfg.AgentName, version); err != nil {
				log.Printf("WARNING: heartbeat update failed: %v", err)
			}
			time.Sleep(cfg.HeartbeatInterval)
		}
	}()

	log.Printf("agent ready — polling every %s", cfg.PollInterval)

	// Main poll loop
	ticker := time.NewTicker(cfg.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case sig := <-sigCh:
			log.Printf("received signal %v — shutting down", sig)
			os.Exit(0)
		case <-ticker.C:
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
