package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
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
var version = "1.19.0"

// How often the idle loop looks at the shipped agent_dist manifest. Update
// checks never run while a job is executing.
const updateCheckInterval = 60 * time.Second

// fatalInit stops the process on an error nothing can be done about here.
//
// It deliberately no longer rolls the binary back. Deciding "this release is
// bad" from an init error meant a database outage could condemn a good version
// and refuse it until a newer one shipped; that judgement now belongs to the
// watchdog (Updater.CheckFailedBoot), which asks whether a start ever reached
// health rather than what the error looked like.
//
// Very little should reach this: the database is lazy and the site config is
// retried, so the environment no longer ends the process. A malformed DSN does,
// because every later use of it would fail the same way.
func fatalInit(err error) {
	log.Printf("FATAL: %v", err)
	os.Exit(1)
}

// How long to wait between attempts to read the site config, and how often to
// say so. An agent that cannot read its config cannot do anything useful, but
// exiting is worse than waiting: on a machine mid-upgrade or mid-restore the
// file is briefly absent, and a supervisor restarting into that races the very
// repair it is interrupting.
const configRetryInterval = 15 * time.Second

// loadConfigWaiting blocks until the site config can be read. It never gives up
// and it never exits — the caller has nothing better to do without a config, and
// a process that is present and complaining is easier to diagnose than one that
// keeps vanishing.
func loadConfigWaiting() *Config {
	warned := false
	for {
		cfg, err := LoadConfig()
		if err == nil {
			if warned {
				log.Printf("site config readable again — continuing startup")
			}
			return cfg
		}
		if !warned {
			log.Printf("WARNING: cannot read the site config (%v)", err)
			log.Printf("  Waiting for it; retrying every %s. Nothing else runs until it is readable.", configRetryInterval)
			warned = true
		}
		time.Sleep(configRetryInterval)
	}
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
	remoteStart.mu.Lock()
	defer remoteStart.mu.Unlock()
	if remoteStart.source != nil {
		return remoteStart.source
	}

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

	// Nil on a machine with no site, and that nil is load-bearing. ExecEnv.DB
	// is the collectors' test for "is there a database to ask about" —
	// check_status skips its database section when it is nil, and REPORTS A
	// FAULT when it is set and unreachable. A siteless machine handed a live
	// provider over an empty DSN would therefore report a database problem on
	// every status check, on a machine that has no database to have a problem
	// with. Absent and broken are different answers and must not be conflated.
	var dbForPrimitives primitives.DBProvider
	if !cfg.Siteless {
		dbForPrimitives = db.Provider()
	}

	env := &primitives.ExecEnv{
		SiteRoot: cfg.SiteRoot,
		WebRoot:  cfg.WebRoot,
		DB:       dbForPrimitives,
		// Which database is this machine's own, from this machine's own config.
		// The plane stores no column for it and so can only guess; see
		// ExecEnv.DBName.
		DBName: cfg.DBName,
		// Component G: a script is verified against the signed manifest of the
		// artifact that ships it, using the release key compiled into this
		// binary. No network call is involved — forging this means forging
		// Ed25519, not spoofing a host.
		//
		// The boundary stays CLOSED where there is nothing to verify against: a
		// node whose installed release predates the manifests, or an artifact
		// that ships none, refuses its scripts rather than running them
		// unverified. That is the same posture as before, now with a refusal
		// that names which artifact could not be checked.
		Manifest: releaseVerifier(cfg.SiteRoot),

		// The support bundle, for a machine with no site tree to verify
		// against. Set unconditionally on a siteless machine, before any bundle
		// has arrived: the verifier reads the manifest at the moment of use and
		// does not cache its absence, so a machine that is handed a bundle ten
		// minutes from now starts running script primitives then, without a
		// restart. Empty where there is a site — SiteRoot wins there, and a
		// second script root would be a second answer.
		ToolRoot:     toolRoot(cfg),
		ToolManifest: bundleVerifier(cfg),

		// How this machine asks its OWN operator to authorize a destructive
		// job. Set from the same database handle the collectors use, and set
		// unconditionally: a machine with no database is a machine that cannot
		// ask, and SettingsApproval refuses in that case rather than the caller
		// having to remember to. Never nil, so "the gate was not wired" can
		// never quietly mean "there was no gate" — Execute refuses a
		// destructive job without one, but a nil here would be a deployment
		// mistake presenting as a policy.
		Approval: NewSettingsApproval(db),

		// How a HOST asks the site it would destroy for that site's own
		// consent (decommission_site). Only a machine in host posture — no
		// site of its own — gets one; everywhere else the field is nil and
		// the primitive refuses. See victim.go.
		VictimCeremony: victimCeremonyFor(cfg),
	}

	source := NewRemoteSource(identity, policy, env, jobLock, agentVersion)
	go source.Run(context.Background())
	remoteStart.source = source
	return source
}

// remoteStart is the one remote source this process runs. Two watchers can
// each finish a join — the settings-driven JoinWatcher and the CLI-driven
// StagedJoinWatcher both run on a site machine — and whichever gets there
// second must find the source already polling, not start a second one that
// claims jobs alongside the first. The lock is held across the whole start so
// two approvals landing in the same second cannot both pass the nil check.
var remoteStart struct {
	mu     sync.Mutex
	source *RemoteSource
}

// recoverStaleJobs force-fails jobs a previous process left running and replays
// their teardown steps — they never reached teardown and never will otherwise.
//
// Runs when the local queue becomes servable, not at startup: those are the same
// moment on a healthy control plane and are not the same moment on one whose
// database was down when it started. Never runs without a local queue, where the
// jobs in that table belong to an agent that does serve it — force-failing
// another agent's running work would be a fine way to break it.
func recoverStaleJobs(db *DB, runner *Runner) {
	stale, err := db.RecoverStaleJobs()
	if err != nil {
		log.Printf("WARNING: failed to recover stale jobs: %v", err)
		return
	}
	if len(stale) == 0 {
		return
	}
	log.Printf("recovered %d stale running job(s) — marked as failed", len(stale))
	for _, job := range stale {
		log.Printf("replaying teardown for stale job #%d", job.ID)
		runner.ReplayTeardown(job)
	}
}

// attemptUpdate runs one self-update check unless a job is running, and reports
// whether a new binary went in (in which case the caller exits so the
// supervisor restarts into it).
//
// The lock is the whole point. A binary must never be swapped out from under a
// running job, and sharing the one job lock is what extends that promise to
// remote work — the local poll loop used to get it for free by checking in the
// same goroutine that ran the job, which never covered jobs the remote source
// was running in its own.
func attemptUpdate(jobLock *sync.Mutex, check func() bool) bool {
	if !jobLock.TryLock() {
		return false
	}
	defer jobLock.Unlock()
	return check()
}

// releaseVerifier builds the manifest verifier for this node's site tree.
//
// A build with no release key baked in cannot verify anything, and must not
// pretend otherwise: it refuses every script, exactly as a missing manifest
// does. A hand-built agent is a legitimate thing to have and an illegitimate
// thing to trust with root-exec of files it cannot check.
// toolRoot is the support bundle's tree on a machine that has no site, and
// empty everywhere else.
func toolRoot(cfg *Config) string {
	if cfg == nil || !cfg.Siteless {
		return ""
	}
	return BundleRoot()
}

// bundleVerifier verifies files under the support bundle against the manifest
// the bundle itself carries.
//
// It is the SAME verifier a site tree uses, pointed at a different root, and
// that is deliberate: the bundle is a signed tree with a RELEASE_MANIFEST and a
// .sig exactly as a release is, so there is one manifest format in this system
// and one piece of code that decides whether a file may be executed as root.
func bundleVerifier(cfg *Config) primitives.ManifestVerifier {
	root := toolRoot(cfg)
	if root == "" {
		return nil
	}
	if updatePubKeyB64 == "" {
		return primitives.UnavailableVerifier{}
	}
	key, err := base64.StdEncoding.DecodeString(updatePubKeyB64)
	if err != nil || len(key) != ed25519.PublicKeySize {
		log.Printf("script primitives unavailable: this build's release key is malformed")
		return primitives.UnavailableVerifier{}
	}
	return primitives.NewArtifactManifests(root, ed25519.PublicKey(key))
}

func releaseVerifier(siteRoot string) primitives.ManifestVerifier {
	if updatePubKeyB64 == "" || siteRoot == "" {
		return primitives.UnavailableVerifier{}
	}
	key, err := base64.StdEncoding.DecodeString(updatePubKeyB64)
	if err != nil || len(key) != ed25519.PublicKeySize {
		log.Printf("script primitives unavailable: this build's release key is malformed")
		return primitives.UnavailableVerifier{}
	}
	return primitives.NewArtifactManifests(siteRoot, ed25519.PublicKey(key))
}

func main() {
	// Subcommands first: they are one-shot operator commands and must not fall
	// through into starting a service. A machine with no site enrolls here
	// rather than through an admin page it does not have (cli.go).
	if handled, exit := runCLI(os.Args); handled {
		os.Exit(exit)
	}

	log.SetFlags(log.Ldate | log.Ltime | log.LUTC)
	log.Printf("starting joinery-agent v%s", version)

	// The watchdog first, before anything else can fail: if the previous start of
	// this binary never proved healthy, put the old one back and let the
	// supervisor restart into it.
	if NewUpdater(nil, version).CheckFailedBoot() {
		os.Exit(1)
	}

	cfg := loadConfigWaiting()
	updater := NewUpdater(cfg, version)

	// Not connecting — preparing a pool. A malformed DSN is a config fault worth
	// stopping for; PostgreSQL being down is not, and no longer reaches here.
	db, err := NewDB(cfg)
	if err != nil {
		fatalInit(err)
	}
	defer db.Close()

	switch {
	case cfg.Siteless:
		// Not an outage and not worth a warning every start. There is no
		// database here because there is no site here.
		log.Printf("machine posture — no local site or database; serving only what this machine can answer for itself")
	default:
		if err := db.Available(); err != nil {
			log.Printf("NOTE: database not reachable yet (%v)", err)
			log.Printf("  Continuing: node work does not need it, and the pool reconnects on its own.")
		} else {
			log.Printf("connected to PostgreSQL %s/%s", cfg.DBHost, cfg.DBName)
		}
	}

	// Fully initialised. Everything past this point degrades rather than exits,
	// so a binary that got here is a binary that runs — which is exactly what
	// the update watchdog needs to be told.
	updater.ConfirmHealthy()

	runner := NewRunner(db, cfg.SecretBoxKey)

	// One job at a time on this machine. A control plane paired to itself runs
	// both job sources in one process, and neither source's concurrency guard
	// was built expecting the other.
	var jobLock sync.Mutex

	// Plane-local work, asked as a live question rather than settled at startup.
	// Stale-job recovery hangs off the transition, not off this line, because a
	// queue that appears ten minutes late still has jobs a dead process left
	// running in it.
	localQueue := NewLocalQueue(cfg.LocalJobs, db.MissingLocalJobTables, func() {
		recoverStaleJobs(db, runner)
	})
	go localQueue.Run(context.Background())

	// Node posture. An agent with an identity polls its management node; one
	// without watches for the local admin page to name one (the node-initiated
	// join, Phase 1.5) — either way the local loop below is unchanged.
	var pairedIdentity *NodeIdentity
	if remote := startRemoteSource(cfg, db, &jobLock, version); remote != nil {
		log.Printf("node posture active — remote job source polling %s", remote.identity.PlaneURL)
		pairedIdentity = remote.identity
		// Both watchers below are settings-table readers, and a siteless
		// machine has no settings table. Its equivalents are the CLI:
		// `joinery-agent join` and `joinery-agent leave` act directly instead
		// of leaving a request for a watcher to notice. Running them anyway
		// would be a query that fails every few seconds for the life of the
		// process, which is how a machine ends up with a log nobody reads.
		if !cfg.Siteless {
			leaver := &LeaveWatcher{db: db, identity: remote.identity, jobLock: &jobLock}
			go leaver.Run(context.Background())
		}
	} else {
		if !cfg.Siteless {
			clearStaleLeaveRequest(db)
			watcher := &JoinWatcher{cfg: cfg, db: db, jobLock: &jobLock, agentVersion: version}
			go watcher.Run(context.Background())
		} else {
			log.Printf("machine posture — not enrolled; run `joinery-agent join --management-node=URL` to ask a management node to adopt this machine")
		}
		// The CLI lodges the ask; this finishes it. An approval can be hours
		// away, and a machine we created has nobody at its terminal. On a site
		// machine too: `joinery-agent join` is how a management node pairs to
		// itself, and the operator who ran it at the terminal is not going to
		// restart the agent afterwards to make the credential count. This
		// watcher reads one file and asks the plane; it never touches the
		// settings table, so it is the same cost on both postures.
		stagedWatcher := &StagedJoinWatcher{cfg: cfg, db: db, jobLock: &jobLock, agentVersion: version}
		go stagedWatcher.Run(context.Background())
	}

	// The run switch. Projects the setting into the marker the supervisor reads,
	// and stops this process when an operator turns the agent off — saying so to
	// the management node first, when there is one to tell.
	switcher := &SwitchWatcher{db: db, jobLock: &jobLock, identity: pairedIdentity}
	go switcher.Run(context.Background())

	// Signal handling
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	// Heartbeat goroutine. Plane-local, like the queue it reports alongside: the
	// row lands in server_manager's table for its dashboard. A node-posture agent
	// has no such table, and its management node learns liveness from the polling
	// itself, so there is nothing here for it to write.
	//
	// The goroutine always runs and asks per tick, rather than being started or
	// not at boot — the queue can arrive later, and a heartbeat that never came
	// back after an outage would read on the dashboard as an agent that died.
	go func() {
		for {
			if localQueue.Available() {
				bundled, updateState := updater.HeartbeatInfo()
				if err := db.UpdateHeartbeat(cfg.AgentName, version, bundled, updateState); err != nil {
					log.Printf("WARNING: heartbeat update failed: %v", err)
				}
			}
			time.Sleep(cfg.HeartbeatInterval)
		}
	}()

	// Self-update and the support bundle, on one clock and under one lock.
	//
	// They share both because they are the same hazard seen twice: swapping the
	// binary under a running job, and swapping the scripts that job is running.
	// The bundle is checked FIRST and does not exit — a machine that has just
	// been given its scripts should be able to use them without waiting for a
	// restart it has no other reason to make.
	bundle := NewBundleSync(cfg)
	go func() {
		ticker := time.NewTicker(updateCheckInterval)
		defer ticker.Stop()
		for range ticker.C {
			attemptUpdate(&jobLock, bundle.CheckAndApply)
			if attemptUpdate(&jobLock, updater.CheckAndApply) {
				os.Exit(0)
			}
		}
	}()

	// Manifest recovery, on its own slower clock and under the same job lock.
	//
	// Separate from the two above because it is not the same hazard: those
	// replace things a running job might be using, while this replaces a
	// manifest that — by the time it runs at all — is refusing every job there
	// is. It still takes the lock, because writing the file a running job is
	// verifying against is precisely the race the lock exists for.
	//
	// nil on a machine with nothing to heal: no site tree, or no release key.
	if healer := newManifestHealer(cfg, releaseVerifier(cfg.SiteRoot)); healer != nil {
		go func() {
			// Once at startup: an agent that has just been restarted onto a
			// wedged node should not wait out the first interval before trying.
			attemptUpdate(&jobLock, healer.CheckAndHeal)
			ticker := time.NewTicker(healCheckInterval)
			defer ticker.Stop()
			for range ticker.C {
				attemptUpdate(&jobLock, healer.CheckAndHeal)
			}
		}()
	}

	switch {
	case localQueue.Available():
		log.Printf("agent ready — polling the local job queue every %s", cfg.PollInterval)
	case !cfg.LocalJobs:
		// Latched off, so the recheck below never runs and saying it would is
		// simply untrue. A machine with no site has no local queue to wait for,
		// and an operator reading this log should not be left watching for a
		// state change that cannot arrive.
		log.Printf("agent ready — machine posture; no local job queue on this machine")
	default:
		log.Printf("agent ready — node posture only for now, rechecking for local work every %s",
			localQueueRecheckInterval)
	}

	// Main poll loop
	ticker := time.NewTicker(cfg.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case sig := <-sigCh:
			log.Printf("received signal %v — shutting down", sig)
			os.Exit(0)
		case <-ticker.C:
			if !localQueue.Available() {
				continue
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
