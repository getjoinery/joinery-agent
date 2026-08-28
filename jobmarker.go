package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
)

// The agent's promise to the installer that is about to restart it.
//
// THE PROBLEM. Several primitives run platform scripts that reach
// install_agent.sh — apply_update runs the whole upgrade, run_plugin_installers
// runs the installers directly — and install_agent.sh's job is to put a fresh
// agent binary in place and restart the agent onto it. Under SSH that was free:
// the upgrade was a child of sshd and the agent was a bystander. Under this
// transport the agent IS the process running the job, and a restart mid-job
// kills the reporter before it reports. The job stays 'running' until the
// plane's claim budget expires, is requeued, and the node does the work again —
// having already succeeded the first time.
//
// THE SIGNAL. This file writes a marker for exactly as long as a job is
// running. install_agent.sh reads it, defers its swap and its restart, and says
// so in its output. The agent then converges itself a minute later through the
// self-update path built for precisely this: signature checked against the key
// baked into the binary, the previous binary kept as .bak, the swap refused
// mid-job by the same job lock this marker tracks, and a watchdog that rolls
// back a version that never reaches a healthy start.
//
// WHY A FILE AND NOT AN ENVIRONMENT VARIABLE. The signal has to survive
// upgrade.php's shell-outs, and upgrade.php runs the host installers through
// `sudo -n` on any node whose deploy user is not root. sudo strips the
// environment — upgrade.php's own comment at that call site records that it
// already loses PGPASSWORD there, which is the same defect wearing a different
// hat. A file crosses sudo, su and every intermediate shell, and a human
// diagnosing a node can read it.
//
// WHY IT CANNOT WEDGE A NODE. The marker names the pid that wrote it. An agent
// killed mid-job leaves one naming a process that is gone, and the installer
// treats that as stale, removes it, and converges normally. There is no timeout
// to tune and no state that outlives the process it describes.
//
// The path is pinned identically in install_agent.sh, which is the only other
// party that reads it. It is a var rather than a const so the tests can point it
// at a temp directory; nothing at runtime writes to it.
var jobMarkerPath = "/etc/joinery-agent/job-running"

// markJobRunning records that this process is executing a job, and returns the
// function that clears it. Call it while the job lock is held, so the marker's
// lifetime is exactly the window in which a restart would strand work.
//
// A failure to write is logged and otherwise ignored: the consequence is the
// old behaviour — a restart mid-job, a requeue, and a second upgrade — which is
// wasteful rather than harmful. Refusing to run the job over it would turn a
// missing directory into a node that cannot be upgraded at all.
func markJobRunning(jobID int64) func() {
	if err := os.MkdirAll(filepath.Dir(jobMarkerPath), 0o755); err != nil {
		log.Printf("job marker: could not create %s: %v", filepath.Dir(jobMarkerPath), err)
		return func() {}
	}

	// pid first, on its own line: it is the field the installer must read, and
	// putting it first means a truncated or half-written file still answers the
	// only question that gates a restart.
	body := fmt.Sprintf("%d\n%d\n%s\n", os.Getpid(), jobID, time.Now().UTC().Format(time.RFC3339))
	if err := os.WriteFile(jobMarkerPath, []byte(body), 0o644); err != nil {
		log.Printf("job marker: could not write %s: %v — an installer run by this job may restart the agent mid-job", jobMarkerPath, err)
		return func() {}
	}

	return func() {
		if err := os.Remove(jobMarkerPath); err != nil && !os.IsNotExist(err) {
			log.Printf("job marker: could not clear %s: %v", jobMarkerPath, err)
		}
	}
}
