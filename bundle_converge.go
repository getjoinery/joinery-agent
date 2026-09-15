package main

// The machine converge that follows a bundle install (specs/agent_tier1_recipes.md
// item 6b).
//
// A site node has a path trigger: the moment a root request lands, the host
// timer's unit runs. A machine with no site has no web user to queue one and,
// before its first converge, no timer at all — the timer is one of the two
// host installers the converge runs. So the one event a siteless machine can
// act on is the arrival of a new signed tree: the support bundle the agent
// just verified and unpacked. Converging to it then is the same act the site's
// trigger performs, on the same signed bytes, under the same job lock and job
// marker a plane job or a recipe attempt would hold.
//
// This is the agent doing root work on its own initiative. The bounds: only
// on a siteless machine; only when a bundle was just installed (not on every
// tick); only the host_converge word, whose argv is a compiled constant; only
// under the job lock (a running job wins, and the timer the previous bundle
// installed converges within the minute anyway); and every line of it in the
// journal under its own header.

import (
	"context"
	"log"
	"strings"
	"sync"
	"time"

	"joinery-agent/primitives"
)

// convergeAfterBundle runs host_converge once, now, because a bundle landed.
func convergeAfterBundle(cfg *Config, db *DB, jobLock *sync.Mutex) {
	if cfg == nil || !cfg.Siteless {
		return
	}
	if !jobLock.TryLock() {
		log.Printf("=== Bundle converge === a job holds the lock; the host timer converges on its next tick")
		return
	}
	defer jobLock.Unlock()
	done := writeJobMarker("bundle converge")
	defer done()

	policy, err := primitives.LoadPolicy(cfg.PolicyPath)
	if err != nil {
		log.Printf("=== Bundle converge === not run: acceptance policy unusable: %v", err)
		return
	}
	word, ok := primitives.Lookup("host_converge")
	if !ok {
		log.Printf("=== Bundle converge === not run: this agent has no host_converge word")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), word.Timeout)
	defer cancel()
	log.Printf("=== Bundle converge === a new support bundle is installed; running host_converge")
	result, err := primitives.Execute(ctx, execEnvFor(cfg, db), policy, primitives.Request{Primitive: "host_converge"})
	if err != nil {
		log.Printf("=== Bundle converge === host_converge did not complete: %v", err)
		return
	}
	output, _ := result["output"].(string)
	lines := strings.Split(strings.TrimRight(output, "\n"), "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			log.Printf("  %s", line)
		}
	}
	log.Printf("=== Bundle converge === done (%d line(s) of transcript)", len(lines))
}

// bundleConvergeTimeoutFloor is what a test pins: the word's own timeout is
// the bound, and it is minutes, not the poll's seconds.
const bundleConvergeTimeoutFloor = 5 * time.Minute
