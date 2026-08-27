package main

import (
	"context"
	"log"
	"strings"
	"sync"
	"time"
)

// How often the local-queue capability re-asks the database. Slow enough to be
// invisible on a machine that will never have one, fast enough that a control
// plane whose database was down at startup starts serving within a minute of it
// coming back.
const localQueueRecheckInterval = 30 * time.Second

// LocalQueue answers "does this machine have plane-local work to serve?", and
// keeps answering it.
//
// It must be able to change its mind in both directions, which is the whole
// reason it is a type rather than a bool. The tables it looks for belong to
// server_manager, so on a plain managed node the answer is a permanent no — but
// on a control plane it is a question about a database that can be down, and
// deciding it once at startup means a plane that restarted during an outage
// serves nothing until someone notices and restarts it again. That is precisely
// the failure the lazy connection exists to prevent, reintroduced one layer up.
//
// The operator's own switch (AGENT_LOCAL_JOBS=0) is different in kind and does
// latch: it is a decision, not an observation, and nothing about the database
// should overturn it.
type LocalQueue struct {
	mu        sync.Mutex
	permitted bool
	present   bool
	probe     func() ([]string, error)

	// onAvailable fires on each no→yes transition, including the first. Stale
	// job recovery hangs off it: jobs left running by a previous process are
	// found when the queue becomes servable, which is not always at startup.
	onAvailable func()
}

func NewLocalQueue(permitted bool, probe func() ([]string, error), onAvailable func()) *LocalQueue {
	return &LocalQueue{permitted: permitted, probe: probe, onAvailable: onAvailable}
}

// Available reports whether local work can be served right now. Every consumer
// asks per tick rather than at startup, so a queue that appears or disappears
// carries the heartbeat and the poll loop with it.
func (q *LocalQueue) Available() bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.permitted && q.present
}

// Refresh re-asks and reports whether the answer changed. A probe that errors —
// the database being unreachable is the usual reason — means not available, and
// is not remembered as an answer: the next Refresh asks again.
func (q *LocalQueue) Refresh() (changed bool) {
	// An operator who turned local jobs off gets no database traffic on their
	// behalf: the answer cannot change anything, so asking is pure noise in the
	// log of a machine that is already unhappy enough to be watched.
	q.mu.Lock()
	permitted := q.permitted
	q.mu.Unlock()
	if !permitted {
		return false
	}

	missing, err := q.probe()
	present := err == nil && len(missing) == 0

	q.mu.Lock()
	changed = present != q.present
	q.present = present
	fire := changed && present && q.onAvailable != nil
	q.mu.Unlock()

	if changed {
		switch {
		case present:
			log.Printf("local job queue is available — serving plane-local work")
		case err != nil:
			log.Printf("local job queue unavailable (%v) — serving node work only until it returns", err)
		default:
			log.Printf("no local job queue on this machine (no %s) — serving node work only",
				strings.Join(missing, ", "))
		}
	}
	if fire {
		q.onAvailable()
	}
	return changed
}

// Run re-resolves until the context ends. The first Refresh happens immediately
// so startup does not wait an interval to discover what it has.
func (q *LocalQueue) Run(ctx context.Context) {
	q.Refresh()

	ticker := time.NewTicker(localQueueRecheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			q.Refresh()
		}
	}
}
