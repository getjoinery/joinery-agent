package primitives

import (
	"sort"
	"sync"
	"time"
)

// The words running right now, each with the deadline Execute gave it.
//
// The agent's liveness watch (liveness.go in package main) reads this to tell a
// long job from a hung one. A backup or a restore may legitimately hold the job
// lock for hours, so "no poll for twenty minutes" alone would kill an agent
// doing exactly what it was asked. A word still running well past its own
// deadline is different: Execute's context has expired and the word has not
// returned, which is the hang this watch exists for (a script whose child
// keeps the output pipe open, an embedded word that ignores its context).
//
// Recipe words and plane jobs both pass through Execute, so both are counted.

type inflightRun struct {
	name     string
	deadline time.Time
}

var inflight = struct {
	mu   sync.Mutex
	next int
	runs map[int]inflightRun
}{runs: map[int]inflightRun{}}

// trackRun records one word as running until it returns. The returned func
// removes it and is safe to call more than once.
func trackRun(name string, deadline time.Time) func() {
	inflight.mu.Lock()
	inflight.next++
	id := inflight.next
	inflight.runs[id] = inflightRun{name: name, deadline: deadline}
	inflight.mu.Unlock()
	return func() {
		inflight.mu.Lock()
		delete(inflight.runs, id)
		inflight.mu.Unlock()
	}
}

// RunningWithinDeadline reports whether any word is running and has not yet
// passed its deadline: legitimate work holding the job lock.
func RunningWithinDeadline(now time.Time) bool {
	inflight.mu.Lock()
	defer inflight.mu.Unlock()
	for _, r := range inflight.runs {
		if now.Before(r.deadline) {
			return true
		}
	}
	return false
}

// OverdueRuns names each word still running more than grace past its
// deadline, oldest deadline first.
func OverdueRuns(now time.Time, grace time.Duration) []string {
	inflight.mu.Lock()
	var late []inflightRun
	for _, r := range inflight.runs {
		if now.After(r.deadline.Add(grace)) {
			late = append(late, r)
		}
	}
	inflight.mu.Unlock()
	sort.Slice(late, func(i, j int) bool { return late[i].deadline.Before(late[j].deadline) })
	names := make([]string, 0, len(late))
	for _, r := range late {
		names = append(names, r.name+" (deadline "+r.deadline.UTC().Format(time.RFC3339)+")")
	}
	return names
}
