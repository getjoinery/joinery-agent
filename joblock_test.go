package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// The job lock. One binary, one job at a time, and the promise that matters:
// nothing swaps the binary or its scripts out from under a job that is running.
// The remote source holds this lock across a job; the self-update, bundle and
// manifest-heal checks each try for it and skip rather than wait.

func TestSelfUpdateNeverSwapsTheBinaryUnderARunningJob(t *testing.T) {
	var jobLock sync.Mutex
	jobLock.Lock() // a job is running — the remote source holds this too
	defer jobLock.Unlock()

	checked := false
	applied := attemptUpdate(&jobLock, func() bool {
		checked = true
		return true
	})

	if checked {
		t.Fatal("the update check ran while a job held the lock")
	}
	if applied {
		t.Fatal("a skipped check must not report an applied update")
	}
}

func TestSelfUpdateRunsWhenNoJobIsRunning(t *testing.T) {
	var jobLock sync.Mutex

	applied := attemptUpdate(&jobLock, func() bool { return true })

	if !applied {
		t.Fatal("an idle agent must run the update check and report the result")
	}
	if !jobLock.TryLock() {
		t.Fatal("the job lock was not released after the update check")
	}
	jobLock.Unlock()
}

func TestSelfUpdateReleasesTheLockWhenTheCheckPanics(t *testing.T) {
	// A wedged job lock would stop all work on the machine, so the release has
	// to survive the check blowing up.
	var jobLock sync.Mutex

	func() {
		defer func() { _ = recover() }()
		attemptUpdate(&jobLock, func() bool { panic("bad manifest") })
	}()

	if !jobLock.TryLock() {
		t.Fatal("a panicking update check left the job lock held")
	}
	jobLock.Unlock()
}

// The poll loop takes the job lock BEFORE it claims, and skips the tick when
// it cannot. A claim marks the job running on the plane, and the self-update
// exits the process after its swap: a claim made while the updater held the
// lock was a job nobody would ever run or report. Pinned on the plane's own
// node after a publish shipped agent 1.26.0 (job 18324, 2026-09-14).
func TestPollNeverClaimsWhileTheUpdaterHoldsTheLock(t *testing.T) {
	claims := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == pathClaim {
			claims++
		}
		w.Write([]byte(`{"api_version":"1.0","data":{"job":null}}`))
	}))
	defer server.Close()

	src := testSource(t, testIdentity(t, server.URL, 7))
	src.jobLock.Lock() // the updater is mid-swap, or a job is running
	defer src.jobLock.Unlock()

	done := make(chan struct{})
	go func() {
		src.pollOnce(context.Background())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("pollOnce waited for the lock; it must skip the tick, since the holder may be about to exit")
	}
	if claims != 0 {
		t.Fatalf("the poll claimed %d job(s) while the lock was held; a claim is a promise only the lock holder can keep", claims)
	}
}

// The lock is held from before the claim request leaves until the outcome is
// posted, and released afterwards.
func TestPollHoldsTheLockFromClaimThroughTheReport(t *testing.T) {
	var src *RemoteSource
	lockHeldDuring := map[string]bool{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// From the plane's side of the wire: is the agent holding its lock
		// while it talks to us?
		held := !src.jobLock.TryLock()
		if !held {
			src.jobLock.Unlock()
		}
		lockHeldDuring[req.URL.Path] = held
		switch req.URL.Path {
		case pathClaim:
			w.Write([]byte(`{"api_version":"1.0","data":{"job":{"job_id":11,"node_id":7,"primitive":"definitely_not_a_primitive"}}}`))
		default:
			w.Write([]byte(`{"api_version":"1.0","data":{}}`))
		}
	}))
	defer server.Close()

	src = testSource(t, testIdentity(t, server.URL, 7))
	src.pollOnce(context.Background())

	if !lockHeldDuring[pathClaim] {
		t.Fatal("the claim went out before the job lock was taken")
	}
	if seen, ok := lockHeldDuring[pathResult]; !ok {
		t.Fatal("the claimed job was never reported")
	} else if !seen {
		t.Fatal("the job lock was released before the outcome was posted")
	}
	if !src.jobLock.TryLock() {
		t.Fatal("the job lock was not released after the poll")
	}
	src.jobLock.Unlock()
}
