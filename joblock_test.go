package main

import (
	"sync"
	"testing"
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
