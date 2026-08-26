package main

import (
	"errors"
	"strings"
	"sync"
	"testing"
)

// One binary serves two kinds of machine. These pin the two decisions that
// tell them apart, both of which used to be settled by a default the agent
// never questioned — and one of which used to kill the process outright.

func TestAControlPlaneServesItsLocalQueue(t *testing.T) {
	local, reason := resolveLocalJobs(func() ([]string, error) { return nil, nil })

	if !local {
		t.Fatalf("all tables present must mean a local queue; got %q", reason)
	}
}

func TestAPlainManagedNodeHasNoLocalQueueAndThatIsNotAnError(t *testing.T) {
	// The state every node in the fleet is in: server_manager was never
	// installed, so none of its tables exist. This must resolve to node work
	// only — not a fatal, which is what stopped the agent running anywhere but
	// a control plane.
	missing := []string{"mgn_managed_nodes", "mjb_management_jobs", "ahb_agent_heartbeats"}
	local, reason := resolveLocalJobs(func() ([]string, error) { return missing, nil })

	if local {
		t.Fatal("a node with none of the plane tables must not serve a local queue")
	}
	for _, table := range missing {
		if !strings.Contains(reason, table) {
			t.Errorf("the reason should name what is missing; %q omits %s", reason, table)
		}
	}
}

func TestAPartialSchemaIsAlsoNoLocalQueue(t *testing.T) {
	// Half the tables is not half a queue.
	local, _ := resolveLocalJobs(func() ([]string, error) {
		return []string{"ahb_agent_heartbeats"}, nil
	})

	if local {
		t.Fatal("one missing table must be enough to decline the local queue")
	}
}

func TestAnUnanswerableProbeDeclinesTheLocalQueue(t *testing.T) {
	local, reason := resolveLocalJobs(func() ([]string, error) {
		return nil, errors.New("connection refused")
	})

	if local {
		t.Fatal("a probe that failed must not be read as a queue being present")
	}
	if !strings.Contains(reason, "connection refused") {
		t.Errorf("the reason should carry the probe error; got %q", reason)
	}
}

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
