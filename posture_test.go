package main

import (
	"errors"
	"sync"
	"testing"
)

// One binary serves two kinds of machine. These pin the two decisions that
// tell them apart, both of which used to be settled by a default the agent
// never questioned — and one of which used to kill the process outright.

// probe returns a canned answer, and counts how many times it was asked — a
// capability that stops asking is the specific bug these guard.
func probeReturning(missing []string, err error, calls *int) func() ([]string, error) {
	return func() ([]string, error) {
		if calls != nil {
			*calls++
		}
		return missing, err
	}
}

func TestAControlPlaneServesItsLocalQueue(t *testing.T) {
	q := NewLocalQueue(true, probeReturning(nil, nil, nil), nil)
	q.Refresh()

	if !q.Available() {
		t.Fatal("all tables present must mean a local queue")
	}
}

func TestAPlainManagedNodeHasNoLocalQueueAndThatIsNotAnError(t *testing.T) {
	// The state every node in the fleet is in: server_manager was never
	// installed, so none of its tables exist. Node work only — not a fatal,
	// which is what stopped the agent running anywhere but a control plane.
	missing := []string{"mgn_managed_nodes", "mjb_management_jobs", "ahb_agent_heartbeats"}
	q := NewLocalQueue(true, probeReturning(missing, nil, nil), nil)
	q.Refresh()

	if q.Available() {
		t.Fatal("a node with none of the plane tables must not serve a local queue")
	}
}

func TestAPartialSchemaIsAlsoNoLocalQueue(t *testing.T) {
	q := NewLocalQueue(true, probeReturning([]string{"ahb_agent_heartbeats"}, nil, nil), nil)
	q.Refresh()

	if q.Available() {
		t.Fatal("one missing table must be enough to decline the local queue")
	}
}

func TestAnUnanswerableProbeDeclinesTheLocalQueue(t *testing.T) {
	q := NewLocalQueue(true, probeReturning(nil, errors.New("connection refused"), nil), nil)
	q.Refresh()

	if q.Available() {
		t.Fatal("a probe that failed must not be read as a queue being present")
	}
}

func TestADatabaseOutageAtStartupDoesNotLatchTheQueueOffForever(t *testing.T) {
	// The regression this type exists for. A control plane that restarts while
	// PostgreSQL is down used to decide "no local queue" once and serve nothing
	// until someone restarted it again — the lazy connection's whole benefit
	// thrown away one layer up.
	down := true
	q := NewLocalQueue(true, func() ([]string, error) {
		if down {
			return nil, errors.New("connection refused")
		}
		return nil, nil
	}, nil)

	q.Refresh()
	if q.Available() {
		t.Fatal("cannot be available while the database is down")
	}

	down = false
	q.Refresh()
	if !q.Available() {
		t.Fatal("the queue must return when the database does")
	}
}

func TestTheQueueGoesAwayAgainWhenTheDatabaseDoes(t *testing.T) {
	// Both directions, or the heartbeat keeps writing into a database that is
	// no longer answering and the dashboard reads the errors as a broken agent.
	down := false
	q := NewLocalQueue(true, func() ([]string, error) {
		if down {
			return nil, errors.New("connection refused")
		}
		return nil, nil
	}, nil)

	q.Refresh()
	if !q.Available() {
		t.Fatal("should start available")
	}

	down = true
	q.Refresh()
	if q.Available() {
		t.Fatal("a queue whose database went away must stop being available")
	}
}

func TestStaleJobRecoveryFiresWhenTheQueueArrivesNotAtStartup(t *testing.T) {
	// Jobs a dead process left running are found when the queue becomes
	// servable. On a plane whose database was down at boot that is not startup,
	// and recovery tied to startup would simply never run.
	down := true
	fired := 0
	q := NewLocalQueue(true, func() ([]string, error) {
		if down {
			return nil, errors.New("connection refused")
		}
		return nil, nil
	}, func() { fired++ })

	q.Refresh()
	if fired != 0 {
		t.Fatalf("nothing to recover while the queue is unavailable; fired %d", fired)
	}

	down = false
	q.Refresh()
	if fired != 1 {
		t.Fatalf("recovery must fire on the transition; fired %d", fired)
	}

	// Steady state is not a transition — recovery must not re-fire every tick.
	q.Refresh()
	q.Refresh()
	if fired != 1 {
		t.Fatalf("recovery re-fired while the queue stayed available; fired %d", fired)
	}
}

func TestTheOperatorSwitchLatchesWhereTheObservationDoesNot(t *testing.T) {
	// AGENT_LOCAL_JOBS=0 is a decision, not an observation. No amount of healthy
	// database should overturn it, and the probe should not even be consulted.
	calls := 0
	q := NewLocalQueue(false, probeReturning(nil, nil, &calls), nil)

	q.Refresh()
	q.Refresh()

	if q.Available() {
		t.Fatal("an operator who turned local jobs off must stay off")
	}
	if calls != 0 {
		t.Fatalf("the database was asked %d times about a decision it cannot change", calls)
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
