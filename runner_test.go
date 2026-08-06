package main

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// fakeStore is an in-memory runnerStore so the main/teardown flow can be
// tested without a database. Step execution is stubbed via Runner.exec, so
// no SSH happens either.
type fakeStore struct {
	output       strings.Builder
	currentSteps []int
	completed    int
	failed       int
	failMsg      string
}

func (f *fakeStore) AppendOutput(jobID int64, text string, currentStep int) error {
	f.output.WriteString(text)
	f.currentSteps = append(f.currentSteps, currentStep)
	return nil
}
func (f *fakeStore) CompleteJob(jobID int64) error { f.completed++; return nil }
func (f *fakeStore) FailJob(jobID int64, msg string) error {
	f.failed++
	f.failMsg = msg
	return nil
}
func (f *fakeStore) GetNodeConnInfo(nodeID int64) (*NodeConnInfo, error) {
	return nil, errors.New("no node info in tests")
}
func (f *fakeStore) GetNodeAPIInfo(nodeID int64) (*NodeAPIInfo, error) {
	return nil, errors.New("no api info in tests")
}
func (f *fakeStore) GetBackupTargetCredentials(targetID int64) (string, error) {
	return "", errors.New("no backup target creds in tests")
}
func (f *fakeStore) GetBackupTargetNodeCredentials(targetID int64) (string, error) {
	return "", errors.New("no backup target node creds in tests")
}

// testRunner returns a Runner whose step execution is the given stub.
// executed collects the labels of every step the stub was asked to run.
func testRunner(store *fakeStore, executed *[]string, failLabels map[string]bool) *Runner {
	r := &Runner{db: store, sshPool: NewSSHPool()}
	r.exec = func(job *Job, step *Step, timeout time.Duration) (string, error) {
		*executed = append(*executed, step.Label)
		if failLabels[step.Label] {
			return "", errors.New("boom")
		}
		return "ok:" + step.Label, nil
	}
	return r
}

func jobWith(steps ...Step) *Job {
	return &Job{ID: 1, Commands: JobCommands{Steps: steps}}
}

func TestPartitionSteps(t *testing.T) {
	steps := []Step{
		{Label: "a"},
		{Label: "t1", Teardown: true},
		{Label: "b"},
		{Label: "t2", Teardown: true},
	}
	mainSteps, teardownSteps := partitionSteps(steps)
	if len(mainSteps) != 2 || mainSteps[0].Label != "a" || mainSteps[1].Label != "b" {
		t.Fatalf("main phase wrong: %+v", mainSteps)
	}
	if len(teardownSteps) != 2 || teardownSteps[0].Label != "t1" || teardownSteps[1].Label != "t2" {
		t.Fatalf("teardown phase wrong: %+v", teardownSteps)
	}

	// No flags anywhere → everything is main, teardown empty (old builders).
	mainSteps, teardownSteps = partitionSteps([]Step{{Label: "x"}, {Label: "y"}})
	if len(mainSteps) != 2 || len(teardownSteps) != 0 {
		t.Fatalf("unflagged steps must all be main: main=%d teardown=%d", len(mainSteps), len(teardownSteps))
	}
}

// The spec's canonical case: second of three main steps fails — teardown
// still runs, the job ends failed, and the error names the original step.
func TestFailedMainStepStillRunsTeardown(t *testing.T) {
	store := &fakeStore{}
	var executed []string
	r := testRunner(store, &executed, map[string]bool{"main2": true})

	r.Execute(jobWith(
		Step{Label: "main1"},
		Step{Label: "main2"},
		Step{Label: "main3"},
		Step{Label: "cleanup1", Teardown: true},
		Step{Label: "cleanup2", Teardown: true},
	))

	want := []string{"main1", "main2", "cleanup1", "cleanup2"}
	if strings.Join(executed, ",") != strings.Join(want, ",") {
		t.Fatalf("execution order wrong: got %v want %v", executed, want)
	}
	if store.failed != 1 || store.completed != 0 {
		t.Fatalf("outcome wrong: failed=%d completed=%d", store.failed, store.completed)
	}
	if store.failMsg != "Step 2 (main2) failed: boom" {
		t.Fatalf("error must keep naming the original failing step, got: %q", store.failMsg)
	}
	if !strings.Contains(store.output.String(), "=== Teardown ===") {
		t.Fatalf("teardown output missing its header:\n%s", store.output.String())
	}
}

func TestSuccessStillRunsTeardown(t *testing.T) {
	store := &fakeStore{}
	var executed []string
	r := testRunner(store, &executed, nil)

	r.Execute(jobWith(
		Step{Label: "main1"},
		Step{Label: "cleanup1", Teardown: true},
	))

	if strings.Join(executed, ",") != "main1,cleanup1" {
		t.Fatalf("execution order wrong: %v", executed)
	}
	if store.completed != 1 || store.failed != 0 {
		t.Fatalf("outcome wrong: failed=%d completed=%d", store.failed, store.completed)
	}
}

func TestTeardownFailureNeverChangesOutcome(t *testing.T) {
	store := &fakeStore{}
	var executed []string
	r := testRunner(store, &executed, map[string]bool{"cleanup1": true})

	r.Execute(jobWith(
		Step{Label: "main1"},
		Step{Label: "cleanup1", Teardown: true},
		Step{Label: "cleanup2", Teardown: true},
	))

	// cleanup1 failing must not stop cleanup2 nor fail the job.
	if strings.Join(executed, ",") != "main1,cleanup1,cleanup2" {
		t.Fatalf("teardown must continue past a failure: %v", executed)
	}
	if store.completed != 1 || store.failed != 0 {
		t.Fatalf("teardown failure was promoted to the job outcome: failed=%d completed=%d", store.failed, store.completed)
	}
	if !strings.Contains(store.output.String(), "[teardown error (ignored): boom]") {
		t.Fatalf("teardown failure not visible in output:\n%s", store.output.String())
	}
}

func TestEmptyMainPhaseRunsTeardownAndCompletes(t *testing.T) {
	store := &fakeStore{}
	var executed []string
	r := testRunner(store, &executed, nil)

	r.Execute(jobWith(Step{Label: "cleanup1", Teardown: true}))

	if strings.Join(executed, ",") != "cleanup1" {
		t.Fatalf("teardown must run with no main steps: %v", executed)
	}
	if store.completed != 1 || store.failed != 0 {
		t.Fatalf("empty main phase must complete: failed=%d completed=%d", store.failed, store.completed)
	}

	// And a fully empty job still completes.
	store2 := &fakeStore{}
	var executed2 []string
	r2 := testRunner(store2, &executed2, nil)
	r2.Execute(jobWith())
	if store2.completed != 1 || len(executed2) != 0 {
		t.Fatalf("empty job must complete without executing anything")
	}
}

func TestTeardownDoesNotAdvanceCurrentStep(t *testing.T) {
	store := &fakeStore{}
	var executed []string
	r := testRunner(store, &executed, map[string]bool{"main2": true})

	r.Execute(jobWith(
		Step{Label: "main1"},
		Step{Label: "main2"},
		Step{Label: "cleanup1", Teardown: true},
	))

	// Main phase ended at index 1; every teardown append must reuse it.
	max := 0
	for _, s := range store.currentSteps {
		if s > max {
			max = s
		}
	}
	if max != 1 {
		t.Fatalf("teardown advanced mjb_current_step past the main phase: max index %d", max)
	}
}

func TestReplayTeardownRunsOnlyTeardownSteps(t *testing.T) {
	store := &fakeStore{}
	var executed []string
	r := testRunner(store, &executed, nil)

	job := jobWith(
		Step{Label: "main1"},
		Step{Label: "cleanup1", Teardown: true},
	)
	job.CurrentStep = 0
	r.ReplayTeardown(job)

	if strings.Join(executed, ",") != "cleanup1" {
		t.Fatalf("replay must run teardown steps only: %v", executed)
	}
	if store.completed != 0 && store.failed != 0 {
		t.Fatalf("replay must never write an outcome")
	}
}
