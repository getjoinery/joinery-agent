package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The marker is a contract between this program and a shell script it will
// never call. These tests pin the half that lives here: that it exists for the
// life of a job, that it names the running pid, and that it goes away.

func withTempMarker(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "joinery-agent", "job-running")
	restore := jobMarkerPath
	jobMarkerPath = path
	t.Cleanup(func() { jobMarkerPath = restore })
	return path
}

func TestTheMarkerExistsWhileAJobRunsAndNotAfter(t *testing.T) {
	path := withTempMarker(t)

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("no marker should exist before a job starts")
	}

	clear := markJobRunning(4242)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("a running job should be marked: %v", err)
	}

	clear()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("the marker outlived the job — install_agent.sh would defer restarts forever")
	}
}

func TestTheMarkerNamesThisProcessFirst(t *testing.T) {
	// The pid is what makes a stale marker recoverable rather than a wedge: the
	// installer checks whether that process is still alive. It is on the first
	// line deliberately, so a half-written file still answers the question that
	// gates the restart.
	path := withTempMarker(t)
	defer markJobRunning(7)()

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(body)), "\n")
	if len(lines) < 2 {
		t.Fatalf("the marker should carry the pid and the job id, got %q", body)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(lines[0]))
	if err != nil {
		t.Fatalf("the first line should be a bare pid, got %q", lines[0])
	}
	if pid != os.Getpid() {
		t.Errorf("the marker names pid %d; this process is %d", pid, os.Getpid())
	}
	if strings.TrimSpace(lines[1]) != "7" {
		t.Errorf("the second line should be the job id, got %q", lines[1])
	}
}

func TestAnUnwritableMarkerDoesNotStopTheJob(t *testing.T) {
	// The consequence of no marker is the old behaviour — a restart mid-job and
	// a requeue — which is wasteful. The consequence of refusing to run would be
	// a node that cannot be upgraded at all. The first is the better failure.
	restore := jobMarkerPath
	jobMarkerPath = filepath.Join(string(os.PathSeparator), "proc", "definitely-not-writable", "job-running")
	defer func() { jobMarkerPath = restore }()

	clear := markJobRunning(1)
	if clear == nil {
		t.Fatal("markJobRunning must always return a usable clear function")
	}
	clear() // must not panic
}
