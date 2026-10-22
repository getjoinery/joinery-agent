package primitives

import (
	"strings"
	"testing"
	"time"
)

// The liveness watch tells a long word from a hung one by these two answers.

func TestInflightWithinAndPastDeadline(t *testing.T) {
	now := time.Date(2026, 10, 22, 3, 0, 0, 0, time.UTC)
	done := trackRun("backup_site", now.Add(4*time.Hour))
	if !RunningWithinDeadline(now) {
		t.Fatal("a word inside its deadline is running")
	}
	if late := OverdueRuns(now, 10*time.Minute); len(late) != 0 {
		t.Fatalf("not overdue yet: %v", late)
	}
	past := now.Add(4*time.Hour + 11*time.Minute)
	if RunningWithinDeadline(past) {
		t.Fatal("past its deadline it is not legitimate work any more")
	}
	late := OverdueRuns(past, 10*time.Minute)
	if len(late) != 1 || !strings.HasPrefix(late[0], "backup_site (deadline ") {
		t.Fatalf("overdue past the grace, named: %v", late)
	}
	done()
	done() // safe twice
	if RunningWithinDeadline(now) || len(OverdueRuns(past, 0)) != 0 {
		t.Fatal("a word that returned is not counted")
	}
}

func TestExecuteCountsTheWordWhileItRuns(t *testing.T) {
	// A refused word never reaches the deadline, so it is never counted.
	if _, err := Execute(t.Context(), nil, nil, Request{Primitive: "no_such_word"}); err == nil {
		t.Fatal("an unknown word is refused")
	}
	if RunningWithinDeadline(time.Now()) {
		t.Fatal("a refusal leaves nothing counted")
	}
}
