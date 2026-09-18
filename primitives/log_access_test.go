package primitives

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// The rule of log_access.go, in each of its states. The three OFF states are
// the ones the spec names; the ON states prove the words are reachable at all.

func TestLogAccessReadsTheSettingWhenTheDatabaseAnswers(t *testing.T) {
	t.Setenv("AGENT_STATE_DIR", t.TempDir())
	// A marker saying ON must not win over a setting saying OFF.
	if err := ProjectLogAccess(true); err != nil {
		t.Fatal(err)
	}
	env := &ExecEnv{DB: fakeDB(settingAnswer(""), nil)}
	if on, src := LogAccessOn(context.Background(), env); on || src != "setting" {
		t.Fatalf("setting off: got on=%v source=%s", on, src)
	}
	env = &ExecEnv{DB: fakeDB(settingAnswer("1"), nil)}
	if on, src := LogAccessOn(context.Background(), env); !on || src != "setting" {
		t.Fatalf("setting on: got on=%v source=%s", on, src)
	}
	for _, spelling := range []string{"true", "YES", " on "} {
		env = &ExecEnv{DB: fakeDB(settingAnswer(spelling), nil)}
		if on, _ := LogAccessOn(context.Background(), env); !on {
			t.Errorf("spelling %q must read as on", spelling)
		}
	}
}

func TestLogAccessWithNoSettingRowIsOff(t *testing.T) {
	t.Setenv("AGENT_STATE_DIR", t.TempDir())
	if err := ProjectLogAccess(true); err != nil {
		t.Fatal(err)
	}
	// The database answers with no row: not seeded yet. No proof, so off —
	// and the marker is not consulted, because the database DID answer.
	env := &ExecEnv{DB: fakeDB(map[string]fakeRows{
		"FROM stg_settings WHERE stg_name = $1": {columns: []string{"stg_value"}},
	}, nil)}
	if on, src := LogAccessOn(context.Background(), env); on || src != "setting" {
		t.Fatalf("no row: got on=%v source=%s", on, src)
	}
}

func TestLogAccessFallsBackToTheMarkerWhenTheDatabaseIsDown(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AGENT_STATE_DIR", dir)
	down := &ExecEnv{DB: fakeDB(nil, errors.New("connection refused"))}

	// Database down, marker off.
	if err := ProjectLogAccess(false); err != nil {
		t.Fatal(err)
	}
	if on, src := LogAccessOn(context.Background(), down); on || src != "marker" {
		t.Fatalf("db down + marker off: got on=%v source=%s", on, src)
	}

	// Database down, marker on: the file word still works.
	if err := ProjectLogAccess(true); err != nil {
		t.Fatal(err)
	}
	if on, src := LogAccessOn(context.Background(), down); !on || src != "marker" {
		t.Fatalf("db down + marker on: got on=%v source=%s", on, src)
	}
	if data, _ := os.ReadFile(filepath.Join(dir, "log_access")); string(data) != "1\n" {
		t.Fatalf("marker shape should match the run switch's, got %q", data)
	}
}

func TestLogAccessWithNoDatabaseAndNoMarkerIsOff(t *testing.T) {
	t.Setenv("AGENT_STATE_DIR", t.TempDir())
	down := &ExecEnv{DB: fakeDB(nil, errors.New("connection refused"))}
	if on, src := LogAccessOn(context.Background(), down); on || src != "none" {
		t.Fatalf("db down + no marker: got on=%v source=%s — a missing marker must read OFF", on, src)
	}
	// A provider that itself fails is the same state.
	failing := &ExecEnv{DB: func() (*sql.DB, error) { return nil, errors.New("no dsn") }}
	if on, _ := LogAccessOn(context.Background(), failing); on {
		t.Fatal("a failing provider with no marker must read OFF")
	}
	// No database at all (siteless) and no marker.
	if on, _ := LogAccessOn(context.Background(), &ExecEnv{}); on {
		t.Fatal("no database and no marker must read OFF")
	}
}

func TestLogAccessRefusalIsTheOwnersReason(t *testing.T) {
	t.Setenv("AGENT_STATE_DIR", t.TempDir())
	err := requireLogAccess(context.Background(), &ExecEnv{DB: fakeDB(settingAnswer("0"), nil)})
	if err == nil || !Refused(err) {
		t.Fatalf("expected a refusal, got %v", err)
	}
	if err.Error() != LogAccessRefusal {
		t.Fatalf("refusal reason %q must be the pinned one", err.Error())
	}
}
