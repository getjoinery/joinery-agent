package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The update watchdog replaced an error taxonomy. The old rollback fired on any
// fatal init error, so a PostgreSQL outage in the window after a self-update
// condemned a good release and refused it until a newer one shipped. These pin
// the replacement: rollback follows from a start that never reached health, and
// from nothing else.

// watchdogUpdater builds an Updater over a temp install path, optionally with a
// previous binary to fall back to.
func watchdogUpdater(t *testing.T, running string, withBackup bool) *Updater {
	t.Helper()
	dir := t.TempDir()
	install := filepath.Join(dir, "joinery-agent")
	if err := os.WriteFile(install, []byte("NEW-BINARY"), 0755); err != nil {
		t.Fatalf("seed installed binary: %v", err)
	}
	u := &Updater{
		installPath: install,
		platform:    "linux-amd64",
		running:     running,
		warned:      map[string]bool{},
	}
	if withBackup {
		if err := os.WriteFile(u.bakPath(), []byte("OLD-BINARY"), 0755); err != nil {
			t.Fatalf("seed backup binary: %v", err)
		}
	}
	return u
}

func TestNoPendingMarkerMeansNothingToRollBack(t *testing.T) {
	u := watchdogUpdater(t, "1.6.0", true)

	if u.CheckFailedBoot() {
		t.Fatal("an ordinary start must not roll anything back")
	}
	if data, _ := os.ReadFile(u.installPath); string(data) != "NEW-BINARY" {
		t.Fatal("the installed binary was replaced with no reason to")
	}
}

func TestFirstStartAfterASwapIsGivenItsChance(t *testing.T) {
	// The marker exists from the swap, unattempted. This process IS the trial —
	// rolling back here would mean no update could ever succeed.
	u := watchdogUpdater(t, "1.6.0", true)
	u.markPendingConfirmation("1.6.0")

	if u.CheckFailedBoot() {
		t.Fatal("the first start after a swap must be allowed to run")
	}
	if data, _ := os.ReadFile(u.installPath); string(data) != "NEW-BINARY" {
		t.Fatal("the new binary was rolled back on its very first start")
	}

	// ...but the attempt is now on record, so a death before confirming is seen.
	data, err := os.ReadFile(u.pendingPath())
	if err != nil {
		t.Fatalf("the pending marker should survive the first start: %v", err)
	}
	if !strings.Contains(string(data), "1") {
		t.Fatalf("the boot attempt was not recorded: %q", data)
	}
}

func TestASecondStartWithoutHealthRollsBack(t *testing.T) {
	// The first start died before ConfirmHealthy — that is the whole signal.
	u := watchdogUpdater(t, "1.6.0", true)
	u.markPendingConfirmation("1.6.0")
	u.CheckFailedBoot() // first start, records the attempt

	if !u.CheckFailedBoot() {
		t.Fatal("a version that never reached health must be rolled back")
	}
	if data, _ := os.ReadFile(u.installPath); string(data) != "OLD-BINARY" {
		t.Fatalf("the previous binary was not restored: %q", data)
	}
	rejected, err := os.ReadFile(u.rejectedPath())
	if err != nil || strings.TrimSpace(string(rejected)) != "1.6.0" {
		t.Fatalf("the failing version should be recorded as rejected: %q %v", rejected, err)
	}
}

func TestReachingHealthDisarmsTheWatchdog(t *testing.T) {
	// ConfirmHealthy is the fact no outage can fake, so it is what clears the
	// marker. After it, a later start has nothing to act on.
	u := watchdogUpdater(t, "1.6.0", true)
	u.markPendingConfirmation("1.6.0")
	u.CheckFailedBoot()

	u.ConfirmHealthy()

	if _, err := os.Stat(u.pendingPath()); !os.IsNotExist(err) {
		t.Fatal("a confirmed-healthy version must leave no pending marker")
	}
	if u.CheckFailedBoot() {
		t.Fatal("a version that proved healthy must never be rolled back")
	}
}

func TestAMarkerForAnotherVersionIsDebrisNotAVerdict(t *testing.T) {
	// A marker naming a version this binary is not says nothing about this
	// binary. Acting on it would roll back a release for its predecessor's sins.
	u := watchdogUpdater(t, "1.6.0", true)
	u.markPendingConfirmation("1.4.0")

	if u.CheckFailedBoot() {
		t.Fatal("a marker for a different version must not condemn this one")
	}
	if _, err := os.Stat(u.pendingPath()); !os.IsNotExist(err) {
		t.Fatal("stale debris should be cleared, not left to fire later")
	}
}

func TestAnOutageCannotCondemnAGoodRelease(t *testing.T) {
	// The regression in one test. A healthy start that happens during a database
	// outage still reaches ConfirmHealthy — because the database is no longer on
	// the path to it — so the version is confirmed, not rejected.
	u := watchdogUpdater(t, "1.6.0", true)
	u.markPendingConfirmation("1.6.0")
	u.CheckFailedBoot()

	// The agent runs through the outage and confirms, as it now does.
	u.ConfirmHealthy()

	if _, err := os.Stat(u.rejectedPath()); !os.IsNotExist(err) {
		t.Fatal("a release must not be marked rejected because the database was down")
	}
	if data, _ := os.ReadFile(u.installPath); string(data) != "NEW-BINARY" {
		t.Fatal("a release must not be rolled back because the database was down")
	}
}
