package primitives

import (
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
)

func TestLockHeldInReadsTheKernelsTable(t *testing.T) {
	table := "1: FLOCK  ADVISORY  WRITE 4242 fd:01:1234567 0 EOF\n" +
		"1: -> FLOCK  ADVISORY  WRITE 4343 08:02:777 0 EOF\n" +
		"2: POSIX  ADVISORY  WRITE 99 00:1b:55 0 EOF\n"
	cases := []struct {
		name     string
		maj, min uint32
		ino      uint64
		want     bool
	}{
		{"a granted lock, device in hex", 0xfd, 0x01, 1234567, true},
		{"a waiter is not a holder", 0x08, 0x02, 777, false},
		{"another inode on the same device", 0xfd, 0x01, 1234568, false},
		{"the same inode on another device", 0xfd, 0x02, 1234567, false},
		{"a POSIX lock is a lock", 0x00, 0x1b, 55, true},
	}
	for _, c := range cases {
		if got := lockHeldIn(table, c.maj, c.min, c.ino); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
	if lockHeldIn("", 0xfd, 0x01, 1234567) {
		t.Error("an empty table lists no lock")
	}
}

func upgradeSite(t *testing.T) (*ExecEnv, string) {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "uploads"), 0o755); err != nil {
		t.Fatal(err)
	}
	path := UpgradeLockPath(root)
	if err := os.WriteFile(path, nil, 0o666); err != nil {
		t.Fatal(err)
	}
	return &ExecEnv{SiteRoot: root}, path
}

// The lock as upgrade.php takes it: its own open file, LOCK_EX, never waiting.
func takeLock(t *testing.T, path string) (*os.File, bool) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, false
	}
	return f, true
}

func TestUpgradeRunningIsTheLockBeingHeld(t *testing.T) {
	env, path := upgradeSite(t)
	if UpgradeRunning(env) || !lockFree(path) {
		t.Fatal("a lock file nothing holds is no upgrade")
	}
	f, ok := takeLock(t, path)
	if !ok {
		t.Fatal("the lock could not be taken")
	}
	if !UpgradeRunning(env) || lockFree(path) {
		t.Fatal("a held lock is an upgrade running")
	}
	f.Close()
	if UpgradeRunning(env) || !lockFree(path) {
		t.Fatal("a lock released (as when upgrade.php exits, however it ends) is no upgrade")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if UpgradeRunning(env) || !lockFree(path) {
		t.Fatal("no lock file is no upgrade")
	}
	if UpgradeRunning(&ExecEnv{}) {
		t.Fatal("a machine with no site runs no site upgrade")
	}
}

// upgrade.php refuses to start when it cannot take the lock at once. Asking
// whether an upgrade runs, however often, must never be the reason.
func TestAskingNeverTurnsAnUpgradeAway(t *testing.T) {
	env, path := upgradeSite(t)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				UpgradeRunning(env)
				lockFree(path)
			}
		}
	}()
	refused := 0
	for i := 0; i < 20000; i++ {
		f, ok := takeLock(t, path)
		if !ok {
			refused++
			continue
		}
		f.Close()
	}
	close(stop)
	wg.Wait()
	if refused > 0 {
		t.Fatalf("an upgrade was refused %d times by the agent asking", refused)
	}
}
