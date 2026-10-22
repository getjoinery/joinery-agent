package primitives

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// check_status names the packages a package run left half done
// (fleet_security_patching B17): on 2026-10-21 dpkg was left mid-install in
// site containers, and nothing said so until the next install repaired it.
func TestDpkgUnfinishedNamesWhatDpkgAuditWould(t *testing.T) {
	path := filepath.Join(t.TempDir(), "status")
	body := "Package: apache2\nStatus: install ok installed\nVersion: 2.4.66\n\n" +
		"Package: php8.5-fpm\nStatus: install ok unpacked\nVersion: 8.5.4\n\n" +
		"Package: libssl3t64\nStatus: install ok half-configured\nVersion: 3.0.13\n\n" +
		"Package: php8.5-common\nStatus: deinstall ok config-files\nVersion: 8.5.3\n\n" +
		"Package: old-thing\nStatus: purge ok not-installed\n\n" +
		"Package: libc-bin\nStatus: install ok triggers-pending\nVersion: 2.39\n\n" +
		"Package: man-db\nStatus: install ok triggers-awaiting\nVersion: 2.12\n\n" +
		"Package: removing\nStatus: deinstall ok half-installed\nVersion: 1.0\n\n" +
		"Package: broken\nStatus: install reinstreq installed\nVersion: 1.0\n\n" +
		"Package: held\nStatus: hold ok installed\nVersion: 1.0\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	u, ok := dpkgUnfinished(path)
	if !ok {
		t.Fatal("a readable status file was not read")
	}
	var got []string
	for _, p := range u["packages"].([]map[string]interface{}) {
		got = append(got, p["name"].(string)+"="+p["state"].(string))
	}
	want := "php8.5-fpm=unpacked libssl3t64=half-configured libc-bin=triggers-pending man-db=triggers-awaiting removing=half-installed broken=reinstreq"
	if strings.Join(got, " ") != want {
		t.Fatalf("half done:\n got %s\nwant %s", strings.Join(got, " "), want)
	}
	if u["count"] != 6 {
		t.Fatalf("count %v, want 6", u["count"])
	}
}

func TestDpkgUnfinishedCleanMachineSaysNone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "status")
	if err := os.WriteFile(path, []byte("Package: apache2\nStatus: install ok installed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	u, ok := dpkgUnfinished(path)
	if !ok || u["count"] != 0 || len(u["packages"].([]map[string]interface{})) != 0 {
		t.Fatalf("clean machine: ok=%v %v", ok, u)
	}
	// No status file (no dpkg): nothing said, so the plane does not read it as clean.
	if _, ok := dpkgUnfinished(filepath.Join(t.TempDir(), "absent")); ok {
		t.Fatal("a missing status file was reported as read")
	}
	result := map[string]interface{}{}
	old := dpkgStatusPath
	dpkgStatusPath = filepath.Join(t.TempDir(), "absent")
	defer func() { dpkgStatusPath = old }()
	collectDpkgUnfinished(result)
	if _, there := result["dpkg_unfinished"]; there {
		t.Fatal("dpkg_unfinished reported with no status file")
	}
}

// A run that dies mid-upgrade can leave hundreds: all counted, twenty named.
func TestDpkgUnfinishedCapsTheNames(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 250; i++ {
		fmt.Fprintf(&b, "Package: p%d\nStatus: install ok unpacked\n\n", i)
	}
	path := filepath.Join(t.TempDir(), "status")
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	u, _ := dpkgUnfinished(path)
	if u["count"] != 250 || len(u["packages"].([]map[string]interface{})) != maxUnfinishedPackages {
		t.Fatalf("count %v, named %d", u["count"], len(u["packages"].([]map[string]interface{})))
	}
}

// A run under way holds apt's or dpkg's lock: the report says so, with when
// its holder started, and the lock is only looked at, never taken. The holder
// is another process, as apt is: a process never conflicts with its own lock.
func TestDpkgRunHeldSeesAnotherProcessHoldingTheLock(t *testing.T) {
	dir := t.TempDir()
	front := filepath.Join(dir, "lock-frontend")
	lock := filepath.Join(dir, "lock")
	for _, p := range []string{front, lock} {
		if err := os.WriteFile(p, nil, 0o640); err != nil {
			t.Fatal(err)
		}
	}
	if held, _, known := dpkgRunHeld([]string{front, lock}, "/proc"); !known || held {
		t.Fatalf("no holder: held=%v known=%v", held, known)
	}
	if _, _, known := dpkgRunHeld([]string{filepath.Join(dir, "absent")}, "/proc"); known {
		t.Fatal("no lock file to read, yet said known")
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestDpkgLockHolderHelper")
	cmd.Env = append(os.Environ(), "DPKG_LOCK_HOLD="+lock)
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { stdin.Close(); cmd.Wait() }()
	line, _ := bufio.NewReader(stdout).ReadString('\n')
	if strings.TrimSpace(line) != "locked" {
		t.Fatalf("the helper did not take the lock: %q", line)
	}
	held, since, known := dpkgRunHeld([]string{front, lock}, "/proc")
	if !known || !held {
		t.Fatalf("dpkg's lock held by another process: held=%v known=%v", held, known)
	}
	if now := time.Now().Unix(); since < now-120 || since > now+2 {
		t.Fatalf("the holder started at %d, not about now (%d)", since, now)
	}
	// Looking took nothing: once the holder ends, nothing holds it.
	stdin.Close()
	cmd.Wait()
	if held, _, _ := dpkgRunHeld([]string{front, lock}, "/proc"); held {
		t.Fatal("still held after the holder ended")
	}
}

// Run only as TestDpkgRunHeldSeesAnotherProcessHoldingTheLock's other process:
// it takes a write lock on the file named, says so, and holds it until stdin closes.
func TestDpkgLockHolderHelper(t *testing.T) {
	path := os.Getenv("DPKG_LOCK_HOLD")
	if path == "" {
		t.Skip("a helper process for the lock test")
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	lk := syscall.Flock_t{Type: syscall.F_WRLCK}
	if err := syscall.FcntlFlock(f.Fd(), syscall.F_SETLK, &lk); err != nil {
		t.Fatal(err)
	}
	fmt.Println("locked")
	bufio.NewReader(os.Stdin).ReadString('\n')
	os.Exit(0)
}
