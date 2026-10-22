package primitives

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// The packages a package run left half done (specs/fleet_security_patching.md
// B17). When apt or dpkg dies part way, as on 2026-10-21 when a container's
// apt-get update pulled the files out from under an install, dpkg leaves
// packages unpacked, half-installed or awaiting triggers. Nothing said so until
// the next install_security_updates run finished them, and a site container
// has no hourly check of its own. Read from dpkg's status file, as the PHP
// report is: no command runs.
//
// "Half done" is what dpkg --audit lists, which is also what
// install_security_updates.sh repairs: a package flagged reinstreq, or in one
// of the states below. Wanted or not does not matter; a removal that died part
// way is as unfinished as an install.
//
// A run under way leaves packages in those states too, until it ends. So the
// report says whether one is: apt holds lock-frontend and dpkg holds lock for
// as long as they run, and the kernel says whether anyone holds either
// (F_GETLK) without taking it. Its holder's start time says how long it has
// run, so a run hung on a question is not mistaken for one under way.
//
// The result, under "dpkg_unfinished", only where the status file was read:
//
//	count        how many packages are half done (0 on a clean machine)
//	packages     the first maxUnfinishedPackages of them, each {name, state}:
//	             state is dpkg's status word, or reinstreq
//	in_progress  whether apt or dpkg holds its lock now; absent where neither
//	             lock file could be read
//	since        when the holder started, in Unix seconds; absent where /proc
//	             would not say
var unfinishedStates = map[string]bool{
	"unpacked":          true,
	"half-configured":   true,
	"half-installed":    true,
	"triggers-awaiting": true,
	"triggers-pending":  true,
}

// A run that dies mid-upgrade can leave hundreds; the names are for a person.
const maxUnfinishedPackages = 20

// The locks apt and dpkg hold while a package run is under way, apt's first.
// A variable so a test can point it at its own files.
var dpkgLockPaths = []string{"/var/lib/dpkg/lock-frontend", "/var/lib/dpkg/lock"}

func collectDpkgUnfinished(result map[string]interface{}) {
	u, ok := dpkgUnfinished(dpkgStatusPath)
	if !ok {
		return
	}
	if held, since, known := dpkgRunHeld(dpkgLockPaths, procRoot); known {
		u["in_progress"] = held
		if since > 0 {
			u["since"] = since
		}
	}
	result["dpkg_unfinished"] = u
}

// dpkgRunHeld asks the kernel whether any process holds apt's or dpkg's lock,
// without taking it. since is when the holder started (0 where /proc would
// not say). known is false where no lock file could be opened.
func dpkgRunHeld(paths []string, proc string) (held bool, since int64, known bool) {
	for _, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		lk := syscall.Flock_t{Type: syscall.F_WRLCK}
		err = syscall.FcntlFlock(f.Fd(), syscall.F_GETLK, &lk)
		f.Close()
		if err != nil {
			continue
		}
		known = true
		if lk.Type != syscall.F_UNLCK {
			if lk.Pid > 0 {
				_, since = procStat(filepath.Join(proc, strconv.Itoa(int(lk.Pid)), "stat"), bootTime(filepath.Join(proc, "stat")))
			}
			return true, since, true
		}
	}
	return false, 0, known
}

// dpkgUnfinished reads dpkg's status file. ok is false where there is none to
// read (a machine without dpkg), so the plane can tell "none" from "cannot say".
func dpkgUnfinished(path string) (map[string]interface{}, bool) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	packages := []map[string]interface{}{}
	count := 0
	var name, status string
	flush := func() {
		// Status: want flag status, e.g. "install reinstreq half-installed".
		if w := strings.Fields(status); name != "" && len(w) == 3 {
			state := ""
			if w[1] == "reinstreq" {
				state = "reinstreq"
			} else if unfinishedStates[w[2]] {
				state = w[2]
			}
			if state != "" {
				count++
				if len(packages) < maxUnfinishedPackages {
					packages = append(packages, map[string]interface{}{"name": name, "state": state})
				}
			}
		}
		name, status = "", ""
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
			flush()
		case strings.HasPrefix(line, "Package: "):
			name = strings.TrimSpace(strings.TrimPrefix(line, "Package: "))
		case strings.HasPrefix(line, "Status: "):
			status = strings.TrimSpace(strings.TrimPrefix(line, "Status: "))
		}
	}
	if sc.Err() != nil {
		return nil, false
	}
	flush()
	return map[string]interface{}{"count": count, "packages": packages}, true
}
