package primitives

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// What PHP this machine runs, and whether the code serving requests is the code
// installed (specs/fleet_security_patching.md WP1).
//
// A package upgrade replaces PHP's binary on disk, but a php-fpm master started
// before it keeps running the old one until it is reloaded or restarted: its
// /proc/PID/exe then names the binary with " (deleted)". On 2026-10-21 every
// site container kept serving the unpatched PHP after its packages were
// upgraded, and nothing reported it. Read from dpkg's status file and /proc,
// as the rest of check_status is: no command runs.
//
// The result, under "php", only where the machine has PHP or a php-fpm:
//
//	packages  each installed phpX.Y-fpm, -cli and -common, with its version and
//	          when it was installed (its dpkg file list's time), so the plane
//	          can tell a php-fpm still on old code minutes after an update from
//	          one left on it
//	fpm       each php-fpm master: its binary, running_current (false when
//	          that binary was replaced on disk; absent when /proc would not
//	          say), when it started, and when its oldest worker started
//
// Variables so a test can point them at a fixture.
var (
	dpkgStatusPath = "/var/lib/dpkg/status"
	dpkgInfoDir    = "/var/lib/dpkg/info"
	procRoot       = "/proc"
)

// The PHP packages a security fix arrives in.
var phpPackagePattern = regexp.MustCompile(`^php[0-9]+\.[0-9]+-(fpm|cli|common)$`)

// At most this many php-fpm masters are reported; a machine runs one per PHP
// version.
const maxFPMMasters = 8

// /proc/PID/stat's start time is in clock ticks since boot, at USER_HZ, which
// Linux fixes at 100 for /proc on every architecture it runs on.
const procTicksPerSecond = 100

func collectPHP(result map[string]interface{}) {
	packages := phpPackages(dpkgStatusPath)
	masters := phpFPMMasters(procRoot)
	if len(packages) == 0 && len(masters) == 0 {
		return
	}
	result["php"] = map[string]interface{}{
		"packages": packages,
		"fpm":      masters,
	}
}

// phpPackages reads dpkg's status file: every installed PHP package a fix
// arrives in, by name, with its version, sorted by name.
func phpPackages(path string) []map[string]interface{} {
	out := []map[string]interface{}{}
	f, err := os.Open(path)
	if err != nil {
		return out
	}
	defer f.Close()
	var name, status, version string
	flush := func() {
		if phpPackagePattern.MatchString(name) && status == "install ok installed" && version != "" {
			p := map[string]interface{}{"name": name, "version": version}
			if at := packageInstalledAt(name); at > 0 {
				p["installed_at"] = at
			}
			out = append(out, p)
		}
		name, status, version = "", "", ""
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
		case strings.HasPrefix(line, "Version: "):
			version = strings.TrimSpace(strings.TrimPrefix(line, "Version: "))
		}
	}
	flush()
	sort.Slice(out, func(i, j int) bool { return out[i]["name"].(string) < out[j]["name"].(string) })
	return out
}

// packageInstalledAt is when dpkg last unpacked a package: its file list's
// modification time, in Unix seconds, or 0 where there is none.
func packageInstalledAt(name string) int64 {
	for _, f := range []string{name + ".list", name + ":amd64.list", name + ":arm64.list"} {
		if fi, err := os.Stat(filepath.Join(dpkgInfoDir, f)); err == nil {
			return fi.ModTime().Unix()
		}
	}
	return 0
}

// A process as /proc tells it: what it runs as, its parent, when it started.
type procEntry struct {
	pid     int
	ppid    int
	cmdline string
	started int64 // Unix seconds; 0 when unknown
}

// phpFPMMasters walks /proc for php-fpm masters ("php-fpm: master process
// (...)") and their workers ("php-fpm: pool NAME").
func phpFPMMasters(root string) []map[string]interface{} {
	out := []map[string]interface{}{}
	dirs, err := os.ReadDir(root)
	if err != nil {
		return out
	}
	boot := bootTime(filepath.Join(root, "stat"))
	var masters, workers []procEntry
	for _, d := range dirs {
		pid, err := strconv.Atoi(d.Name())
		if err != nil || pid <= 0 {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(root, d.Name(), "cmdline"))
		if err != nil || len(raw) == 0 {
			continue
		}
		cmd := strings.TrimRight(strings.ReplaceAll(string(raw), "\x00", " "), " ")
		isMaster := strings.HasPrefix(cmd, "php-fpm: master process")
		isWorker := strings.HasPrefix(cmd, "php-fpm: pool ")
		if !isMaster && !isWorker {
			continue
		}
		e := procEntry{pid: pid, cmdline: cmd}
		e.ppid, e.started = procStat(filepath.Join(root, d.Name(), "stat"), boot)
		if isMaster {
			masters = append(masters, e)
		} else {
			workers = append(workers, e)
		}
	}
	sort.Slice(masters, func(i, j int) bool { return masters[i].pid < masters[j].pid })
	for _, m := range masters {
		if len(out) >= maxFPMMasters {
			break
		}
		entry := map[string]interface{}{}
		// The binary it runs: readable for a master running as the agent's
		// own user. " (deleted)" is the kernel's word for a file replaced
		// since the process started.
		if exe, err := os.Readlink(filepath.Join(root, strconv.Itoa(m.pid), "exe")); err == nil {
			current := !strings.HasSuffix(exe, " (deleted)")
			entry["binary"] = safeProcPath(strings.TrimSuffix(exe, " (deleted)"))
			entry["running_current"] = current
		}
		if m.started > 0 {
			entry["started_at"] = m.started
		}
		var oldest int64
		for _, w := range workers {
			if w.ppid == m.pid && w.started > 0 && (oldest == 0 || w.started < oldest) {
				oldest = w.started
			}
		}
		if oldest > 0 {
			entry["oldest_worker_started_at"] = oldest
		}
		out = append(out, entry)
	}
	return out
}

// bootTime is /proc/stat's btime: when the machine booted, in Unix seconds.
func bootTime(path string) int64 {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "btime ") {
			v, err := strconv.ParseInt(strings.TrimSpace(strings.TrimPrefix(line, "btime ")), 10, 64)
			if err == nil {
				return v
			}
		}
	}
	return 0
}

// procStat reads a process's parent and start time from /proc/PID/stat. The
// command name is in parentheses and may hold spaces or parentheses itself, so
// the fields are counted from the last ")".
func procStat(path string, boot int64) (ppid int, started int64) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, 0
	}
	s := string(raw)
	i := strings.LastIndex(s, ")")
	if i < 0 {
		return 0, 0
	}
	f := strings.Fields(s[i+1:])
	// After the name: state (field 3), ppid (4), ... starttime (22).
	if len(f) < 20 {
		return 0, 0
	}
	ppid, _ = strconv.Atoi(f[1])
	ticks, err := strconv.ParseInt(f[19], 10, 64)
	if err != nil || boot == 0 {
		return ppid, 0
	}
	return ppid, boot + ticks/procTicksPerSecond
}

// safeProcPath keeps a binary's path to the characters a path is made of.
func safeProcPath(p string) string {
	var b strings.Builder
	for _, r := range p {
		if r == '/' || r == '.' || r == '-' || r == '_' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			b.WriteRune(r)
		}
	}
	if b.Len() > 200 {
		return b.String()[:200]
	}
	return b.String()
}
