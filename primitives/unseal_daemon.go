package primitives

// The site's unseal daemon, as the agent reports it (specs/unseal_daemon.md
// § Every other way it dies, Managed nodes): one word per poll, so a degraded
// node shows on the fleet dashboard, and the same word with its crash count in
// check_status.
//
// Read from what root left, never asked over the socket (the daemon answers
// only the pool user): the install record install_unseal_daemon.sh writes,
// the launcher's state (which build runs, the event log), the hold file, and
// the process table.
//
//	absent      no install record: the installer has not run here
//	held        the sentinel's hold is on: no Private vault opens until root lifts it
//	swap_refused  a site container that cannot lock memory, on swap that can reach a
//	            disk: the launcher does not start the daemon until swap is RAM-only
//	            (its swap_refused file), so no Private vault opens through it
//	previous    the launcher moved to the previous build after four starts with no run lasting five minutes
//	restarting  not running, it started or stopped within the last minute, and
//	            fewer than three crashes in the last ten minutes
//	down        not running, and nothing has happened for a minute, or three
//	            crashes in ten minutes (a crash loop with no previous build)
//	unlocked    running, with no locked memory, on swap that can reach a disk
//	running     running on the current build with its memory locked, or
//	            unlocked on swap that never reaches a disk (a site container,
//	            which cannot raise its memory-lock limit: the daemon serves
//	            there only while that holds, and exits when it stops)

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Test seams: a directory standing in for /, and for /proc.
var (
	unsealFSRoot   = ""
	unsealProcRoot = "/proc"
	unsealNow      = time.Now
)

// unsealKey is the installer's key for a site root: the basename, every byte
// outside A-Za-z0-9._- made '_', at most 64 bytes.
func unsealKey(siteRoot string) string {
	base := []byte(filepath.Base(strings.TrimRight(siteRoot, "/")))
	for i, c := range base {
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
			base[i] = '_'
		}
	}
	if len(base) > 64 {
		base = base[:64]
	}
	return string(base)
}

// unsealDaemonFacts returns the state word and the crashes in the last hour.
func unsealDaemonFacts(env *ExecEnv) (string, int) {
	if env == nil || env.SiteRoot == "" {
		return "", 0
	}
	key := unsealKey(env.SiteRoot)
	conf, err := os.ReadFile(unsealFSRoot + "/etc/joinery-unseal/" + key + "/installed")
	if err != nil {
		return "absent", 0
	}
	socket := ""
	for _, line := range strings.Split(string(conf), "\n") {
		if v, ok := strings.CutPrefix(line, "socket="); ok {
			socket = v
		}
	}
	if socket != "/run/joinery-unseal/"+key+"/unseal.sock" {
		return "absent", 0
	}
	state := unsealFSRoot + "/var/lib/joinery-unseal/" + key
	now := unsealNow().Unix()
	crashes, recent, lastEvent := 0, 0, int64(0)
	if f, err := os.Open(state + "/events"); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			var e struct {
				Time  int64  `json:"time"`
				Event string `json:"event"`
			}
			if json.Unmarshal(sc.Bytes(), &e) != nil {
				continue
			}
			if e.Time > lastEvent {
				lastEvent = e.Time
			}
			if e.Event == "crash" && e.Time >= now-3600 {
				crashes++
				if e.Time >= now-600 {
					recent++
				}
			}
		}
		f.Close()
	}
	if _, err := os.Stat(unsealFSRoot + "/run/joinery-unseal/" + key + ".hold"); err == nil {
		return "held", crashes
	}
	if _, err := os.Stat(state + "/swap_refused"); err == nil {
		return "swap_refused", crashes
	}
	if b, _ := os.ReadFile(state + "/binary"); strings.TrimSpace(string(b)) == "previous" {
		return "previous", crashes
	}
	pid := unsealDaemonPid(socket, "/var/lib/joinery-unseal/"+key+"/active")
	if pid == "" {
		if lastEvent >= now-60 && recent < 3 {
			return "restarting", crashes
		}
		return "down", crashes
	}
	if unsealVmLckKB(pid) <= 0 {
		if unsealSwapRAMOnly(unsealProcRoot+"/swaps", unsealFSRoot+"/sys/block") {
			return "running", crashes
		}
		return "unlocked", crashes
	}
	return "running", crashes
}

// unsealDaemonPid finds the process whose command line names --socket SOCKET.
// unsealDaemonPid finds the daemon by its command line: started as program
// (its state folder's active link, under systemd and the container keepalive
// alike) with --socket socket. In a container runuser stays alive as its
// parent with the same arguments; matching the program name is what keeps
// that parent, whose memory is never locked, from being read as the daemon.
func unsealDaemonPid(socket, program string) string {
	want := []byte("--socket\x00" + socket + "\x00")
	prog := []byte(program + "\x00")
	entries, _ := os.ReadDir(unsealProcRoot)
	for _, e := range entries {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		cmd, err := os.ReadFile(filepath.Join(unsealProcRoot, e.Name(), "cmdline"))
		if err != nil {
			continue
		}
		cmd = append(cmd, 0)
		if bytes.HasPrefix(cmd, prog) && bytes.Contains(cmd, want) {
			return e.Name()
		}
	}
	return ""
}

func unsealVmLckKB(pid string) int64 {
	b, err := os.ReadFile(filepath.Join(unsealProcRoot, pid, "status"))
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, "VmLck:"); ok {
			n, _ := strconv.ParseInt(strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(v), "kB")), 10, 64)
			return n
		}
	}
	return 0
}

// UnsealDaemonReport is the poll's word: "" on a machine with no site.
func UnsealDaemonReport(env *ExecEnv) string {
	word, _ := unsealDaemonFacts(env)
	return word
}

// unsealSwapRAMOnly is the daemon's own rule (joinery_unseal/swap_linux.go,
// VaultHealth::checkSwapSafe): every active swap device is a block device the
// kernel lists (Type partition) that sysfs has, and is zram with no backing
// device or dm-crypt; no swap at all counts. Anything else (a swap file, a
// name sysfs does not know, anything unreadable) can reach a disk. In a
// container /proc/swaps names the host's devices, which /dev there does not
// have, so a device is found in sysfs by name, and a device-mapper one by its
// dm/name. swap_rule_cases_test.json is the platform's corpus for this
// rule, kept byte-identical to joinery_unseal/testdata/swap_rule_cases.json
// (the platform's vault_health test compares them).
func unsealSwapRAMOnly(procSwaps, sysBlock string) bool {
	body, err := os.ReadFile(procSwaps)
	if err != nil {
		return false
	}
	isDir := func(p string) bool {
		st, err := os.Stat(p)
		return err == nil && st.IsDir()
	}
	lines := strings.Split(strings.TrimSpace(string(body)), "\n")
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		path := strings.ReplaceAll(fields[0], `\040`, " ")
		if len(fields) < 2 || fields[1] != "partition" {
			return false
		}
		name := filepath.Base(path)
		if real, err := filepath.EvalSymlinks(path); err == nil {
			name = filepath.Base(real)
		}
		if !isDir(filepath.Join(sysBlock, name)) {
			mapped := ""
			dirs, _ := filepath.Glob(filepath.Join(sysBlock, "dm-*"))
			for _, dir := range dirs {
				if b, err := os.ReadFile(filepath.Join(dir, "dm", "name")); err == nil && strings.TrimSpace(string(b)) == filepath.Base(path) {
					mapped = filepath.Base(dir)
				}
			}
			if mapped == "" {
				return false
			}
			name = mapped
		}
		switch {
		case strings.HasPrefix(name, "zram"):
			backing, err := os.ReadFile(filepath.Join(sysBlock, name, "backing_dev"))
			if err != nil {
				if os.IsNotExist(err) {
					continue // in sysfs, on a kernel without zram writeback
				}
				return false
			}
			if b := strings.TrimSpace(string(backing)); b != "" && b != "none" {
				return false
			}
		case strings.HasPrefix(name, "dm-"):
			uuid, err := os.ReadFile(filepath.Join(sysBlock, name, "dm", "uuid"))
			if err != nil || !strings.HasPrefix(strings.TrimSpace(string(uuid)), "CRYPT-") {
				return false
			}
		default:
			return false
		}
	}
	return true
}
