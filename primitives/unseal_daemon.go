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
//	previous    the launcher moved to the previous build after four starts with no run lasting five minutes
//	restarting  not running, it started or stopped within the last minute, and
//	            fewer than three crashes in the last ten minutes
//	down        not running, and nothing has happened for a minute, or three
//	            crashes in ten minutes (a crash loop with no previous build)
//	unlocked    running, with no locked memory
//	running     running on the current build with its memory locked

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
	if b, _ := os.ReadFile(state + "/binary"); strings.TrimSpace(string(b)) == "previous" {
		return "previous", crashes
	}
	pid := unsealDaemonPid(socket)
	if pid == "" {
		if lastEvent >= now-60 && recent < 3 {
			return "restarting", crashes
		}
		return "down", crashes
	}
	if unsealVmLckKB(pid) <= 0 {
		return "unlocked", crashes
	}
	return "running", crashes
}

// unsealDaemonPid finds the process whose command line names --socket SOCKET.
func unsealDaemonPid(socket string) string {
	want := []byte("--socket\x00" + socket + "\x00")
	entries, _ := os.ReadDir(unsealProcRoot)
	for _, e := range entries {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		cmd, err := os.ReadFile(filepath.Join(unsealProcRoot, e.Name(), "cmdline"))
		if err == nil && bytes.Contains(append(cmd, 0), want) {
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
