package primitives

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestUnsealKeyMatchesTheInstaller(t *testing.T) {
	for in, want := range map[string]string{
		"/var/www/html/joinerytest":      "joinerytest",
		"/var/www/html/my site.example/": "my_site.example",
		"/srv/a/b":                       "b",
	} {
		if got := unsealKey(in); got != want {
			t.Fatalf("unsealKey(%q) = %q, want %q", in, got, want)
		}
	}
	long := "/x/" + fmt.Sprintf("%070d", 0)
	if got := unsealKey(long); len(got) != 64 {
		t.Fatalf("a long name is cut to 64, got %d", len(got))
	}
}

func TestUnsealDaemonReport(t *testing.T) {
	root, proc := t.TempDir(), t.TempDir()
	unsealFSRoot, unsealProcRoot = root, proc
	now := time.Unix(1800000000, 0)
	unsealNow = func() time.Time { return now }
	defer func() { unsealFSRoot, unsealProcRoot, unsealNow = "", "/proc", time.Now }()
	env := &ExecEnv{SiteRoot: "/var/www/html/site1"}
	write := func(p, body string) {
		os.MkdirAll(filepath.Dir(root+p), 0o755)
		os.WriteFile(root+p, []byte(body), 0o644)
	}
	want := func(state string) {
		t.Helper()
		if got := UnsealDaemonReport(env); got != state {
			t.Fatalf("want %s, got %s", state, got)
		}
	}
	if UnsealDaemonReport(&ExecEnv{}) != "" {
		t.Fatal("a machine with no site reports nothing")
	}
	want("absent")
	write("/etc/joinery-unseal/site1/installed", "socket=/tmp/elsewhere.sock\nallow_uid=33\n")
	want("absent") // a record naming a socket outside its directory is not one
	write("/etc/joinery-unseal/site1/installed", "socket=/run/joinery-unseal/site1/unseal.sock\nallow_uid=33\n")
	write("/var/lib/joinery-unseal/site1/events", fmt.Sprintf(
		`{"time":%d,"event":"crash"}`+"\n"+`{"time":%d,"event":"start"}`+"\n", now.Unix()-30, now.Unix()-20))
	want("restarting")
	now = now.Add(2 * time.Minute)
	want("down")
	// A crash loop keeps an event inside every minute; three crashes in ten
	// minutes are down, not restarting.
	loop := ""
	for i := 0; i < 3; i++ {
		loop += fmt.Sprintf(`{"time":%d,"event":"start"}`+"\n"+`{"time":%d,"event":"crash"}`+"\n", now.Unix()-int64(20*i)-5, now.Unix()-int64(20*i))
	}
	write("/var/lib/joinery-unseal/site1/events", loop)
	want("down")
	write("/var/lib/joinery-unseal/site1/events", fmt.Sprintf(`{"time":%d,"event":"crash"}`+"\n", now.Unix()-10))
	os.MkdirAll(proc+"/4242", 0o755)
	os.WriteFile(proc+"/4242/cmdline", []byte("/var/lib/joinery-unseal/site1/active\x00--socket\x00/run/joinery-unseal/site1/unseal.sock\x00--allow-uid\x0033\x00"), 0o644)
	os.WriteFile(proc+"/4242/status", []byte("Name:\tactive\nVmLck:\t       0 kB\n"), 0o644)
	want("unlocked") // no /proc/swaps to read: it can reach a disk
	header := "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n"
	os.WriteFile(proc+"/swaps", []byte(header+"/dev/zram9  partition 2004476 0 100\n"), 0o644)
	write("/sys/block/zram9/backing_dev", "none\n")
	want("running") // a site container's daemon on the host's zram: unlocked by design
	write("/sys/block/zram9/backing_dev", "/dev/sdb\n")
	want("unlocked") // zram writing back to a disk is a disk
	write("/sys/block/zram9/backing_dev", "none\n")
	os.WriteFile(proc+"/swaps", []byte(header+"/dev/zram9  partition 2004476 0 100\n/swapfile  file 1048572 0 -2\n"), 0o644)
	want("unlocked") // a swap file beside it
	os.Remove(proc + "/swaps")
	// The launcher not starting it while swap can reach a disk: its own word,
	// never a bad build, whatever else the state directory says.
	write("/var/lib/joinery-unseal/site1/swap_refused", "swap /swapfile is a file, not a block device\n")
	write("/var/lib/joinery-unseal/site1/binary", "previous\n")
	want("swap_refused")
	os.Remove(root + "/var/lib/joinery-unseal/site1/swap_refused")
	os.Remove(root + "/var/lib/joinery-unseal/site1/binary")
	os.WriteFile(proc+"/4242/status", []byte("Name:\tactive\nVmLck:\t    4096 kB\n"), 0o644)
	want("running")
	// A container's keepalive leaves runuser alive as the daemon's parent, with
	// the same arguments and a lower pid; its memory is never locked, and it is
	// not the daemon.
	os.MkdirAll(proc+"/4241", 0o755)
	os.WriteFile(proc+"/4241/cmdline", []byte("runuser\x00-u\x00joinery-unseal\x00--\x00/var/lib/joinery-unseal/site1/active\x00--socket\x00/run/joinery-unseal/site1/unseal.sock\x00--allow-uid\x0033\x00"), 0o644)
	os.WriteFile(proc+"/4241/status", []byte("Name:\trunuser\nVmLck:\t       0 kB\n"), 0o644)
	want("running")
	if _, crashes := unsealDaemonFacts(env); crashes != 1 {
		t.Fatalf("crashes in the last hour: %d", crashes)
	}
	write("/var/lib/joinery-unseal/site1/binary", "previous\n")
	want("previous")
	write("/run/joinery-unseal/site1.hold", "")
	want("held")
}

// The platform's corpus for the swap rule (swap_rule_cases_test.json, a byte-identical copy of
// joinery_unseal/testdata/swap_rule_cases.json): this copy of the rule gives
// every case the daemon's verdict.
func TestUnsealSwapRuleCorpus(t *testing.T) {
	body, err := os.ReadFile("swap_rule_cases_test.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Cases []struct {
			Name      string            `json:"name"`
			Swaps     [][2]string       `json:"swaps"`
			Block     map[string]string `json:"block"`
			BlockDirs []string          `json:"block_dirs"`
			Files     []string          `json:"files"`
			RAMOnly   bool              `json:"ram_only"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(body, &corpus); err != nil || len(corpus.Cases) < 10 {
		t.Fatalf("corpus: %v, %d cases", err, len(corpus.Cases))
	}
	for _, c := range corpus.Cases {
		dir := t.TempDir()
		at := func(s string) string { return strings.ReplaceAll(s, "@DIR@", dir) }
		sysBlock := filepath.Join(dir, "block")
		os.MkdirAll(sysBlock, 0o755)
		for rel, b := range c.Block {
			p := filepath.Join(sysBlock, rel)
			os.MkdirAll(filepath.Dir(p), 0o755)
			os.WriteFile(p, []byte(b), 0o644)
		}
		for _, d := range c.BlockDirs {
			os.MkdirAll(filepath.Join(sysBlock, d), 0o755)
		}
		for _, f := range c.Files {
			os.MkdirAll(filepath.Dir(at(f)), 0o755)
			os.WriteFile(at(f), nil, 0o644)
		}
		swaps := "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n"
		for _, row := range c.Swaps {
			swaps += at(row[0]) + "                              " + row[1] + "\t2097148\t\t0\t\t-2\n"
		}
		os.WriteFile(filepath.Join(dir, "swaps"), []byte(swaps), 0o644)
		if got := unsealSwapRAMOnly(filepath.Join(dir, "swaps"), sysBlock); got != c.RAMOnly {
			t.Errorf("%s: got ram_only=%v, want %v", c.Name, got, c.RAMOnly)
		}
	}
}
