package primitives

import (
	"fmt"
	"os"
	"path/filepath"
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
	want("unlocked")
	os.WriteFile(proc+"/4242/status", []byte("Name:\tactive\nVmLck:\t    4096 kB\n"), 0o644)
	want("running")
	if _, crashes := unsealDaemonFacts(env); crashes != 1 {
		t.Fatalf("crashes in the last hour: %d", crashes)
	}
	write("/var/lib/joinery-unseal/site1/binary", "previous\n")
	want("previous")
	write("/run/joinery-unseal/site1.hold", "")
	want("held")
}
