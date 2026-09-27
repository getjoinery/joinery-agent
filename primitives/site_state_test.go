package primitives

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// The quiet state (specs/site_copy.md WP5): while a site is quiet the agent
// runs every observe word and, of the rest, only a word that declares the
// reason. site_quiet off never lets a copy go live until this machine holds
// its source's node id.

func quietFixture(t *testing.T, state, copyOf string) *ExecEnv {
	t.Helper()
	dir := t.TempDir()
	old := SiteStateDir
	SiteStateDir = dir
	t.Cleanup(func() { SiteStateDir = old })
	if state != "" {
		site := filepath.Join(dir, "qsite")
		if err := os.MkdirAll(site, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(site, "state"), []byte(state+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if copyOf != "" {
			if err := os.WriteFile(filepath.Join(site, "copy_of"), []byte(copyOf+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	return &ExecEnv{SiteRoot: "/var/www/html/qsite"}
}

func mustLookup(t *testing.T, name string) Primitive {
	t.Helper()
	p, ok := Lookup(name)
	if !ok {
		t.Fatalf("%s should be registered", name)
	}
	return p
}

func TestAQuietSiteRunsOnlyWhatItsReasonAllows(t *testing.T) {
	cases := []struct {
		state string
		word  string
		ok    bool
	}{
		{"", "run_installer", true},
		{"", "backup_run", true},
		{"quiet switchover", "check_status", true},
		{"quiet switchover", "site_quiet", true},
		{"quiet switchover", "backup_run", true},
		{"quiet switchover", "run_installer", false},
		{"quiet switchover", "apply_update", false},
		{"quiet switchover", "restore_chain", false},
		{"quiet copy", "check_status", true},
		{"quiet copy", "site_quiet", true},
		{"quiet copy", "backup_run", false},
		{"quiet copy", "run_installer", false},
		{"quiet copy", "restore_chain", false},
		// Anything else in the file is quiet, the strict way.
		{"garbage", "backup_run", true},
		{"garbage", "run_installer", false},
	}
	for _, c := range cases {
		env := quietFixture(t, c.state, "")
		err := quietAllows(env, mustLookup(t, c.word))
		if c.ok && err != nil {
			t.Errorf("state %q: %s should run, got %v", c.state, c.word, err)
		}
		if !c.ok && (err == nil || !Refused(err)) {
			t.Errorf("state %q: %s should be refused, got %v", c.state, c.word, err)
		}
	}
}

func TestTheDispatcherRefusesAQuietSitesWordBeforeItsParameters(t *testing.T) {
	env := quietFixture(t, "quiet copy", "")
	policy := &Policy{Accept: []Class{ClassObserve, ClassOperate}, source: "the test policy"}
	_, err := Execute(context.Background(), env, policy, Request{JobID: 1, Primitive: "run_installer",
		Params: map[string]interface{}{"name": "not an installer"}})
	if err == nil || !Refused(err) || !strings.Contains(err.Error(), "dormant copy") {
		t.Fatalf("a copy must refuse run_installer, and say why rather than naming a parameter: %v", err)
	}
}

func TestADamagedStateLineNeverUnmakesACopy(t *testing.T) {
	env := quietFixture(t, "garbage", "417")
	st, err := ReadSiteState(env)
	if err != nil || st.Reason != "copy" || st.CopyOf != 417 {
		t.Fatalf("a copy_of record means a copy whatever the line says: %+v %v", st, err)
	}
	env.NodeID = func() (int64, error) { return 512, nil }
	if _, err := siteQuietArgs(t, env, "off"); err == nil || !Refused(err) {
		t.Fatalf("off must still need the node id: %v", err)
	}
}

func TestNoMachineWithoutASiteIsQuiet(t *testing.T) {
	quietFixture(t, "quiet copy", "")
	if err := quietAllows(&ExecEnv{}, mustLookup(t, "run_installer")); err != nil {
		t.Fatalf("a machine with no site has no state to be quiet in: %v", err)
	}
}

func TestSiteQuietShape(t *testing.T) {
	p := mustLookup(t, "site_quiet")
	if p.Class != ClassOperate || p.Script == nil || p.Script.ScriptPath != siteQuietScript || p.Script.Interpreter != "/bin/bash" {
		t.Fatalf("site_quiet is an operate script word running %s", siteQuietScript)
	}
	if p.Quiet != QuietAny {
		t.Error("site_quiet must run under both reasons: it is how either one ends")
	}
	if p.Machine {
		t.Error("a machine with no site has nothing to quiet")
	}
	for _, bad := range []map[string]interface{}{{}, {"action": "copy"}, {"action": "on", "reason": "copy"}, {"action": "status"}} {
		if _, err := Validate(p.Params, bad); err == nil {
			t.Errorf("%v must be refused", bad)
		}
	}
}

func siteQuietArgs(t *testing.T, env *ExecEnv, action string) ([]string, error) {
	t.Helper()
	params, err := Validate(mustLookup(t, "site_quiet").Params, map[string]interface{}{"action": action})
	if err != nil {
		t.Fatal(err)
	}
	return siteQuietArgv(context.Background(), env, params)
}

func TestSiteQuietOnOnlyEverAsksForASwitchover(t *testing.T) {
	for _, state := range []string{"", "quiet switchover", "quiet copy"} {
		got, err := siteQuietArgs(t, quietFixture(t, state, "417"), "on")
		if err != nil || !reflect.DeepEqual(got, []string{"on"}) {
			t.Errorf("state %q: on is always the bare word (the script refuses over a copy): %v %v", state, got, err)
		}
	}
}

func TestSiteQuietOffNeverLetsACopyGoLiveBesideItsSource(t *testing.T) {
	nodeID := func(n int64, err error) func() (int64, error) {
		return func() (int64, error) { return n, err }
	}

	env := quietFixture(t, "quiet switchover", "")
	if got, err := siteQuietArgs(t, env, "off"); err != nil || !reflect.DeepEqual(got, []string{"off"}) {
		t.Errorf("a switch-over clears with a bare off: %v %v", got, err)
	}

	env = quietFixture(t, "quiet copy", "417")
	env.NodeID = nodeID(512, nil)
	if _, err := siteQuietArgs(t, env, "off"); err == nil || !Refused(err) || !strings.Contains(err.Error(), "copy of node 417") {
		t.Errorf("a copy still on its own node id must stay quiet: %v", err)
	}
	env.NodeID = nodeID(417, nil)
	if got, err := siteQuietArgs(t, env, "off"); err != nil || !reflect.DeepEqual(got, []string{"off", "--copy-promoted"}) {
		t.Errorf("a copy holding its source's node id clears: %v %v", got, err)
	}
	env.NodeID = nodeID(0, errors.New("identity unreadable"))
	if _, err := siteQuietArgs(t, env, "off"); err == nil || !Refused(err) {
		t.Errorf("an unreadable identity keeps a copy quiet: %v", err)
	}
	env.NodeID = nil
	if _, err := siteQuietArgs(t, env, "off"); err == nil || !Refused(err) {
		t.Errorf("no way to read the node id keeps a copy quiet: %v", err)
	}

	env = quietFixture(t, "quiet copy", "")
	env.NodeID = nodeID(0, nil)
	if _, err := siteQuietArgs(t, env, "off"); err == nil || !Refused(err) {
		t.Errorf("a copy with no record of its source can never prove it took over: %v", err)
	}
}

func TestAnObserveWordCannotDeclareAQuietReason(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("Register must refuse an observe word that declares Quiet")
		}
	}()
	Register(Primitive{Name: "zz_quiet_observe", Class: ClassObserve, Quiet: QuietCopy,
		Run: func(context.Context, *ExecEnv, Params) (map[string]interface{}, error) { return nil, nil }})
}
