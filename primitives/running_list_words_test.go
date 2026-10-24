package primitives

import (
	"context"
	"database/sql/driver"
	"strings"
	"testing"
	"time"
)

// The four words of specs/agent_recipes_and_vocabulary.md's running list
// (listening_sockets, reboot_machine, spam_learning_status,
// container_inventory) and check_status's
// plugin list. Each review rests on the same things: the word cannot be
// pointed anywhere, it runs the one script it names, and its class is the one
// the review argued for.

func TestRunningListWordsAskForNothing(t *testing.T) {
	for _, name := range []string{"listening_sockets", "reboot_machine", "spam_learning_status", "container_inventory"} {
		p, ok := Lookup(name)
		if !ok {
			t.Fatalf("%s should be registered", name)
		}
		if len(p.Params) != 0 {
			t.Errorf("%s declares %d parameter(s); it must declare none", name, len(p.Params))
		}
		for _, key := range []string{"port", "address", "delay", "seconds", "kernel", "mailbox", "user", "days", "path"} {
			if _, err := Validate(p.Params, map[string]interface{}{key: "anything"}); err == nil {
				t.Errorf("%s: a job carrying %q must be refused", name, key)
			}
		}
		if _, err := Validate(p.Params, nil); err != nil {
			t.Errorf("%s: a job with no parameters is the only well-formed one: %v", name, err)
		}
		if p.Script == nil || p.Run != nil {
			t.Fatalf("%s is a script word and nothing else", name)
		}
		if len(p.Script.Args) != 0 || p.Script.ArgsFrom != nil || p.Script.StdinFrom != nil {
			t.Errorf("%s: argv and stdin must be empty", name)
		}
		if p.RequiresLogAccess {
			t.Errorf("%s reads no log and no content; it must not sit behind the owner's log switch", name)
		}
		if p.Timeout <= 0 || p.Timeout > 5*time.Minute {
			t.Errorf("%s: a timeout of %v is not a bounded read", name, p.Timeout)
		}
	}
}

func TestRunningListWordsRunTheirOwnScripts(t *testing.T) {
	for name, want := range map[string]struct {
		script      string
		interpreter string
		class       Class
		machine     bool
	}{
		"listening_sockets":    {listeningSocketsScript, "/bin/bash", ClassObserve, true},
		"container_inventory":  {containerInventoryScript, "/bin/bash", ClassObserve, true},
		"reboot_machine":       {rebootMachineScript, "/bin/bash", ClassOperate, true},
		"spam_learning_status": {spamLearningStatusScript, "/usr/bin/php", ClassObserve, false},
	} {
		p, _ := Lookup(name)
		if p.Script.ScriptPath != want.script || p.Script.Interpreter != want.interpreter {
			t.Errorf("%s runs %s %s, want %s %s", name, p.Script.Interpreter, p.Script.ScriptPath, want.interpreter, want.script)
		}
		if p.Class != want.class {
			t.Errorf("%s is %q, want %q", name, p.Class, want.class)
		}
		// The two machine words are asked of a siteless host too; the spam
		// counts are a site's, and a host with no site never reports the word.
		if p.Machine != want.machine {
			t.Errorf("%s Machine=%v, want %v", name, p.Machine, want.machine)
		}
		if !strings.HasPrefix(want.script, "maintenance_scripts/sysadmin_tools/") {
			t.Errorf("%s: a word's script lives in the signed sysadmin_tools", name)
		}
	}
}

// The reboot is an operate word, never observe: a node that accepts only
// observe words must refuse it.
func TestRebootIsNeverAnObserveWord(t *testing.T) {
	p, _ := Lookup("reboot_machine")
	if p.Class == ClassObserve {
		t.Fatal("reboot_machine changes running state; it cannot be an observe word")
	}
	if p.Class == ClassDestructive {
		t.Fatal("reboot_machine loses no data (rule 9); destructive would put an owner's key in front of every reboot")
	}
}

// check_status carries the site's plugins from plg_plugins: name, the
// version its recorded plugin.json gives, switched on or not, and its status.
func TestCollectPluginsReadsTheRegistry(t *testing.T) {
	cols := []string{"plg_name", "plg_active", "plg_status", "plg_metadata"}
	provider := fakeDB(map[string]fakeRows{
		"FROM plg_plugins": {columns: cols, rows: [][]driver.Value{
			{"mailbox", int64(1), "active", `{"name":"Mailbox","version":"1.143.0","depends":{"store":">=1.0.0"}}`},
			{"bookings", int64(0), "inactive", `{"version":"1.3.1"}`},
			{"odd<name>", nil, nil, `{"version":"1.0\"; rm -rf /"}`},
			{"broken", int64(1), "error", `{not json`},
		}},
	}, nil)
	db, err := provider()
	if err != nil {
		t.Fatal(err)
	}
	got, ok := collectPlugins(context.Background(), db)
	if !ok {
		t.Fatal("a readable registry must be reported")
	}
	if len(got) != 4 {
		t.Fatalf("want 4 plugins, got %d: %v", len(got), got)
	}
	if got[0]["name"] != "mailbox" || got[0]["version"] != "1.143.0" || got[0]["active"] != true || got[0]["status"] != "active" {
		t.Errorf("mailbox read wrong: %v", got[0])
	}
	if got[1]["active"] != false {
		t.Errorf("plg_active 0 is switched off: %v", got[1])
	}
	if got[2]["name"] != "oddname" || got[2]["active"] != false || got[2]["version"] != "1.0rm-rf" {
		t.Errorf("names and versions must be reduced to a safe set: %v", got[2])
	}
	if got[3]["version"] != "" {
		t.Errorf("metadata that is not JSON gives no version, not a guess: %v", got[3])
	}

	failing := fakeDB(nil, errFakeDown)
	db2, _ := failing()
	if _, ok := collectPlugins(context.Background(), db2); ok {
		t.Error("a registry that cannot be read is not measured, never a site with no plugins")
	}
}

var errFakeDown = &fakeDownError{}

type fakeDownError struct{}

func (*fakeDownError) Error() string { return "database not accepting connections" }

// The two words of specs/slow_request_diagnosis_words.md: net_health takes
// nothing at all; web_workers takes nothing from the wire and passes only the
// site's own domain, from its config, when it is a host name.
func TestSlowRequestWordsAskForNothing(t *testing.T) {
	for name, script := range map[string]string{"net_health": netHealthScript, "web_workers": webWorkersScript} {
		p, ok := Lookup(name)
		if !ok {
			t.Fatalf("%s should be registered", name)
		}
		if len(p.Params) != 0 {
			t.Errorf("%s declares %d parameter(s); it must declare none", name, len(p.Params))
		}
		for _, key := range []string{"port", "address", "domain", "url", "path", "pool"} {
			if _, err := Validate(p.Params, map[string]interface{}{key: "anything"}); err == nil {
				t.Errorf("%s: a job carrying %q must be refused", name, key)
			}
		}
		if p.Script == nil || p.Run != nil || p.Script.ScriptPath != script || p.Script.Interpreter != "/bin/bash" {
			t.Fatalf("%s runs the one script it names", name)
		}
		if p.Class != ClassObserve || !p.Machine || p.RequiresLogAccess {
			t.Errorf("%s: observe, a machine word, and behind no switch", name)
		}
		if len(p.Script.Args) != 0 || p.Script.StdinFrom != nil {
			t.Errorf("%s: no fixed argv and no stdin", name)
		}
		if p.Timeout <= 0 || p.Timeout > 2*time.Minute {
			t.Errorf("%s: a timeout of %v is not a bounded read", name, p.Timeout)
		}
	}
	if p, _ := Lookup("net_health"); p.Script.ArgsFrom != nil {
		t.Errorf("net_health takes no argument at all")
	}
}

func TestWebWorkersPassesOnlyTheSitesOwnHostName(t *testing.T) {
	ctx := context.Background()
	for domain, want := range map[string][]string{
		"jeremytunnell.com":        {"jeremytunnell.com"},
		"":                         {},
		"evil.com/../etc":          {},
		"a b":                      {},
		"-leading.example":         {},
		"x.example --resolve evil": {},
	} {
		got, err := webWorkersArgs(ctx, &ExecEnv{SiteDomain: domain}, Params{})
		if err != nil || strings.Join(got, "|") != strings.Join(want, "|") {
			t.Errorf("SiteDomain %q gave %q (%v), want %q", domain, got, err, want)
		}
	}
	if got, _ := webWorkersArgs(ctx, nil, Params{}); len(got) != 0 {
		t.Errorf("no environment, no argument; got %q", got)
	}
}
