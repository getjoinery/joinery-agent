package primitives

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// Whose switch decides a log word: this machine's own site; nobody, for a
// machine word on a machine with no site; and the named container site's own
// switch for a word that reads one co-resident site (log_access.go).

func TestMachineLogWordOnASitelessMachineNeedsNoSwitch(t *testing.T) {
	t.Setenv("AGENT_STATE_DIR", t.TempDir()) // no marker: this machine's own switch reads OFF
	host := &ExecEnv{Siteless: true}
	if err := requireLogAccessFor(context.Background(), host, Primitive{Name: "unit_journal", Machine: true}); err != nil {
		t.Fatalf("a machine word on a machine with no site reads only the host, and must run: %v", err)
	}
	if !ReportedLogAccess(context.Background(), host) {
		t.Error("a machine with no site must report its machine log words as allowed")
	}
}

func TestSiteLogWordOnASitelessMachineStillAsksTheSwitch(t *testing.T) {
	t.Setenv("AGENT_STATE_DIR", t.TempDir())
	err := requireLogAccessFor(context.Background(), &ExecEnv{Siteless: true}, Primitive{Name: "site_log"})
	if err == nil || err.Error() != LogAccessRefusal {
		t.Fatalf("a site word is not let through by the machine having no site; got %v", err)
	}
}

func TestMachineLogWordOnASiteMachineAsksItsSwitch(t *testing.T) {
	t.Setenv("AGENT_STATE_DIR", t.TempDir())
	env := &ExecEnv{DB: fakeDB(settingAnswer("0"), nil)}
	err := requireLogAccessFor(context.Background(), env, Primitive{Name: "unit_journal", Machine: true})
	if err == nil || err.Error() != LogAccessRefusal {
		t.Fatalf("on a machine with a site its owner's switch decides; got %v", err)
	}
	if ReportedLogAccess(context.Background(), env) {
		t.Error("a site machine whose switch is off must report off")
	}
}

func TestSiteConvergerAsksTheNamedSitesOwnSwitch(t *testing.T) {
	t.Setenv("AGENT_STATE_DIR", t.TempDir())
	var asked []string
	answer := false
	var answerErr error
	env := &ExecEnv{Siteless: true, ToolManifest: UnavailableVerifier{},
		SiteLogAccess: func(ctx context.Context, site string) (bool, error) {
			asked = append(asked, site)
			return answer, answerErr
		}}
	run := func(params map[string]interface{}) error {
		_, err := Execute(context.Background(), env, openPolicy(),
			Request{JobID: 7, Primitive: "site_converger", Params: params})
		return err
	}

	// A bad name is refused by validation, and no site is asked anything.
	if err := run(map[string]interface{}{"site": "../sa"}); !Refused(err) {
		t.Fatalf("a bad site name must be refused, got %v", err)
	}
	if len(asked) != 0 {
		t.Fatalf("an invalid job must not ask any site; asked %v", asked)
	}

	// The site says no: refused with that site's reason, the host switch notwithstanding.
	err := run(map[string]interface{}{"site": "sa"})
	if !Refused(err) || !strings.Contains(err.Error(), "owner of the site sa has not allowed log access") {
		t.Fatalf("a site whose owner said no must refuse with its reason, got %v", err)
	}
	if len(asked) != 1 || asked[0] != "sa" {
		t.Fatalf("the named site, and only it, is asked; asked %v", asked)
	}

	// The site cannot answer: refused, saying so.
	answerErr = errors.New("connection refused")
	err = run(map[string]interface{}{"site": "sa"})
	if !Refused(err) || !strings.Contains(err.Error(), "could not say whether it allows log access") {
		t.Fatalf("a site that cannot answer reads OFF, got %v", err)
	}

	// The site says yes: past the gate. The script then cannot be vouched for
	// (UnavailableVerifier), which is a different refusal from the switch's.
	answer, answerErr = true, nil
	err = run(map[string]interface{}{"site": "sa"})
	if err != nil && strings.Contains(err.Error(), "allow") {
		t.Fatalf("a site that allows log access must get past the switch, got %v", err)
	}
}

func TestSiteConvergerRefusesWhenItCannotAskTheSite(t *testing.T) {
	t.Setenv("AGENT_STATE_DIR", t.TempDir())
	_, err := Execute(context.Background(), &ExecEnv{Siteless: true}, openPolicy(),
		Request{JobID: 8, Primitive: "site_converger", Params: map[string]interface{}{"site": "sa"}})
	if !Refused(err) || !strings.Contains(err.Error(), "cannot ask the site sa") {
		t.Fatalf("no way to ask the site must refuse, got %v", err)
	}
}

func TestLogAccessSiteMustBeAMachineLogWordsRequiredParam(t *testing.T) {
	cases := []Primitive{
		{Name: "bad_site_gate_a", Class: ClassObserve, Machine: true, LogAccessSite: "site",
			Params: []ParamSpec{{Name: "site", Type: ParamString, Required: true, MaxLen: 5}}},
		{Name: "bad_site_gate_b", Class: ClassObserve, RequiresLogAccess: true, LogAccessSite: "site",
			Params: []ParamSpec{{Name: "site", Type: ParamString, Required: true, MaxLen: 5}}},
		{Name: "bad_site_gate_c", Class: ClassObserve, Machine: true, RequiresLogAccess: true, LogAccessSite: "site",
			Params: []ParamSpec{{Name: "site", Type: ParamString, MaxLen: 5}}},
	}
	for _, p := range cases {
		p.Run = func(ctx context.Context, env *ExecEnv, params Params) (map[string]interface{}, error) {
			return nil, nil
		}
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: a misdeclared LogAccessSite must fail to register", p.Name)
				}
			}()
			Register(p)
		}()
		if _, ok := Lookup(p.Name); ok {
			t.Errorf("%s registered", p.Name)
		}
	}
}

// The site's database is the container's: the question goes out under the
// word's own deadline, so a database that never answers cannot hold the job
// lock for good.
func TestSiteLogAccessIsAskedUnderTheWordsDeadline(t *testing.T) {
	t.Setenv("AGENT_STATE_DIR", t.TempDir())
	hadDeadline := false
	env := &ExecEnv{Siteless: true, ToolManifest: UnavailableVerifier{},
		SiteLogAccess: func(ctx context.Context, site string) (bool, error) {
			_, hadDeadline = ctx.Deadline()
			return false, nil
		}}
	_, _ = Execute(context.Background(), env, openPolicy(),
		Request{JobID: 9, Primitive: "site_converger", Params: map[string]interface{}{"site": "sa"}})
	if !hadDeadline {
		t.Fatal("the site's switch must be asked under the word's deadline")
	}
}

// On a machine WITH a site whose own switch is off, site_converger still asks
// the named container site, and that site's answer decides.
func TestSiteConvergerIgnoresTheHostSwitchOnASiteMachine(t *testing.T) {
	t.Setenv("AGENT_STATE_DIR", t.TempDir())
	asked := 0
	env := &ExecEnv{SiteRoot: t.TempDir(), Manifest: UnavailableVerifier{},
		DB: fakeDB(settingAnswer("0"), nil),
		SiteLogAccess: func(ctx context.Context, site string) (bool, error) {
			asked++
			return true, nil
		}}
	_, err := Execute(context.Background(), env, openPolicy(),
		Request{JobID: 10, Primitive: "site_converger", Params: map[string]interface{}{"site": "sa"}})
	if asked != 1 {
		t.Fatalf("the named site must be asked once, whatever this machine's switch says; asked %d", asked)
	}
	if err != nil && err.Error() == LogAccessRefusal {
		t.Fatal("this machine's own switch must not refuse a word that reads another site")
	}
}

// On a machine with no site, the gateway's journal is the sites' members', not
// the host's: refused; any other unit runs.
func TestSitelessMachineRefusesTheMailGatewayJournal(t *testing.T) {
	t.Setenv("AGENT_STATE_DIR", t.TempDir())
	env := &ExecEnv{Siteless: true, ToolManifest: UnavailableVerifier{}}
	run := func(unit string) error {
		_, err := Execute(context.Background(), env, openPolicy(),
			Request{JobID: 11, Primitive: "unit_journal", Params: map[string]interface{}{"unit": unit}})
		return err
	}
	if err := run("joinery-mail-gateway"); !Refused(err) || !strings.Contains(err.Error(), "members of the sites it serves") {
		t.Fatalf("the gateway's journal must be refused on a machine with no site, got %v", err)
	}
	if err := run("cron"); err != nil && (strings.Contains(err.Error(), "log access") || strings.Contains(err.Error(), "members")) {
		t.Fatalf("a host unit must get past the log gate on a machine with no site, got %v", err)
	}
}
