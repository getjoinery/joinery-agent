package recipes

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"joinery-agent/primitives"
)

// pinnedRecipes is the complete recipe list this agent ships with, written out
// by hand: each recipe, the observe word it checks with and the operate word
// it repairs with. A pin in the same sense as primitives/gate_test.go: the
// point is not that the list is correct, it is that it cannot CHANGE without a
// human editing this file. A recipe that arrives without a line here fails
// the build's tests, so "the fleet quietly started repairing something" is
// not a thing that can happen between releases.
var pinnedRecipes = map[string][2]string{
	// The first recipe of specs/agent_tier1_recipes.md: fail2ban active with
	// at least one jail, or host_housekeeping.sh through the host runner.
	// Absent counts as failed (the installer installs it); a container's
	// "unknown" never repairs. Armed (see pinnedMode).
	"fail2ban": {"host_report", "host_converge"},
	// Recipe 2: something would restart this agent if it stopped, or
	// install_agent.sh through the host runner. Site-scoped: the bundle a
	// siteless machine runs from carries no install_agent.sh.
	"agent_supervision": {"agent_report", "agent_converge"},
}

// pinnedMode is the repair switch as this release ships it. Arming (or
// disarming) is a release: changing ReportOnly means changing this line too,
// in the same commit. Armed since 1.33.0, after the burn-in ledger was read
// and the case proof ran (specs/agent_tier1_recipes.md, "Burn-in" and
// build-order item 7).
const pinnedMode = ModeArmed

func TestRecipeListIsPinned(t *testing.T) {
	for _, name := range Names() {
		words, pinned := pinnedRecipes[name]
		if !pinned {
			t.Errorf("recipe %q is registered but not pinned in registry_test.go — add it here deliberately, or it does not ship", name)
			continue
		}
		r, _ := Lookup(name)
		if r.CheckWord != words[0] || r.RepairWord != words[1] {
			t.Errorf("recipe %q composes %s -> %s but is pinned as %s -> %s — a different word is a different sentence",
				name, r.CheckWord, r.RepairWord, words[0], words[1])
		}
	}
	for name := range pinnedRecipes {
		if _, ok := Lookup(name); !ok {
			t.Errorf("recipe %q is pinned but not registered — it was removed without updating the pin", name)
		}
	}
}

func TestTheRepairSwitchIsPinned(t *testing.T) {
	if Mode() != pinnedMode {
		t.Fatalf("this build's recipes are %s but the pin says %s — arming (or disarming) the loop is a deliberate edit to both", Mode(), pinnedMode)
	}
}

func TestARecipeHasNowhereToPutAParameter(t *testing.T) {
	// A recipe never has a parameter, and the way that is made true is that
	// the struct has no field one could live in: nothing named like one, and
	// nothing of the type the primitives registry declares them with.
	rt := reflect.TypeOf(Recipe{})
	paramSpec := reflect.TypeOf([]primitives.ParamSpec{})
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		lower := strings.ToLower(f.Name)
		for _, banned := range []string{"param", "arg", "option", "config", "setting"} {
			if strings.Contains(lower, banned) {
				t.Errorf("Recipe has a field %q — a recipe takes no parameters, and a field to hold one is how it would start to", f.Name)
			}
		}
		if f.Type == paramSpec {
			t.Errorf("Recipe field %q is a parameter spec list; recipes declare none", f.Name)
		}
		switch f.Type.Kind() {
		case reflect.Map, reflect.Slice:
			t.Errorf("Recipe field %q is a %s; a recipe is a name, two words and two functions, with nothing list-shaped to fill from outside", f.Name, f.Type.Kind())
		}
	}
}

func TestEveryRecipeComposesAParameterlessObserveAndOperateWord(t *testing.T) {
	// Register enforces this; the test says it out loud for the shipped list.
	for _, r := range All() {
		check, ok := primitives.Lookup(r.CheckWord)
		if !ok || check.Class != primitives.ClassObserve || len(check.Params) != 0 {
			t.Errorf("recipe %q: check word %q must be a parameterless observe word", r.Name, r.CheckWord)
		}
		repair, ok := primitives.Lookup(r.RepairWord)
		if !ok || repair.Class != primitives.ClassOperate || len(repair.Params) != 0 {
			t.Errorf("recipe %q: repair word %q must be a parameterless operate word", r.Name, r.RepairWord)
		}
		if r.MinInterval < TickInterval {
			t.Errorf("recipe %q checks every %v, more often than the %v tick", r.Name, r.MinInterval, TickInterval)
		}
	}
}

func TestRegisterRefusesWhatTheContractForbids(t *testing.T) {
	good := func() Recipe {
		return Recipe{
			Name: "refused_probe", MinInterval: TickInterval,
			CheckWord: "host_report", RepairWord: "host_converge",
			Check:  func(context.Context, *Env) Verdict { return Verdict{Pass, ""} },
			Repair: func(context.Context, *Env) (string, error) { return "", nil },
		}
	}
	cases := map[string]func(*Recipe){
		"a check shorter than the tick":       func(r *Recipe) { r.MinInterval = TickInterval - time.Second },
		"a name that reads as a path":         func(r *Recipe) { r.Name = "../hold" },
		"a check word that changes the host":  func(r *Recipe) { r.CheckWord = "host_converge" },
		"a repair word that only reads":       func(r *Recipe) { r.RepairWord = "host_report" },
		"a repair word that is destructive":   func(r *Recipe) { r.RepairWord = "restore_database" },
		"a word this agent does not have":     func(r *Recipe) { r.RepairWord = "run_anything" },
		"a repair word that takes parameters": func(r *Recipe) { r.RepairWord = "download_backup" },
		"no check":                            func(r *Recipe) { r.Check = nil },
		"no repair":                           func(r *Recipe) { r.Repair = nil },
	}
	for label, mutate := range cases {
		r := good()
		mutate(&r)
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("Register accepted %s", label)
				}
				delete(registry, r.Name)
			}()
			Register(r)
		}()
	}
}

func TestTheReportNamesEveryRecipeWithItsMode(t *testing.T) {
	ResetVerdictsForTests()
	report := Report()
	for _, r := range All() {
		if !strings.Contains(","+report+",", ","+r.Name+":"+ModeOf(r)+",") {
			t.Errorf("the claim's recipe list %q does not carry %s with mode %s (no verdict before the first check)", report, r.Name, ModeOf(r))
		}
	}
	// Every character must survive the plane's field pattern, or the claim is
	// refused wholesale and the node drops its extras.
	for _, r := range report {
		if !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && r != '_' && r != ',' && r != ':' && r != '-' {
			t.Errorf("the recipe report %q carries %q, which the wire format does not allow", report, r)
		}
	}
}

// The plane could not tell a recipe failing every tick from a healthy one
// while the claim carried only the mode (the case proof of 2026-09-16: three
// hours of fail on the docker-prod host, "fail2ban:report-only" throughout).
// Once the check has run, the claim says what it said.
func TestTheReportCarriesTheLastVerdictOnceThereIsOne(t *testing.T) {
	ResetVerdictsForTests()
	defer ResetVerdictsForTests()
	r, ok := Lookup("fail2ban")
	if !ok {
		t.Skip("no fail2ban recipe registered")
	}
	if !Applicable(r) {
		t.Skip("fail2ban does not apply in this environment; the not-applicable path is scope_test's")
	}
	for _, k := range []Kind{Fail, Unknown, Pass} {
		noteVerdict("fail2ban", k)
		want := "fail2ban:" + Mode() + ":" + string(k)
		if !strings.Contains(","+Report()+",", ","+want+",") {
			t.Errorf("after a %s check the claim should carry %q, got %q", k, want, Report())
		}
	}
	// Every character still survives the plane's field pattern.
	for _, c := range Report() {
		if !(c >= 'a' && c <= 'z') && !(c >= '0' && c <= '9') && c != '_' && c != ',' && c != ':' && c != '-' {
			t.Errorf("the recipe report %q carries %q, which the wire format does not allow", Report(), c)
		}
	}
}
