package recipes

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"joinery-agent/primitives"
)

// TickInterval is the check loop's cadence (settled question Q1 of
// specs/agent_tier1_recipes.md: every ten minutes, and a repair only after two
// consecutive failing ticks, so the worst-case detection is twenty minutes and
// a transient is never repaired). Every recipe's MinInterval is at least this;
// Register refuses one that is shorter.
const TickInterval = 10 * time.Minute

// Kind is a check's verdict: the only three answers a check may give.
type Kind string

const (
	// Pass: the aspect is correct.
	Pass Kind = "pass"
	// Fail: the aspect is wrong in a way the recipe's repair addresses.
	Fail Kind = "fail"
	// Unknown: the check could not answer (the word refused, the tool is
	// absent, the answer was unreadable). Unknown never repairs and never
	// counts as a failed tick.
	Unknown Kind = "unknown"
)

// Verdict is what a check returns: a kind and a short reason a person can read
// in the ledger.
type Verdict struct {
	Kind   Kind
	Reason string
}

// Env is what a recipe's check and repair may reach: the same execution
// environment and the same node policy the remote source hands a
// plane-dispatched job. A recipe runs its words through Run and nothing else.
type Env struct {
	Exec   *primitives.ExecEnv
	Policy *primitives.Policy
}

// Run executes one word of the vocabulary in-process, with no parameters and
// no job id. It goes through primitives.Execute, so the name is checked
// against the registry, the class against this node's policy, and a script
// against the signed manifest, exactly as for a job the plane sent.
func (e *Env) Run(ctx context.Context, word string) (map[string]interface{}, error) {
	if e == nil {
		return nil, fmt.Errorf("recipe has no execution environment")
	}
	return primitives.Execute(ctx, e.Exec, e.Policy, primitives.Request{Primitive: word})
}

// Recipe is one fixed sentence. There is no Params field, no Args field and
// no field of any type a parameter could hide in: a recipe is a name, the two
// words it composes, and the two functions that read their answers. Adding a
// field here that could carry configuration is a change to the security model
// and registry_test.go fails on it.
type Recipe struct {
	Name        string
	Description string

	// MinInterval is how often this recipe's check may run. Never shorter
	// than TickInterval; a check more expensive than the tick can be rarer.
	MinInterval time.Duration

	// CheckWord and RepairWord name the two primitives this recipe composes.
	// Register requires both to exist, CheckWord to be an observe word and
	// RepairWord to be an operate word, and neither to take a parameter.
	// A NoRepair recipe names no RepairWord at all.
	CheckWord  string
	RepairWord string

	// NoRepair marks a check-only recipe: a condition with no safe automatic
	// answer (a full disk — deleting things unattended is worse than the
	// disease), where the loop's job is to tell a person, not to act. Register
	// permits it only with an empty RepairWord and a nil Repair, and the loop
	// opens a case on the FIRST failing tick instead of spending a retry
	// budget it has no use for. registry_test.go pins which recipes are
	// check-only, so the set stays one visible list.
	NoRepair bool

	// Scope says where the recipe's subject lives. ScopeHost means the
	// machine itself (its units, its jails): an agent inside a container
	// cannot see that machine, so the loop does not tick a host-scoped
	// recipe there, and the claim reports it as not-applicable rather than
	// unknown every ten minutes for ever. ScopeSite means the recipe's
	// repair lives in a site tree (an installer the support bundle does not
	// carry): a machine with no site never ticks it, for the same reason.
	// ScopeAny (the zero value) ticks everywhere.
	Scope Scope

	// Check runs the check word and reads its answer into a verdict. Cheap,
	// side-effect free, run every tick the recipe is due.
	Check func(ctx context.Context, env *Env) Verdict

	// Repair runs the repair word once and says whether the word itself
	// reported success — the transcript, not the exit code. The loop then
	// verifies by running Check again; a repair counts as repaired only when
	// both agree. Detail is a bounded string for the ledger.
	Repair func(ctx context.Context, env *Env) (detail string, err error)
}

// namePattern is the same shape a primitive name has, for the same reason:
// the name travels to the plane in the claim and lands in a ledger filename,
// so nothing that could read as a path, a flag or a mode may register.
var namePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{2,39}$`)

// registry is the compiled-in recipe list. Populated only by Register, only
// from init functions in this package.
var registry = map[string]Recipe{}

// Register adds a recipe. Every failure is a panic at process start rather
// than a skipped recipe at tick time, as in primitives.Register: a malformed
// recipe list is a build mistake, and an agent that started with one would be
// an agent acting unasked on a sentence nobody reviewed.
func Register(r Recipe) {
	if !namePattern.MatchString(r.Name) {
		panic(fmt.Sprintf("recipes: invalid recipe name %q", r.Name))
	}
	if _, dup := registry[r.Name]; dup {
		panic(fmt.Sprintf("recipes: duplicate recipe %q", r.Name))
	}
	if r.MinInterval < TickInterval {
		panic(fmt.Sprintf("recipes: recipe %q wants a check every %v, shorter than the %v tick", r.Name, r.MinInterval, TickInterval))
	}
	if r.Check == nil {
		panic(fmt.Sprintf("recipes: recipe %q must set Check", r.Name))
	}
	if r.NoRepair {
		// Check-only, and only that: a repair word or function beside the
		// flag would be a repair the loop never runs, which is a reviewer
		// reading a sentence that does not happen.
		if r.RepairWord != "" || r.Repair != nil {
			panic(fmt.Sprintf("recipes: recipe %q is NoRepair but names a repair; a check-only recipe has none", r.Name))
		}
	} else if r.Repair == nil {
		panic(fmt.Sprintf("recipes: recipe %q must set both Check and Repair (or be NoRepair)", r.Name))
	}
	check, ok := primitives.Lookup(r.CheckWord)
	if !ok {
		panic(fmt.Sprintf("recipes: recipe %q checks with %q, which this agent has no word for", r.Name, r.CheckWord))
	}
	if check.Class != primitives.ClassObserve {
		panic(fmt.Sprintf("recipes: recipe %q checks with %q, which is %s, not observe — a check reads, never changes", r.Name, r.CheckWord, check.Class))
	}
	// A recipe has no parameters, so the words it composes cannot take any
	// either: there would be nothing to fill them from except this source,
	// and a value compiled here is a value the word should have compiled
	// itself.
	if len(check.Params) != 0 {
		panic(fmt.Sprintf("recipes: recipe %q composes a word that takes parameters; recipes compose only parameterless words", r.Name))
	}
	if !r.NoRepair {
		repair, ok := primitives.Lookup(r.RepairWord)
		if !ok {
			panic(fmt.Sprintf("recipes: recipe %q repairs with %q, which this agent has no word for", r.Name, r.RepairWord))
		}
		if repair.Class != primitives.ClassOperate {
			panic(fmt.Sprintf("recipes: recipe %q repairs with %q, which is %s, not operate — a recipe never runs a destructive word unasked", r.Name, r.RepairWord, repair.Class))
		}
		if len(repair.Params) != 0 {
			panic(fmt.Sprintf("recipes: recipe %q composes a word that takes parameters; recipes compose only parameterless words", r.Name))
		}
	}
	registry[r.Name] = r
}

// Lookup returns the recipe registered under name.
func Lookup(name string) (Recipe, bool) {
	r, ok := registry[name]
	return r, ok
}

// Names returns every registered recipe name, sorted.
func Names() []string {
	out := make([]string, 0, len(registry))
	for name := range registry {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// All returns every registered recipe, in name order. What the loop runs.
func All() []Recipe {
	names := Names()
	out := make([]Recipe, 0, len(names))
	for _, name := range names {
		out = append(out, registry[name])
	}
	return out
}

// Mode is how the loop's repair step behaves this release, as one word the
// plane can show on the node page.
// Scope is where a recipe's subject lives; see Recipe.Scope.
type Scope string

const (
	ScopeAny  Scope = ""
	ScopeHost Scope = "host"
	ScopeSite Scope = "site"
)

// HasSite answers whether this agent has a site tree to run installers
// from. Set once by the agent's main from its configuration (an empty site
// root is a machine with no site); a variable so a test can say either. The
// default is the live answer for the common posture.
var HasSite = func() bool { return true }

// InContainer answers whether this process runs inside a container: the
// Docker marker file, or no systemd to have units at all. A variable so a
// test can say either; the loop and the claim read it through the same
// answer.
var InContainer = func() bool {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		return true
	}
	return false
}

// Applicable answers whether a recipe ticks on this machine.
func Applicable(r Recipe) bool {
	return applicableWith(r, InContainer, HasSite)
}

func applicableWith(r Recipe, inContainer, hasSite func() bool) bool {
	switch r.Scope {
	case ScopeHost:
		return !inContainer()
	case ScopeSite:
		return hasSite()
	}
	return true
}

// inapplicableReason says, for a recipe that does not tick here, why not.
func inapplicableReason(r Recipe) string {
	if r.Scope == ScopeSite {
		return "no site tree here; the recipe's repair is an installer the support bundle does not carry"
	}
	return "in a container; the recipe's subject is the host"
}

// ModeOf is the mode the claim reports for one recipe: the compiled mode,
// or not-applicable where the recipe's subject is out of this agent's sight.
func ModeOf(r Recipe) string {
	if !Applicable(r) {
		return ModeNotApplicable
	}
	return Mode()
}

func Mode() string {
	if ReportOnly {
		return ModeReportOnly
	}
	return ModeArmed
}

const (
	ModeReportOnly    = "report-only"
	ModeArmed         = "armed"
	ModeNotApplicable = "not-applicable"
)

// Report is the recipe list as it travels in the claim: every recipe name
// with its mode after a colon and, once the check has run, its last verdict
// after another ("fail2ban:armed:fail"), comma-separated and sorted, so the
// plane never guesses which recipes a node runs, whether they act, or
// whether their subject is right. A recipe that does not apply here carries
// no verdict: it is never checked. The plane validates the list under the
// same rules as the vocabulary and stores it beside it.
func Report() string {
	parts := make([]string, 0, len(registry))
	for _, r := range All() {
		entry := r.Name + ":" + ModeOf(r)
		if Applicable(r) {
			if k := LastVerdict(r.Name); k != "" {
				entry += ":" + string(k)
			}
		}
		parts = append(parts, entry)
	}
	return strings.Join(parts, ",")
}
