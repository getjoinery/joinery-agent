package recipes

import (
	"context"
	"fmt"
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
	CheckWord  string
	RepairWord string

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
	if r.Check == nil || r.Repair == nil {
		panic(fmt.Sprintf("recipes: recipe %q must set both Check and Repair", r.Name))
	}
	check, ok := primitives.Lookup(r.CheckWord)
	if !ok {
		panic(fmt.Sprintf("recipes: recipe %q checks with %q, which this agent has no word for", r.Name, r.CheckWord))
	}
	if check.Class != primitives.ClassObserve {
		panic(fmt.Sprintf("recipes: recipe %q checks with %q, which is %s, not observe — a check reads, never changes", r.Name, r.CheckWord, check.Class))
	}
	repair, ok := primitives.Lookup(r.RepairWord)
	if !ok {
		panic(fmt.Sprintf("recipes: recipe %q repairs with %q, which this agent has no word for", r.Name, r.RepairWord))
	}
	if repair.Class != primitives.ClassOperate {
		panic(fmt.Sprintf("recipes: recipe %q repairs with %q, which is %s, not operate — a recipe never runs a destructive word unasked", r.Name, r.RepairWord, repair.Class))
	}
	// A recipe has no parameters, so the words it composes cannot take any
	// either: there would be nothing to fill them from except this source,
	// and a value compiled here is a value the word should have compiled
	// itself.
	if len(check.Params) != 0 || len(repair.Params) != 0 {
		panic(fmt.Sprintf("recipes: recipe %q composes a word that takes parameters; recipes compose only parameterless words", r.Name))
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
func Mode() string {
	if ReportOnly {
		return ModeReportOnly
	}
	return ModeArmed
}

const (
	ModeReportOnly = "report-only"
	ModeArmed      = "armed"
)

// Report is the recipe list as it travels in the claim: every recipe name
// with its mode after a colon, comma-separated and sorted, so the plane never
// guesses which recipes a node runs or whether they act. The plane validates
// it under the same rules as the vocabulary and stores it beside it.
func Report() string {
	names := Names()
	parts := make([]string, 0, len(names))
	for _, name := range names {
		parts = append(parts, name+":"+Mode())
	}
	return strings.Join(parts, ",")
}
