// Package primitives is the agent's vocabulary: the complete, compiled-in set
// of things a control plane may ask this node to do.
//
// The package exists as its own package, separate from the agent's generic
// step executor, on purpose. The executor in the parent package runs shell
// strings from the local job queue — that is the plane-local job source, where
// the plane and the agent are the same machine. Nothing in THIS package can
// reach it: a primitive is selected by name from a registry, its parameters are
// validated against a declared shape, and the only file here permitted to start
// a process is script.go, which refuses to start one it cannot verify against a
// signed release manifest.
//
// There is deliberately no exec class. A job naming an unknown primitive, or a
// primitive whose class the node's own policy refuses, is refused ON THE NODE
// with a recorded reason, whatever the plane says. See
// specs/agent_on_node_architecture.md §3.2, §3.3, decision A1.
package primitives

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"time"
)

// Class groups primitives by what accepting one costs you. Acceptance policy
// is set per class, not per primitive (§3.2).
type Class string

const (
	// ClassObserve reads: collectors, status, list. No state changes.
	ClassObserve Class = "observe"
	// ClassOperate changes running state in recoverable ways: restarts,
	// reboots, disk reclaim, cert provisioning, upgrade apply, backup runs.
	ClassOperate Class = "operate"
	// ClassDestructive destroys or replaces data: restores, decommission.
	// Never dispatched unattended anywhere, own fleet included (A2).
	ClassDestructive Class = "destructive"
)

// classAllowed is the complete set of classes that exist. Register refuses any
// class outside it, so a fourth class cannot arrive as a string literal in a
// new primitive file — it has to be added here, in the file whose test asserts
// the set is exactly these three and contains nothing resembling "exec".
var classAllowed = map[Class]bool{
	ClassObserve:     true,
	ClassOperate:     true,
	ClassDestructive: true,
}

// namePattern is what a primitive may be called. Anything that could be read
// as a path, a flag, or a command fails to register.
var namePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{2,39}$`)

// Primitive is agent code selected by name. Exactly one of Run or Script is
// set: Run for an embedded primitive (the logic lives in Go), Script for one
// that invokes a platform script already on the node under a fixed argv
// template. Both are validated identically before either is reached.
type Primitive struct {
	Name        string
	Class       Class
	Description string

	// Params declares every parameter this primitive accepts. A job carrying
	// anything not declared here is refused; there is no pass-through.
	Params []ParamSpec

	// Run is the embedded implementation. It receives only validated params.
	Run func(ctx context.Context, env *ExecEnv, p Params) (map[string]interface{}, error)

	// Script is the script-invoking implementation: a fixed argv template
	// resolved from validated params, run without a shell, and only after the
	// target file verifies against the signed release manifest (§3.2).
	Script *ScriptSpec

	// Describe composes this node's own account of what a job would do, for the
	// operator who has to approve it. REQUIRED on ClassDestructive and
	// meaningless anywhere else; Register enforces both.
	//
	// The node composes it, from the node's own records — not the plane, which
	// is the party whose word is not being taken. It receives validated params
	// and the same ExecEnv a run would, so it can state the real archive, its
	// real age and its real size rather than what a job row claimed.
	Describe func(ctx context.Context, env *ExecEnv, p Params) (ApprovalStatement, error)

	// Timeout is how long this primitive may run before the node kills it.
	// Zero means DefaultTimeout.
	//
	// Declared per primitive and compiled in, for the same reason as everything
	// else here: a deadline the plane could set is a deadline an attacker could
	// set to zero (a denial of service) or to a week (a wedged root process per
	// job). The node decides how long its own work may take.
	//
	// It exists because the SSH steps each carried one and the primitive path
	// carried none — RemoteSource passes the agent's root context, so before
	// this a hung transfer was bounded only by whatever the script bounded
	// itself with, and an embedded primitive by nothing at all.
	Timeout time.Duration
}

// DefaultTimeout applies to any primitive that does not declare one. Sized for
// the ones that read a directory or write a file: generous for work measured in
// milliseconds, short enough that a wedged one is noticed.
const DefaultTimeout = 5 * time.Minute

// MaxTimeout is the ceiling on any declared timeout. A primitive asking for
// longer is a build mistake, and Register panics rather than accepting it: work
// that genuinely takes half a day should be a job the node reports progress on,
// not one root process nothing will ever reap.
const MaxTimeout = 6 * time.Hour

// registry is the compiled-in vocabulary. Populated only by Register, only
// from init functions in this package.
var registry = map[string]Primitive{}

// Register adds a primitive to the vocabulary. Every failure here is a panic
// at process start rather than an error at job time: a malformed vocabulary is
// a build mistake, and an agent that started with one would be an agent whose
// refusals cannot be trusted.
func Register(p Primitive) {
	if !namePattern.MatchString(p.Name) {
		panic(fmt.Sprintf("primitives: invalid primitive name %q", p.Name))
	}
	if _, dup := registry[p.Name]; dup {
		panic(fmt.Sprintf("primitives: duplicate primitive %q", p.Name))
	}
	if !classAllowed[p.Class] {
		panic(fmt.Sprintf("primitives: primitive %q declares unknown class %q", p.Name, p.Class))
	}
	if (p.Run == nil) == (p.Script == nil) {
		panic(fmt.Sprintf("primitives: primitive %q must set exactly one of Run or Script", p.Name))
	}
	// One source of argv, so "where did this argument come from" has one
	// answer. A spec setting both would silently ignore one of them, and the
	// ignored one would read as an active constraint to the next reviewer.
	if p.Script != nil && p.Script.Args != nil && p.Script.ArgsFrom != nil {
		panic(fmt.Sprintf("primitives: primitive %q sets both Args and ArgsFrom", p.Name))
	}
	if err := validateSpecs(p.Params); err != nil {
		panic(fmt.Sprintf("primitives: primitive %q has a bad parameter spec: %v", p.Name, err))
	}
	// A destructive primitive that cannot describe itself is one no operator
	// could meaningfully approve, and approving it anyway would make the
	// approval a formality. A panic at process start rather than a refusal at
	// job time, for the reason every other check here is: a malformed
	// vocabulary is a build mistake, and an agent that started with one is an
	// agent whose refusals cannot be trusted.
	if p.Class == ClassDestructive && p.Describe == nil {
		panic(fmt.Sprintf("primitives: destructive primitive %q has no Describe", p.Name))
	}
	if p.Class != ClassDestructive && p.Describe != nil {
		panic(fmt.Sprintf("primitives: primitive %q is not destructive but declares Describe", p.Name))
	}
	if p.Timeout < 0 || p.Timeout > MaxTimeout {
		panic(fmt.Sprintf("primitives: primitive %q declares a timeout of %v, outside (0, %v]", p.Name, p.Timeout, MaxTimeout))
	}
	if p.Timeout == 0 {
		p.Timeout = DefaultTimeout
	}
	registry[p.Name] = p
}

// Lookup returns the primitive registered under name.
func Lookup(name string) (Primitive, bool) {
	p, ok := registry[name]
	return p, ok
}

// Names returns every registered primitive name, sorted. The plane has no say
// in this list; it is what this binary was compiled with.
func Names() []string {
	out := make([]string, 0, len(registry))
	for name := range registry {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// Classes returns the complete class set, sorted. Used by the gate test and by
// the agent's startup log line.
func Classes() []Class {
	out := make([]Class, 0, len(classAllowed))
	for c := range classAllowed {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
