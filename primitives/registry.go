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
}

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
	if err := validateSpecs(p.Params); err != nil {
		panic(fmt.Sprintf("primitives: primitive %q has a bad parameter spec: %v", p.Name, err))
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
