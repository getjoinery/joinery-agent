package primitives

import (
	"context"
	"database/sql"
	"fmt"
)

// RefusalError is the node saying no. It is distinct from a primitive that ran
// and failed: a refusal means nothing was attempted, and the reason is recorded
// and reported back so a refused job reads as a decision rather than a fault.
type RefusalError struct{ Reason string }

func (e *RefusalError) Error() string { return e.Reason }

func refusedf(format string, args ...interface{}) error {
	return &RefusalError{Reason: fmt.Sprintf(format, args...)}
}

// Refused reports whether err is a node-side refusal.
func Refused(err error) bool {
	_, ok := err.(*RefusalError)
	return ok
}

// ExecEnv is what a primitive is allowed to reach. Everything a primitive can
// touch is here, by name: there is no ambient handle to the SSH pool, the job
// queue, or a shell. Adding a capability means adding a field here, which is a
// visible change to the security boundary rather than an import in one file.
type ExecEnv struct {
	// SiteRoot is the directory holding config/ and public_html/.
	SiteRoot string
	// WebRoot is the public_html directory.
	WebRoot string
	// DB is the node's own database, for collectors that read local state.
	// Nil when the node has no Joinery database.
	DB *sql.DB
	// Manifest verifies a file against the signed release manifest before a
	// script-invoking primitive is allowed to execute it. Never nil in
	// production; see manifest.go.
	Manifest ManifestVerifier
}

// Request is one job as the agent received it, after the transport has decided
// it is addressed to this node.
type Request struct {
	JobID     int64
	Primitive string
	Params    map[string]interface{}
}

// Execute runs one primitive job under a node-side policy.
//
// Order matters and is the whole point: the name is checked against the
// compiled-in vocabulary, then the class against the node's own policy, then
// the params against the primitive's declared shape — all before any primitive
// code runs. A wire string is never executed at any point in this function or
// anything it calls.
func Execute(ctx context.Context, env *ExecEnv, policy *Policy, req Request) (map[string]interface{}, error) {
	p, ok := Lookup(req.Primitive)
	if !ok {
		return nil, refusedf("this agent has no primitive named %q — its vocabulary is compiled in and cannot be extended from the wire", req.Primitive)
	}

	if err := policy.Accepts(p.Class); err != nil {
		return nil, err
	}

	params, err := Validate(p.Params, req.Params)
	if err != nil {
		return nil, err
	}

	if p.Script != nil {
		return runScriptPrimitive(ctx, env, p, params)
	}

	if env == nil {
		return nil, refusedf("primitive %q has no execution environment", p.Name)
	}
	return p.Run(ctx, env, params)
}
