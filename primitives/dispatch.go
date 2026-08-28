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
	// DB resolves the node's own database, for collectors that read local
	// state. Nil when the node has no Joinery database at all.
	//
	// A provider rather than a handle, because the agent no longer waits for
	// PostgreSQL to be up before it runs. Resolution happens at use, so a
	// primitive that needs the database on a node where it is down reports that
	// as its own legible failure — while the primitives that need nothing from
	// it carry on, which on a sick node is most of what is worth knowing.
	DB DBProvider
	// Manifest verifies a file against the signed release manifest before a
	// script-invoking primitive is allowed to execute it. Never nil in
	// production; see manifest.go.
	Manifest ManifestVerifier

	// ToolRoot is the signed support bundle a machine with NO SITE unpacks, and
	// the tree its script primitives resolve against instead of SiteRoot. Empty
	// on every machine that has a site, which is every machine that has a
	// release manifest of its own to check against.
	//
	// It is a second root, not a fallback: a machine has one or the other, and
	// SiteRoot wins wherever it exists. Trying both in turn would mean a file
	// missing from the site's manifest could be satisfied by a bundle, which is
	// the cross-manifest fallback ArtifactManifests refuses for the same reason
	// — being listed in SOME manifest is not the same as being the file the
	// artifact that owns it shipped.
	ToolRoot string

	// ToolManifest verifies files under ToolRoot, against the signature the
	// bundle carries. Same contract as Manifest, same compiled-in key, and the
	// same posture when it is absent: no manifest means no script runs.
	ToolManifest ManifestVerifier
}

// DBProvider hands back a usable database connection, or says why not.
type DBProvider func() (*sql.DB, error)

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

	// The node's own deadline on its own work. Applied after validation, so a
	// refusal is never delayed by it, and applied to embedded and script
	// primitives alike: before this, RemoteSource handed both the agent's ROOT
	// context, so a wedged transfer was bounded only by whatever the script
	// bounded itself with, and an embedded primitive by nothing at all.
	ctx, cancel := context.WithTimeout(ctx, p.Timeout)
	defer cancel()

	if p.Script != nil {
		return runScriptPrimitive(ctx, env, p, params)
	}

	if env == nil {
		return nil, refusedf("primitive %q has no execution environment", p.Name)
	}
	return p.Run(ctx, env, params)
}
