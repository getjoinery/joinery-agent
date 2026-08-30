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
	// DBName is which database on this machine is the site's own, read from
	// the node's own config (Globalvars_site.php). Empty on a machine with no
	// site.
	//
	// It exists because there is nowhere else the answer lives: the control
	// plane stores no column for it, so a plane naming a node's database would
	// be inventing the value — and an invented value aimed at the wrong node
	// names somebody else's database, in the one operation that drops a schema.
	// The node knows, so the node says. Same rule as the site name in
	// run_plugin_installers and the domain in restore_project.
	//
	// It is a fact about this machine's own identity, like SiteRoot, and grants
	// nothing: a primitive that has DB already runs SQL, and one that does not
	// cannot start doing so by learning a name.
	DBName string

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

	// Approval is how this node asks its OWN operator to authorize a
	// destructive job. Nil means it cannot ask, and a node that cannot ask
	// refuses every destructive job — see Execute. It is a field here, rather
	// than something a primitive reaches for, for the reason the type comment
	// gives: everything a primitive can touch is named in this struct, so
	// widening the boundary is a visible change rather than an import.
	Approval ApprovalGate
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

	// CAN this node be asked at all? A question about the node and the binary,
	// not about the job, so it is answered here beside the policy check and
	// ahead of the parameters. A machine that cannot reach its own operator
	// refuses every destructive job, and says that rather than reporting
	// whichever parameter happened to be wrong.
	//
	// Nil is never "nobody objected". A build that forgot to wire the gate, or
	// a deployment that could not reach the database to ask, is a machine that
	// does not restore.
	if p.Class == ClassDestructive {
		if env == nil || env.Approval == nil {
			return nil, refusedf("this node has no way to ask its own operator to approve a %s, "+
				"so it will not run one", p.Name)
		}
		if p.Describe == nil {
			// Register refuses to build such a primitive, so reaching this is a
			// broken binary rather than a bad job. Refuse anyway: an
			// unapprovable destructive primitive must never fall through to
			// running.
			return nil, refusedf("primitive %q is destructive but cannot say what it would do, "+
				"so there is nothing an operator could approve", p.Name)
		}
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
	//
	// IT COVERS THE APPROVAL WAIT TOO, and that placement is load-bearing. A
	// destructive job is claimed and then HELD while a person at this machine
	// answers a challenge, and the plane's claim budget bounds the whole claim,
	// not the work inside it. With the deadline started after the approval
	// instead, a restore could spend the full approval window AND then the full
	// work budget — over the plane's ceiling — and the plane would hand the job
	// out a second time while the first copy was still restoring. Two concurrent
	// restores is the one thing in this vocabulary that destroys what it was
	// recovering. Each restore primitive's declared Timeout therefore includes
	// ApprovalWindow, and the two numbers have to stay on the same side of this
	// line.
	ctx, cancel := context.WithTimeout(ctx, p.Timeout)
	defer cancel()

	// THE APPROVAL ITSELF, for anything that destroys. After validation,
	// because the statement the operator approves is composed from validated
	// parameters — nobody should be shown an approval screen for a job the node
	// was going to reject anyway — and before any primitive code runs, because
	// the whole point is that nothing happens until a human on this machine
	// says so.
	//
	// Deliberately NOT inside Policy.Accepts. That answers a question about a
	// CLASS and has no job, no parameters and no way to reach the node's own
	// state; folding the approval into it would have meant either approving a
	// class in the abstract or giving the policy a dependency on everything.
	if p.Class == ClassDestructive {
		statement, err := p.Describe(ctx, env, params)
		if err != nil {
			return nil, err
		}
		if err := env.Approval.Require(ctx, req.JobID, statement); err != nil {
			return nil, err
		}
	}

	if p.Script != nil {
		return runScriptPrimitive(ctx, env, p, params)
	}

	if env == nil {
		return nil, refusedf("primitive %q has no execution environment", p.Name)
	}
	return p.Run(ctx, env, params)
}
