package primitives

import (
	"context"
	"time"
)

// ApprovalWindow is how long a node holds a destructive job open waiting for its
// own operator to answer.
//
// It is a real cost and it is chosen deliberately. The agent claims one job at a
// time, so a node waiting on an approval is a node doing nothing else — but a
// node in this position is a node mid-incident, and the alternative shapes are
// worse. Refusing immediately and asking the operator to re-dispatch would mean
// the challenge was bound to a job that no longer exists, so the second dispatch
// would issue a second challenge and the first approval would be worthless.
//
// AN HOUR, and the number is a symptom of the design rather than a judgement
// about people. It was fifteen minutes, which assumed an operator standing by
// with their recovery key already to hand. The real case is someone at work, in
// a meeting, or asleep — and for that the honest answer is not a longer hold but
// no hold at all: stage the challenge, release the job, and pick the answer up
// on a later poll. That is specced in `deferred_destructive_approval.md`, and
// until it lands this constant is bounded by what a node can afford to be deaf
// for, NOT by what is convenient for the person approving.
//
// So: an hour covers a meeting, and costs a node up to an hour of answering
// nothing else — its scheduled backup queues behind the restore rather than
// being lost. Twelve hours, which is what the requirement actually wants, would
// take a managed node out of monitoring for half a day and delay noticing a
// genuinely crashed restore by the same amount, because the plane's claim budget
// has to exceed this. That is the trade the deferred design removes.
//
// Each restore primitive adds this to its own deadline, so the wait is inside
// the job rather than on top of it, and every plane-side claim budget must
// exceed the total — pinned by primitive_transport_parity_test.php, which reads
// this constant out of the source.
const ApprovalWindow = 60 * time.Minute

// The gate a destructive job passes before anything runs.
//
// THE MANAGEMENT NODE IS NOT IN THIS PATH — not as a gate, and not as a relay.
// A restore erases a live database or replaces a live site tree, and the party
// that dispatches it is exactly the party this design assumes may be
// compromised. So the machine being restored decides, its own operator answers,
// and the plane can do nothing whatsoever to get a restore approved.
//
// WHAT AUTHORIZES IT is the node's own backup recovery key. Every node already
// holds the public half and has already proven someone holds the private half —
// that proof is why the node is allowed to seal a backup at all. Whoever holds
// that key can already read every backup the machine has ever made, so proving
// possession of it is at least as strong an authority as anything that could be
// invented, and there is nothing to enrol: every node in the fleet can approve a
// restore today, with a key it already has.
//
// The shape of it: the agent composes its OWN statement of what it would do,
// seals a one-time challenge to the recovery public key, binds the challenge to
// that specific job and that specific statement, and stages both where the
// node's own site can render them. The operator opens the challenge with their
// recovery key on their own machine's admin page and answers. The agent verifies
// the answer against the challenge it issued, and only then runs.
//
// THE WIRE FORMAT IS WHAT ENFORCES "NO RELAY". None of the restore primitives
// declares a parameter through which an approval answer could arrive, and
// Validate refuses undeclared keys — so a job carrying one is refused before any
// of this is reached. That is deliberate and it is the same rule restore_paths.go
// states for key material: not "the builder was careful", but "there is no field
// for it". Anyone adding a convenience parameter here would be reopening the
// property, in a diff a reviewer sees.

// ApprovalFact is one line of what the node says it is about to do. Ordered
// pairs rather than a map, because the operator reads them in order and the
// order is chosen: what will be destroyed first, what it will be replaced with
// second, how old that is third.
type ApprovalFact struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

// ApprovalStatement is the node's own account of a destructive job, composed
// from the node's own records. It is what the challenge is bound to, so the
// machine can only act on what it itself stated, and afterwards there is a
// record of exactly what was authorized that the plane could neither forge nor
// alter — because the plane never touched it.
type ApprovalStatement struct {
	// Primitive is the operation, by name.
	Primitive string `json:"primitive"`
	// Summary is one plain sentence: what this does to this machine.
	Summary string `json:"summary"`
	// Facts are the specifics, in reading order.
	Facts []ApprovalFact `json:"facts"`
}

// ApprovalGate blocks a destructive job until the machine's own operator
// approves this exact job, or refuses it, or the wait runs out.
//
// A nil gate is not "approve everything": Execute refuses ClassDestructive
// outright when there is none, so a build or a deployment that forgot to wire
// one is a node that will not restore, rather than a node that restores on
// anyone's say-so.
type ApprovalGate interface {
	// Require returns nil only when an operator on this machine's own site has
	// opened a challenge sealed to this machine's recovery public key and
	// answered with what was inside it, for this job.
	//
	// Every other outcome is a refusal: no recovery key, no proof of possession,
	// an explicit decline, an expired challenge, or a wait that ran out.
	Require(ctx context.Context, jobID int64, statement ApprovalStatement) error
}
