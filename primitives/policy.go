package primitives

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"syscall"
)

// DefaultPolicyPath is where a node's acceptance policy lives. Root-owned,
// beside the agent's other root-owned configuration — NOT in the web tree,
// which the web user can write. A compromised plane cannot relax this file,
// and neither can a compromised web tier.
const DefaultPolicyPath = "/etc/joinery-agent/policy.json"

// Policy is which primitive classes this node accepts unattended, and from
// which paired plane. It lives on the node so refusal is node-enforced rather
// than plane-promised (§3.3).
type Policy struct {
	// Accept lists the classes this node accepts unattended.
	Accept []Class `json:"accept"`
	// PlaneURL, when set, is the only plane this node takes work from. The
	// transport enforces it; it is recorded here so one root-owned file
	// answers both halves of "who may ask, and for what".
	PlaneURL string `json:"plane_url,omitempty"`

	// source describes where this policy came from, for the refusal reason.
	source string
}

// ShippedPolicy is the fleet-uniform policy of §3.3: observe yes, operate yes,
// destructive only behind an approval this node issues and verifies itself —
// everywhere, own nodes included (A1/A2). A node with no policy file runs this.
//
// DESTRUCTIVE IS LISTED HERE, AND THAT IS NOT A RELAXATION OF A2. A2 says a
// destructive job is never run UNATTENDED. It is not unattended: Execute
// requires an operator on this machine's own site to open a challenge sealed to
// this machine's recovery key and answer it, for that job, before a destructive
// primitive runs at all. Listing the class here is what lets the fleet's
// existing nodes approve a restore with a key they already hold — the
// alternative was pushing a new policy file to every node, which is an
// enrolment step, and an enrolment step is the thing this design was chosen to
// avoid.
//
// A node that wants restores refused outright, approval or not, drops
// "destructive" from its own policy file. That still works and still wins.
func ShippedPolicy() *Policy {
	return &Policy{
		Accept: []Class{ClassObserve, ClassOperate, ClassDestructive},
		source: "the shipped fleet-uniform policy (no policy file on this node)",
	}
}

// LoadPolicy reads a node's policy file.
//
// Absent file: the shipped policy, which already refuses the only class that
// matters. Present but not trustworthy — not owned by root, or writable by
// group or other — is NOT a warning: it is a policy that something other than
// root could have written, so it is refused outright and the node accepts
// nothing until a human fixes the file. Failing open here would hand the
// decision to whoever could write the file, which is the one thing the file
// exists to prevent.
func LoadPolicy(path string) (*Policy, error) {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return ShippedPolicy(), nil
	}
	if err != nil {
		return refuseAllPolicy(fmt.Sprintf("policy file %s cannot be read (%v)", path, err)), nil
	}

	if !info.Mode().IsRegular() {
		return refuseAllPolicy(fmt.Sprintf("policy file %s is not a regular file", path)), nil
	}
	if perm := info.Mode().Perm(); perm&0o022 != 0 {
		return refuseAllPolicy(fmt.Sprintf(
			"policy file %s is writable by group or other (mode %04o) — something other than root could have written it", path, perm)), nil
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok && st.Uid != 0 {
		return refuseAllPolicy(fmt.Sprintf(
			"policy file %s is owned by uid %d, not root", path, st.Uid)), nil
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return refuseAllPolicy(fmt.Sprintf("policy file %s cannot be read (%v)", path, err)), nil
	}

	var p Policy
	if err := json.Unmarshal(raw, &p); err != nil {
		return refuseAllPolicy(fmt.Sprintf("policy file %s is not valid JSON (%v)", path, err)), nil
	}
	for _, c := range p.Accept {
		if !classAllowed[c] {
			return refuseAllPolicy(fmt.Sprintf(
				"policy file %s names class %q, which this agent has no such class for", path, c)), nil
		}
	}
	p.source = "the policy file at " + path
	return &p, nil
}

// refuseAllPolicy is the fail-closed policy: it accepts nothing and says why.
func refuseAllPolicy(reason string) *Policy {
	return &Policy{Accept: nil, source: reason}
}

// Accepts reports whether this node will consider a primitive of the given
// class at all, returning a refusal naming the reason when it will not.
//
// IT IS NOT THE WHOLE OF THE DESTRUCTIVE GATE, and reading it as such is the
// mistake this comment exists to prevent. Accepting the class means "this node
// is willing to be ASKED", never "this node will do it". The second half lives
// in Execute: a ClassDestructive job runs only after an operator on this
// machine's own site has opened a challenge sealed to this machine's own backup
// recovery key — bound to that job and to the node's own statement of what it
// would do — and answered with what was inside it. There is no configuration
// value, on this node or anywhere else, that skips that.
//
// The two halves are apart because they answer different questions with
// different information. This one is about a CLASS and knows nothing else: no
// job, no parameters, no way to reach the machine's own state. The approval is
// about one job's real archive, real age and real size, which only exists after
// the parameters have been validated. Folding them together would have meant
// either approving a class in the abstract or giving the policy file a
// dependency on the whole environment.
//
// A node that wants destructive work refused outright — approval or not — says
// so by leaving "destructive" out of its own root-owned policy file, and that
// refusal is final: the plane cannot argue with it and neither can an operator
// at a keyboard.
func (p *Policy) Accepts(class Class) error {
	for _, accepted := range p.Accept {
		if accepted == class {
			return nil
		}
	}
	return refusedf("this node does not accept %s primitives: %s", class, p.source)
}

// Describe renders the policy for the startup log and the heartbeat, so what a
// node will and will not accept is readable without opening the file.
func (p *Policy) Describe() string {
	if len(p.Accept) == 0 {
		return "accepts nothing — " + p.source
	}
	names := make([]string, 0, len(p.Accept))
	for _, c := range p.Accept {
		names = append(names, string(c))
	}
	sort.Strings(names)
	out := "accepts"
	for i, n := range names {
		if i > 0 {
			out += ","
		}
		out += " " + n
	}
	// Named explicitly, because "accepts destructive" on a startup line would
	// otherwise read as "this node will restore when told to", which is exactly
	// the opposite of what it means.
	if p.acceptsClass(ClassDestructive) {
		out += " (destructive only behind an approval answered on this machine)"
	}
	return out + " — from " + p.source
}

// acceptsClass is the plain membership test, without the refusal message.
func (p *Policy) acceptsClass(class Class) bool {
	for _, accepted := range p.Accept {
		if accepted == class {
			return true
		}
	}
	return false
}
