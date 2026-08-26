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
// destructive refused unattended — everywhere, own nodes included (A1/A2).
// A node with no policy file runs this.
func ShippedPolicy() *Policy {
	return &Policy{
		Accept: []Class{ClassObserve, ClassOperate},
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

// Accepts reports whether this node will run a primitive of the given class
// unattended, returning a refusal naming the reason when it will not.
//
// The destructive ceiling is compiled in, above the policy: a destructive job
// executes only when it carries a signature, over a node-issued challenge
// bound to that specific job, that the agent verifies itself (§3.3, sentinel
// §13.O10). No such verifier exists in this build, so there is no code path
// that can accept one — a policy file listing "destructive" still refuses.
// That is deliberate: the ceiling drops only when the approval verifier lands,
// in the same release, reviewed together.
func (p *Policy) Accepts(class Class) error {
	if class == ClassDestructive {
		return refusedf("destructive primitives are never run unattended on this node; " +
			"they require a node-verified approval signature, and this agent has no approval verifier yet")
	}
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
	return out + " (destructive always refused) — from " + p.source
}
