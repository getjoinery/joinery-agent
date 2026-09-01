package primitives

// decommission_site: the vocabulary's shape and its refusals. The ceremony's
// own mechanics (victim location, scoped staging) are tested in the main
// package beside the code that owns them; what belongs here is the boundary —
// what the wire can express, and what a machine that cannot ask refuses.

import (
	"context"
	"strings"
	"testing"
)

func decommissionRequest(params map[string]interface{}) Request {
	return Request{JobID: 99, Primitive: "decommission_site", Params: params}
}

// TestTheParameterIsANameNeverAPath: everything path-like is refused at
// validation, before the ceremony and before any code runs.
func TestDecommissionSiteNameIsANameNeverAPath(t *testing.T) {
	bad := []string{
		"../etc", "a/b", "a.b", "-flag", "UPPER", "", strings.Repeat("a", 51), "a b",
	}
	for _, site := range bad {
		_, err := Execute(context.Background(), &ExecEnv{}, ShippedPolicy(),
			decommissionRequest(map[string]interface{}{"site": site}))
		if err == nil {
			t.Errorf("site name %q was accepted", site)
		}
	}
}

// TestAMachineThatIsNotAHostRefuses: without a victim ceremony there is no one
// to ask, and a destructive job with no one to ask does not run. This is also
// the posture of every SITE machine in the fleet — only a siteless host is
// handed the ceremony.
func TestDecommissionRefusedWithoutAVictimCeremony(t *testing.T) {
	_, err := Execute(context.Background(), &ExecEnv{}, ShippedPolicy(),
		decommissionRequest(map[string]interface{}{"site": "scratchsite"}))
	if err == nil || !Refused(err) {
		t.Fatalf("expected a refusal, got %v", err)
	}
	if !strings.Contains(err.Error(), "host posture") {
		t.Errorf("the refusal should say only a host-posture agent stages this: %v", err)
	}
}

// TestTheCeremonyDecidesBeforeAnythingRuns: a ceremony whose gate declines
// means the script is never reached — proven by a ceremony that records it was
// consulted and a run that leaves no other trace.
func TestDecommissionCeremonyGateBlocksTheRun(t *testing.T) {
	asked := false
	env := &ExecEnv{
		VictimCeremony: func(ctx context.Context, site string) (ApprovalStatement, ApprovalGate, func(), error) {
			if site != "scratchsite" {
				t.Errorf("the ceremony was handed site %q", site)
			}
			asked = true
			return ApprovalStatement{Primitive: "decommission_site", Summary: "destroys scratchsite"},
				decliningGate{}, nil, nil
		},
	}
	_, err := Execute(context.Background(), env, ShippedPolicy(),
		decommissionRequest(map[string]interface{}{"site": "scratchsite"}))
	if err == nil || !Refused(err) {
		t.Fatalf("a declined ceremony must refuse the job, got %v", err)
	}
	if !asked {
		t.Fatal("the victim ceremony was never consulted")
	}
}

// TestACeremonyThatCannotBeBuiltIsARefusal: an unreachable victim (config
// unreadable, database down) refuses the job rather than proceeding unasked.
func TestDecommissionCeremonyErrorRefusesTheJob(t *testing.T) {
	env := &ExecEnv{
		VictimCeremony: func(ctx context.Context, site string) (ApprovalStatement, ApprovalGate, func(), error) {
			return ApprovalStatement{}, nil, nil, refusedf("the site %s's database did not answer", site)
		},
	}
	_, err := Execute(context.Background(), env, ShippedPolicy(),
		decommissionRequest(map[string]interface{}{"site": "scratchsite"}))
	if err == nil || !Refused(err) {
		t.Fatalf("expected a refusal, got %v", err)
	}
}

// TestTheCleanupRunsEvenWhenTheGateDeclines: the victim connection is released
// on every path out of the ceremony.
func TestDecommissionCeremonyCleanupAlwaysRuns(t *testing.T) {
	cleaned := false
	env := &ExecEnv{
		VictimCeremony: func(ctx context.Context, site string) (ApprovalStatement, ApprovalGate, func(), error) {
			return ApprovalStatement{Primitive: "decommission_site", Summary: "destroys scratchsite"},
				decliningGate{}, func() { cleaned = true }, nil
		},
	}
	_, _ = Execute(context.Background(), env, ShippedPolicy(),
		decommissionRequest(map[string]interface{}{"site": "scratchsite"}))
	if !cleaned {
		t.Fatal("the ceremony's cleanup never ran")
	}
}

// TestNoParameterCanCarryAnAnswer pins the wire shape: the vocabulary declares
// exactly one parameter, so an approval answer has no field to arrive through
// — the same rule the restores pin in their own way. An undeclared key is
// refused by Validate before anything else happens.
func TestDecommissionWireShapeHasNoAnswerChannel(t *testing.T) {
	p, ok := Lookup("decommission_site")
	if !ok {
		t.Fatal("decommission_site is not registered")
	}
	if len(p.Params) != 1 || p.Params[0].Name != "site" {
		t.Fatalf("the wire shape grew: %+v — a second parameter is a place an answer could arrive", p.Params)
	}
	if p.Script == nil || p.Script.StdinFrom != nil {
		t.Fatal("the script gained a stdin channel")
	}
	_, err := Execute(context.Background(), &ExecEnv{}, ShippedPolicy(),
		decommissionRequest(map[string]interface{}{"site": "scratchsite", "answer": "yes"}))
	if err == nil {
		t.Fatal("an undeclared parameter was accepted")
	}
}

// decliningGate answers no, immediately.
type decliningGate struct{}

func (decliningGate) Require(ctx context.Context, jobID int64, s ApprovalStatement) error {
	return refusedf("the operator of the site being removed declined this decommission on its own admin page")
}
