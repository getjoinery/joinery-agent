package primitives

import (
	"context"
	"regexp"
	"time"
)

// decommission_held_site: permanently remove one container site from this
// Docker host that has been held stopped long enough that its hosting is over
// (specs/hosting_paid_launch.md B1).
//
// A Starter site whose payment failed is held stopped at the end of its grace
// (hold_container), and its backups are pruned some sixty days later. After
// that nothing of it is wanted, but decommission_site cannot remove it: that
// waits for the site to approve on its own Backups page, and a stopped site
// renders no page. Here the HOST's own record stands in for the approval: the
// hold it wrote (/etc/joinery/sites/{site}/held, its time the hold's start) is
// at least HeldSiteMinAge old, and the engine says the container is not
// running. A management node can hold any container, but not backdate the
// hold, so the plane alone cannot remove a site it stopped yesterday.
//
// Same parameter, same script, same verdict as decommission_site; only the
// gate differs. See ExecEnv.HeldSiteProof.
func init() {
	Register(Primitive{
		Name:        "decommission_held_site",
		Class:       ClassDestructive,
		Machine:     true,
		Description: "Permanently remove one container site from this host that this host has held stopped for at least 55 days.",
		Params: []ParamSpec{
			{Name: "site", Type: ParamString, Required: true, MaxLen: 50,
				Pattern: regexp.MustCompile(`^[a-z0-9_-]{1,50}$`)},
		},
		Script: &ScriptSpec{
			Interpreter: "/bin/bash",
			ScriptPath:  decommissionScript,
			Args:        []string{"{site}", "-y"},
			StdinFrom:   nil,
		},
		Ceremony: heldSiteCeremony,
		Timeout:  20 * time.Minute,
	})
}

// HeldSiteMinAge is how long a hold must stand before the host removes the
// site on it. The plane asks only after the site's backups are pruned, about
// sixty days after the hold; the host's floor sits below that so a late prune
// never waits on it, and far above any hold a person might lift.
const HeldSiteMinAge = 55 * 24 * time.Hour

// heldSiteCeremony hands the check to the machinery that can read the host's
// holds and containers. Nil on a machine that is not a host, which refuses.
func heldSiteCeremony(ctx context.Context, env *ExecEnv, params Params) (ApprovalStatement, ApprovalGate, func(), error) {
	if env == nil || env.HeldSiteProof == nil {
		return ApprovalStatement{}, nil, nil, refusedf(
			"this machine cannot read a co-resident site's hold — only an agent in host " +
				"posture (no site of its own) does that, so it will not remove one")
	}
	return env.HeldSiteProof(ctx, params.String("site"))
}
