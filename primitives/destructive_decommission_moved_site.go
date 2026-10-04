package primitives

import (
	"context"
	"regexp"
	"time"
)

// decommission_moved_site: permanently remove one container site from this
// Docker host once its domain no longer reaches it — the old machine of a
// switch-over whose new server already holds the site (specs/site_copy.md
// WP14).
//
// decommission_site asks the victim's operator to approve on the victim's own
// Backups page. After a switch-over that page is unreachable: the domain points
// at the new server. Here the HOST's proof that the domain has left stands in
// for the approval. The proof runs on this machine, never on the plane: the
// approval exists so that the plane alone cannot destroy a site, and a plane
// that could say "it moved" would have that back.
//
// Same parameter, same script, same verdict as decommission_site; only the
// gate differs. See ExecEnv.MovedSiteProof.
func init() {
	Register(Primitive{
		Name:        "decommission_moved_site",
		Class:       ClassDestructive,
		Machine:     true,
		Description: "Permanently remove one container site from this host once this host proves its domain reaches another server.",
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
		Ceremony: movedSiteCeremony,
		// Teardown is minutes; the proof is a handful of bounded fetches.
		Timeout: 20 * time.Minute,
	})
}

// movedSiteCeremony hands the proof to the machinery that can reach the host's
// vhosts and containers. Nil on a machine that is not a host, which refuses.
func movedSiteCeremony(ctx context.Context, env *ExecEnv, params Params) (ApprovalStatement, ApprovalGate, func(), error) {
	if env == nil || env.MovedSiteProof == nil {
		return ApprovalStatement{}, nil, nil, refusedf(
			"this machine cannot prove where a co-resident site's domain goes — only an agent in host " +
				"posture (no site of its own) does that, so it will not remove one")
	}
	return env.MovedSiteProof(ctx, params.String("site"))
}
