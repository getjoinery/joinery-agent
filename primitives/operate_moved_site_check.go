package primitives

import (
	"context"
	"regexp"
	"time"
)

// moved_site_check: say whether one container site's domain has left this
// Docker host — the proof decommission_moved_site runs before it removes
// anything, run on its own and removing nothing (specs/site_copy.md WP14).
// The management node shows the answer beside the old machine's site, so what
// the page says and what the removal would allow are one test.
//
// OPERATE, not observe: the proof writes a one-time token into the
// container's web root and empties it again. It changes nothing else.
//
// One parameter, a site NAME; the names checked come from this host's own
// vhost, as for the removal. See ExecEnv.MovedSiteCheck.
func init() {
	Register(Primitive{
		Name:        "moved_site_check",
		Class:       ClassOperate,
		Machine:     true,
		Description: "Check whether every name this host serves a container site under reaches another server, removing nothing.",
		Params: []ParamSpec{
			{Name: "site", Type: ParamString, Required: true, MaxLen: 50,
				Pattern: regexp.MustCompile(`^[a-z0-9_-]{1,50}$`)},
		},
		Run: movedSiteCheckRun,
		// A handful of bounded lookups and fetches (20 s each) and two copies.
		Timeout: 5 * time.Minute,
	})
}

// movedSiteCheckRun hands the check to the machinery that can reach the
// host's vhosts and containers. Nil on a machine that is not a host, which
// refuses.
func movedSiteCheckRun(ctx context.Context, env *ExecEnv, params Params) (map[string]interface{}, error) {
	if env == nil || env.MovedSiteCheck == nil {
		return nil, refusedf("this machine cannot check where a co-resident site's domain goes — only an " +
			"agent in host posture (no site of its own) does that")
	}
	return env.MovedSiteCheck(ctx, params.String("site"))
}
