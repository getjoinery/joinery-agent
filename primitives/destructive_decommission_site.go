package primitives

import (
	"context"
	"regexp"
	"time"
)

// decommission_site: permanently remove one container site from this Docker
// host. The second DESTRUCTIVE operation in the vocabulary, and the first whose
// approving party is not this machine's own site — the HOST runs the teardown,
// and the VICTIM (the site being destroyed) approves it on its own admin with
// its own recovery key. See ExecEnv.VictimCeremony and the Ceremony field.
//
// The parameter is a NAME, never a path (the delete_backup rule): every path —
// the vhost, the config volume, the web root — is composed host-side from
// compiled-in patterns, so the plane cannot express a location. The script it
// runs, remove_account.sh, arrives through the signed support bundle (a host
// has no site tree of its own to verify against) and is self-verifying: after
// removal it re-probes the container, its volumes, the vhost and the web root,
// and puts DECOMMISSION_VERIFIED or DECOMMISSION_FAILED_VERIFY in its own
// output, so one run carries its own verdict.
//
// WHAT THE SSH PATH COULD EXPRESS AND THIS CANNOT: the SSH job scp'd an
// arbitrary local file to an arbitrary remote path and ran it. Here the script
// is the bundle's, verified against the compiled-in release key, and the only
// thing the wire supplies is which site — bounded below.
func init() {
	Register(Primitive{
		Name:        "decommission_site",
		Class:       ClassDestructive,
		Description: "Permanently remove one container site from this host, with the site's own consent.",
		Params: []ParamSpec{
			// Which site. Lowercase name, no separators that could read as a
			// path, no leading dash that could read as a flag.
			{Name: "site", Type: ParamString, Required: true, MaxLen: 50,
				Pattern: regexp.MustCompile(`^[a-z0-9_-]{1,50}$`)},
		},
		Script: &ScriptSpec{
			Interpreter: "/bin/bash",
			ScriptPath:  decommissionScript,
			Args:        []string{"{site}", "-y"},
			// No stdin: the script reads none, and there is nothing secret to
			// carry — the approval already happened by the time this runs.
			StdinFrom: nil,
		},
		// The victim approves its own removal. Statement and gate both come
		// from the victim connection the host builds; a machine that cannot
		// build one (not in host posture, victim unreachable, victim config
		// unreadable) refuses before anything is touched.
		Ceremony: decommissionCeremony,
		// Teardown is minutes (docker stop/rm, volume rm, a vhost delete); the
		// wait for a person is the window. Same shape as the restores: the
		// approval happens inside this deadline.
		Timeout: 15*time.Minute + ApprovalWindow,
	})
}

// decommissionScript ships in the signed support bundle, recorded at the same
// site-root-relative path a full release records it at, so the one ScriptPath
// resolves in either posture.
const decommissionScript = "maintenance_scripts/sysadmin_tools/remove_account.sh"

// decommissionCeremony hands the ceremony to the machinery that owns the
// victim connection. It lives behind an ExecEnv field for the boundary reason
// the struct states: what a primitive can reach is named there, and a machine
// that is not a host has the field nil and refuses.
func decommissionCeremony(ctx context.Context, env *ExecEnv, params Params) (ApprovalStatement, ApprovalGate, func(), error) {
	if env == nil || env.VictimCeremony == nil {
		return ApprovalStatement{}, nil, nil, refusedf(
			"this machine cannot stage a decommission approval on the site it would remove — " +
				"only an agent in host posture (no site of its own) does that, so it will not run one")
	}
	return env.VictimCeremony(ctx, params.String("site"))
}
