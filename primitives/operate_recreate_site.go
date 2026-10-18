package primitives

import "time"

// recreate_site: replace one of this host's site containers with a new one on
// the host's current base image, keeping everything the site is
// (specs/multi_tenant_host_hardening.md D9).
//
// Why it exists: a site container's OS (PHP, PostgreSQL, Apache, openssl,
// all from Ubuntu's archive) is its image's, and nothing inside it installs
// a fix. Everything the site keeps is on volumes, so it is patched by
// replacing its container. The host does that nightly when Ubuntu ships a
// security fix (site_refresh.sh); this is the operator's word for one site
// now, and the way a hold a failed replacement placed is lifted once the
// cause is put right.
//
// A SCRIPT WORD: maintenance_scripts/sysadmin_tools/recreate_site.sh,
// verified against the signed release manifest (on a host, the support
// bundle's), with one argv element: the site name.
//
// HOSTILE-CALLER REVIEW (rule 5).
//
// What is the worst a compromised management node can do with this word?
// Take one of the host's sites down for a swap, about ten seconds, as often
// as it asks (restart_container could already). The new container is made
// from the host's own run spec, base image and signed tree, never from
// anything in the job; when it does not come up, the previous image is put
// back. Accepted.
//
// What it cannot do:
//
//   - Name anything but a running site container install.sh made with a run
//     spec: `name` matches the site pattern, and the script refuses a
//     container whose SITENAME is not its name, a quiet or held site, and
//     one being rebased.
//   - Change what the site runs: the code is on its volumes, the image is
//     built from the host's tree, and the container's arguments are its run
//     spec's.
//   - Cut off an upgrade, backup or restore: the script refuses a site that
//     runs one.
//   - Read anything. It prints what it did, and one JSON object.
func init() {
	Register(Primitive{
		Name:        "recreate_site",
		Class:       ClassOperate,
		Machine:     true,
		Description: "Replace one of this host's site containers with a new one on the host's current base image (Ubuntu's fixes), building first; the previous image is put back when the new one does not come up.",
		Params: []ParamSpec{
			{Name: "name", Type: ParamString, Required: true, MaxLen: 50, Pattern: holdContainerName},
		},

		Script: &ScriptSpec{
			Interpreter: "/bin/bash",
			ScriptPath:  recreateSiteScript,
			Args:        []string{"{name}"},
			StdinFrom:   nil,
		},

		// The script's own bounds, summed: up to two minutes waiting out a
		// scheduled task (twice), a minute or two for each call into the site,
		// a 600 s build (the word never builds a base), two stops and two
		// three-minute waits: about thirty minutes at the worst, usually two.
		// The plane's claim for the word (management_jobs PRIMITIVE_CLAIM_BUDGETS)
		// is longer, so a job is never handed out again while it runs.
		Timeout: 32 * time.Minute,
	})
}

const recreateSiteScript = "maintenance_scripts/sysadmin_tools/recreate_site.sh"
