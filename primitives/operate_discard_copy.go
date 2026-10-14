package primitives

import "time"

// discard_copy {name}: remove a dormant copy of a site from this host
// (specs/site_container_engine.md D9). A copy installed here by site_install
// and not wanted, discarded from its Copy tab, or left behind by a way back.
//
// A SCRIPT WORD: maintenance_scripts/sysadmin_tools/discard_copy.sh, verified
// against the signed manifest (on a host, the support bundle's), with one argv
// element, the site name. It runs remove_account.sh beside it.
//
// HOSTILE-CALLER REVIEW (rule 5).
//
// What is the worst a compromised management node can do with this word?
// Remove a dormant copy: a site that was installed empty, filled from its
// source's backups, and has served no one. Its source and its backups hold
// every byte it does. Accepted, and why it needs no owner's ceremony.
//
// What it cannot do:
//
//   - Remove a live site. The script refuses unless the host records the site
//     as a dormant copy (/etc/joinery/sites/SITE/quiet says copy). Only
//     install.sh's dormant install writes that record; site_quiet_host sets
//     switchover and refuses to turn a copy's record into one; the record is
//     cleared when the copy takes over its source. So no word reaches a site
//     that is or was live.
//   - Name anything but a site: `name` matches the site pattern here and in
//     the script.
func init() {
	Register(Primitive{
		Name:        "discard_copy",
		Class:       ClassOperate,
		Machine:     true,
		Description: "Remove a dormant copy of a site from this host: only one its host records as a copy, which holds nothing its source and its backups do not.",
		Params: []ParamSpec{
			{Name: "name", Type: ParamString, Required: true, MaxLen: 50, Pattern: siteInstallName},
		},
		Script: &ScriptSpec{
			Interpreter: "/bin/bash",
			ScriptPath:  discardCopyScript,
			Args:        []string{"{name}"},
		},
		// remove_account.sh stops the container and removes its volumes.
		Timeout: 20 * time.Minute,
	})
}

const discardCopyScript = "maintenance_scripts/sysadmin_tools/discard_copy.sh"
