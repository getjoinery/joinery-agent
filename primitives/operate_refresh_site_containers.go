package primitives

import "time"

// refresh_site_containers: run this host's nightly replacement of its site
// containers now (fleet_security_patching.md WP4, Refresh now on the host's
// node page).
//
// Why it exists: a site container's OS is its image's, and nothing inside it
// installs a fix; the host replaces its containers when Ubuntu ships one, at
// night (site_refresh.sh). On the day a critical fix ships, waiting for the
// night leaves every site on the old code until then. This starts the same
// run now: a check of the base, a fresh build when a fix is pending, then each
// due site replaced one at a time.
//
// A SCRIPT WORD: maintenance_scripts/install_tools/site_refresh.sh, verified
// against the signed release manifest (on a host, the support bundle's), with
// one fixed argument, start. The script starts the systemd service the
// nightly timer starts and returns, so the run keeps the service's own bounds,
// lock and log, and the job does not wait out a run of many sites. What the
// run did is in the host report's site_refresh, as a night's is.
//
// HOSTILE-CALLER REVIEW (rule 5).
//
// What is the worst a compromised management node can do with this word?
// Make the host run its nightly replacement early, as often as it asks: a
// base built when a fix is pending, and each site whose image is not on the
// current base replaced, about ten seconds down each (recreate_site could
// already do one at a time). A second ask while a run is under way starts
// nothing. Accepted.
//
// What it cannot do:
//
//   - Name a site, an image, a package or an option: the word takes no
//     parameters, and what is replaced is decided on the host from its own
//     base, run specs and signed tree.
//   - Start a run the host has switched off: the script refuses where the
//     timer is off (site_refresh.sh install stops it for a tree that is not
//     root's alone).
//   - Read anything. It prints one line.
func init() {
	Register(Primitive{
		Name:        "refresh_site_containers",
		Class:       ClassOperate,
		Machine:     true,
		Description: "Start this host's nightly replacement of its site containers now (Ubuntu's fixes): check the base, build it fresh when a fix is pending, then replace each due site one at a time. Returns once the run has started; takes nothing.",
		Params:      nil,

		Script: &ScriptSpec{
			Interpreter: "/bin/bash",
			ScriptPath:  refreshSiteContainersScript,
			Args:        []string{"start"},
			StdinFrom:   nil,
		},

		// The script asks systemd to start a service and returns.
		Timeout: 2 * time.Minute,
	})
}

const refreshSiteContainersScript = "maintenance_scripts/install_tools/site_refresh.sh"
