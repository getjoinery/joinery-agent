package primitives

import "time"

// install_security_updates: install, now, the updates this machine's own
// automatic-update policy allows, and report each package that changed.
//
// Automatic updates run once a day. When a hole is being attacked the day its
// fix ships, the fleet would otherwise wait until the next morning, and a
// machine nobody logs into (no root login, no SSH key) had no way to ask for
// it sooner.
//
// A SCRIPT WORD for the same reason as reset_failed_unit: only script.go may
// start a process. What runs is
// maintenance_scripts/sysadmin_tools/install_security_updates.sh, verified
// against the signed release manifest, with no arguments.
//
// HOSTILE-CALLER REVIEW (rule 5 of specs/agent_recipes_and_vocabulary.md).
//
// What is the worst a compromised management node can do with this word?
// Make the machine install, early, what its nightly run would install anyway:
// the updates its own unattended-upgrades policy allows (Ubuntu's security
// pocket, and the outside PHP and PostgreSQL repositories host_housekeeping.sh
// named). A package's own scripts restart the service they replace, so a site
// may be briefly unavailable; asked repeatedly, the second run finds nothing
// to install.
//
// What it cannot do:
//
//   - Name a package, a repository or an option. The word takes no parameters
//     and the script refuses any argument; what is installed is the machine's
//     policy, never the plane's choice, and never a general `apt upgrade`.
//   - Reboot. A package asking for one is reported; reboot_machine is a
//     separate word a person chooses.
//   - Read anything beyond package names, versions and service names, reduced
//     to a safe character set, so it needs neither the owner's log switch nor
//     the redactor.
//
// OPERATE, not observe: it changes what is installed. Machine: a siteless
// Docker host needs its fixes as much as a site does, and the support bundle
// carries the script.
func init() {
	Register(Primitive{
		Name:        "install_security_updates",
		Class:       ClassOperate,
		Machine:     true,
		Description: "Install now the updates this machine's own unattended-upgrades policy allows (the nightly run's packages), reporting each package that changed; takes nothing and never reboots.",
		Params:      nil,

		Script: &ScriptSpec{
			Interpreter: "/bin/bash",
			ScriptPath:  installSecurityUpdatesScript,
			Args:        nil,
			StdinFrom:   nil,
		},

		// The script bounds itself: ten minutes waiting for another package
		// run, five refreshing the lists, thirty for the updater (which stops
		// after the package in hand when told to), ten more for a run that
		// took the lock in between, and two for needrestart. This sits past
		// all of them so the script's own limits, never this kill, end a run.
		Timeout: 60 * time.Minute,
	})
}

// installSecurityUpdatesScript is the shipped script, site-root relative.
const installSecurityUpdatesScript = "maintenance_scripts/sysadmin_tools/install_security_updates.sh"
