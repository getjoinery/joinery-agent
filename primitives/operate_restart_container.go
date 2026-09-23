package primitives

import (
	"regexp"
	"time"
)

// restart_container: restart one of this Docker host's Joinery containers,
// and report its state before and after.
//
// specs/agent_recipes_and_vocabulary.md § First words: a container is not a
// systemd unit, and the service_health recipe needs a repair for one whose
// site stops answering.
//
// A SCRIPT WORD: maintenance_scripts/sysadmin_tools/restart_container.sh,
// verified against the signed release manifest (on a Docker host, the
// support bundle's), with one argv element.
//
// HOSTILE-CALLER REVIEW (rule 5).
//
// What is the worst a compromised management node can do with this word?
// Restart one of the host's own site containers repeatedly: that site is
// down while it does. docker restart keeps the container, its writable layer
// and its volumes, so nothing is lost. The same outage apply_update could
// already cause. Accepted.
//
// What it cannot do:
//
//   - Name a container that is not a Joinery site. `name` must match the
//     site pattern here, and the script refuses any container whose name is
//     not its own SITENAME — the shape install.sh creates — so an operator's
//     database or proxy container is out of reach whatever it is called.
//   - Remove, stop, exec into, pull or run anything. The script's only
//     changing verb is restart, pinned by its gate.
//   - Read anything. It prints compiled states.
func init() {
	Register(Primitive{
		Name:        "restart_container",
		Class:       ClassOperate,
		Machine:     true,
		Description: "Restart one of this host's Joinery site containers (a container whose name is its SITENAME), reporting its state before and after.",
		Params: []ParamSpec{
			{Name: "name", Type: ParamString, Required: true, MaxLen: 50, Pattern: restartContainerName},
		},

		Script: &ScriptSpec{
			Interpreter: "/bin/bash",
			ScriptPath:  restartContainerScript,
			Args:        []string{"{name}"},
			StdinFrom:   nil,
		},

		Timeout: 4 * time.Minute,
	})
}

// restartContainerName is the site-name pattern decommission_site accepts,
// and the one restart_container.sh re-checks.
var restartContainerName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,49}$`)

const restartContainerScript = "maintenance_scripts/sysadmin_tools/restart_container.sh"
