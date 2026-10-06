package primitives

import (
	"regexp"
	"time"
)

// hold_container: stop one of this Docker host's Joinery containers and keep
// it stopped, or start it again (specs/site_copy.md WP14).
//
// Why it exists: a switch-over from backups moved a container site to a new
// server and left the old container running. It kept taking writes nobody
// would see again and kept running its scheduled tasks, its own backups
// among them, until someone removed it, and the switch-over asked the owner
// to say they had turned it off, which they could not do without root. The
// switch-over now stops it with this word once the copy has taken the site.
// A plain docker stop would not last: container_health restarts a site
// container that is not running.
//
// A SCRIPT WORD: maintenance_scripts/sysadmin_tools/hold_container.sh,
// verified against the signed release manifest (on a Docker host, the
// support bundle's), with two argv elements: stop|start and the site name.
//
// HOSTILE-CALLER REVIEW (rule 5).
//
// What is the worst a compromised management node can do with this word?
// Stop one of the host's own site containers and keep it stopped: that site
// is down until start. docker stop keeps the container, its writable layer
// and its volumes, and start puts back the restart policy the stop recorded,
// so nothing is lost. The same outage restart_container in a loop could
// already cause. Accepted.
//
// What it cannot do:
//
//   - Name a container that is not a Joinery site. `name` must match the site
//     pattern here, and the script refuses any container whose name is not
//     its own SITENAME, the shape install.sh creates.
//   - Remove, exec into, pull or run anything. The script's only changing
//     verbs are update (the restart policy), stop and start, pinned by its
//     gate.
//   - Read anything. It prints compiled states.
func init() {
	Register(Primitive{
		Name:        "hold_container",
		Class:       ClassOperate,
		Machine:     true,
		Description: "Stop one of this host's Joinery site containers and keep it stopped (no restart by Docker or container_health), or start it again with its restart policy back.",
		Params: []ParamSpec{
			{Name: "action", Type: ParamEnum, Required: true, Values: []string{"stop", "start"}},
			{Name: "name", Type: ParamString, Required: true, MaxLen: 50, Pattern: holdContainerName},
		},

		Script: &ScriptSpec{
			Interpreter: "/bin/bash",
			ScriptPath:  holdContainerScript,
			Args:        []string{"{action}", "{name}"},
			StdinFrom:   nil,
		},

		// docker stop waits up to the container's own stop timeout; the
		// script gives it two minutes, and each inspect twenty seconds.
		Timeout: 5 * time.Minute,
	})
}

// holdContainerName is the site-name pattern restart_container accepts, and
// the one hold_container.sh re-checks.
var holdContainerName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,49}$`)

const holdContainerScript = "maintenance_scripts/sysadmin_tools/hold_container.sh"
