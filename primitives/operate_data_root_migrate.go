package primitives

import "time"

// data_root_migrate: move this host's data onto its data root
// (specs/one_data_root.md WP3, WP4, D5).
//
// Why it exists: a host installed before the data root keeps its database,
// mail queue, sites' folders and Docker's data on the root disk. The data
// root (/srv/joinery, a filesystem of its own) is where every new install
// keeps them, and the management node moves each older node there one at a
// time. The move stops the node's services for as long as copying its data
// once takes; nothing is lost if it fails, because it puts everything back.
//
// A SCRIPT WORD: maintenance_scripts/install_tools/joinery_data_root.sh,
// verified against the signed release manifest (on a Docker host, the
// support bundle's), with the one argv element migrate. No parameters: the
// script sizes the data root from the data it finds.
//
// The script runs the move in a systemd unit of its own
// (joinery-data-root-migrate.service), so a timeout here, which kills this
// word's process group, or an agent restart mid-copy, ends only the
// transcript: the move finishes or puts everything back by itself, and
// writes /var/log/joinery-data-root-migrate.log either way. A second run
// while one is going is refused.
//
// HOSTILE-CALLER REVIEW (rule 5).
//
// What is the worst a compromised management node can do with this word?
// Take the node's sites, database and mail down for the length of one copy
// of its data, once: run again, the script finds nothing left to move and
// stops nothing. The same outage restart_unit could cause. Disk: the script
// refuses before changing anything when the root disk cannot hold the data
// twice, so it cannot fill the root disk. Accepted.
//
// What it cannot do:
//
//   - Name a path, a size or a device. argv is fixed; the places moved are
//     the script's compiled list (D1).
//   - Lose data. Each copy is compared with its original before anything is
//     switched, and the originals stay at /srv/joinery.old until the data
//     root has passed check after a reboot.
//   - Read anything. The transcript says what moved and how much, in bytes.
func init() {
	Register(Primitive{
		Name:        "data_root_migrate",
		Class:       ClassOperate,
		Machine:     true,
		Description: "Move this host's data (PostgreSQL, the mail queue, each site's folders, Docker's data) onto its data root, /srv/joinery: its services stop for as long as one copy takes, and a move that does not finish puts everything back.",
		Params:      []ParamSpec{},

		Script: &ScriptSpec{
			Interpreter: "/bin/bash",
			ScriptPath:  dataRootMigrateScript,
			Args:        []string{"migrate"},
			StdinFrom:   nil,
		},

		// One copy of the host's data. The move itself is not bounded by this:
		// past it the transcript ends and the move goes on in its own unit.
		Timeout: 4 * time.Hour,
	})
}

const dataRootMigrateScript = "maintenance_scripts/install_tools/joinery_data_root.sh"
