package primitives

import "time"

// container_inventory: every container on this machine, whether install.sh
// made it, its image, its state, its mounts and whether its run spec exists.
//
// The word specs/agent_recipes_and_vocabulary.md's running list asked for on
// 2026-10-06. Removing getjoinery's old container from docker-prod reached for
// two sibling sites' volumes by a name prefix; remove_account.sh 2.10 fixed it
// to remove only a container install.sh made, and deciding that rule needed
// each container's image and mounts and whether the host keeps run specs,
// which took a read-only SSH session. The running list first named host_report
// for this; a host's hundred sites already fill most of the agent's 64 KiB
// there, so it is a word of its own.
//
// A SCRIPT WORD, because it needs the container engine (Docker, or the site
// container engine, Podman, named by install_tools/_site_engine.sh). What runs is
// maintenance_scripts/sysadmin_tools/container_inventory.sh, verified against
// the signed release manifest, with no argv and no stdin.
//
// HOSTILE-CALLER REVIEW (rule 5 of specs/agent_recipes_and_vocabulary.md).
//
// What is the worst a compromised management node can do with this word?
// Learn the names, images and volume names of the containers on the machine.
// host_report already names the site containers and their state; this adds
// their images and every other container on the host, which is configuration
// (rule 8), not user data.
//
// What it cannot do:
//
//   - Point anywhere. NO PARAMETERS: not a container, not an image.
//   - Read a container's environment. The inspect template filters the
//     environment to SITENAME inside the engine; no other variable (a
//     password) reaches the script.
//   - Read a path on the server. A mount is its type and a volume's name; a
//     bind's source is never read.
//   - Change anything. The engine's ps and one inspect; no other verb.
//   - Flood the plane. A bounded list, held under its own byte budget below
//     the agent's 64 KiB cap, with truncated saying when it was cut.
//
// No owner switch: it reads no log and no content. Not redacted: every value
// is a name, an image reference or a type the script reduced to a safe
// character set.
//
// OBSERVE, and the classification does real work: a node whose policy accepts
// only observe words has to be able to trust that this one writes nothing.
func init() {
	Register(Primitive{
		Name:        "container_inventory",
		Class:       ClassObserve,
		Machine:     true,
		Description: "Every container on this machine: whether install.sh made it, its image, state, mounts (type and volume name) and whether its run spec exists; never a container's environment or a bind's source.",

		// Empty on purpose. See the review above.
		Params: nil,

		Script: &ScriptSpec{
			Interpreter: "/bin/bash",
			ScriptPath:  containerInventoryScript,
			Args:        nil,
			StdinFrom:   nil,
			Redact:      false,
		},

		// The engine's ps and one inspect for every container, each bounded at
		// twenty seconds in the script.
		Timeout: 2 * time.Minute,
	})
}

// containerInventoryScript is the shipped reader, site-root relative.
const containerInventoryScript = "maintenance_scripts/sysadmin_tools/container_inventory.sh"
