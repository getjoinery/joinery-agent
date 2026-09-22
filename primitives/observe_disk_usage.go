package primitives

import "time"

// disk_usage: where the space went — the filesystem's own figures, the site
// tree's biggest directories to depth two, and the machine directories that
// are usually the answer when the site tree is not.
//
// It exists because of the question that followed a node filling its disk:
// *what are the ten gigabytes?* The plane stores a total and nothing else, so
// the honest answer was "an ingest ran for four days and we cannot see what it
// wrote". A total says a node is filling; this says with what, which is the
// next thing anybody asks and the first thing they need.
//
// A SCRIPT WORD, because it needs du. The whole of what runs is
// maintenance_scripts/sysadmin_tools/disk_usage.sh, verified against the
// signed release manifest before it runs as root, with no argv and no stdin.
//
// HOSTILE-CALLER REVIEW (rule 5 of specs/agent_recipes_and_vocabulary.md).
//
// What is the worst a compromised management node can do with this word? Learn
// the SHAPE of the disk: that uploads is 12 GB and logs is 40 MB. That is
// reconnaissance of the same grade host_report already grants, and narrower
// than it in one way that matters — host_report names units and jails, this
// names no file, no owner and no time.
//
// What it cannot do:
//
//   - Point anywhere. NO PARAMETERS: not a path, not a depth, not a count.
//     Params is nil, so a job carrying any field at all is refused on the node
//     before the script is reached, and Args is nil, so there is no argv
//     element for a future edit to make wire-supplied. The tree comes from the
//     script's own location; the machine directories are compiled into it.
//   - Describe content. Directory names and byte counts, and nothing else —
//     no file names, no file counts, no modification times, no owners. "Where
//     did the space go" is answerable without saying what anyone stored, and
//     this word answers only that.
//   - Walk off the filesystem, or off the machine. du -x, always: a bind or
//     network mount under the tree is somebody else's disk.
//   - Flood the plane. Depth two and twenty entries, both bounded in the
//     script, with the agent's 64 KiB cap above them as a backstop that is
//     never the thing that bounds the answer.
//   - Change anything, or cost much. du is a read, and it runs under nice and
//     ionice because walking a large tree on a small box is the one read here
//     that costs the machine something.
//
// It carries no owner switch. It reads no log, no message and no content — the
// thing agent_log_access governs — and a node that will report its units and
// its jails is not made more exposed by reporting the size of a directory.
//
// OBSERVE, and the classification does real work: a node whose policy accepts
// only observe words has to be able to trust that this one writes nothing.
func init() {
	Register(Primitive{
		Name:        "disk_usage",
		Class:       ClassObserve,
		Machine:     true,
		Description: "Where the disk went: the filesystem's figures, the site tree's biggest directories to depth two, and the usual machine directories — sizes only, no file names.",

		// Empty on purpose. See the review above.
		Params: nil,

		Script: &ScriptSpec{
			Interpreter: "/bin/bash",
			ScriptPath:  diskUsageScript,
			Args:        nil,
			StdinFrom:   nil,

			// Every string this script prints is a path it reduced to a safe
			// character set, and every number is a byte count. There is
			// nothing here the redactor would mask and a masked byte count
			// would be an answer corrupted to hide nothing.
			Redact: false,
		},

		// Longer than the other observe words, and this is the reason: du over
		// a large tree on a small box is measured in minutes on a cold cache,
		// where every other read here is measured in milliseconds. The script
		// bounds each walk at four minutes; this bounds the word.
		Timeout: 5 * time.Minute,
	})
}

// diskUsageScript is the shipped walker, site-root relative. A constant so the
// test asserts the same string the registration uses.
const diskUsageScript = "maintenance_scripts/sysadmin_tools/disk_usage.sh"
