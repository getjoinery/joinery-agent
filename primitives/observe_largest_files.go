package primitives

import "time"

// largest_files: this site's biggest files, by name — the question disk_usage
// leaves open. disk_usage says static_files holds 800 MB; this says which
// files they are, so "is that release archives, an old engine build, or
// somebody's video" has an answer without a shell on the box.
//
// A SCRIPT WORD, because it needs find. The whole of what runs is
// maintenance_scripts/sysadmin_tools/largest_files.sh, verified against the
// signed release manifest before it runs as root, with no argv and no stdin.
//
// HOSTILE-CALLER REVIEW (rule 5 of specs/agent_recipes_and_vocabulary.md).
//
// What is the worst a compromised management node can do with this word?
// Learn the names, sizes and days of this site's twenty-five biggest files.
// A file name can say what somebody stored, which is why the word is behind
// the site owner's log-access switch (RequiresLogAccess) like every other
// word that carries text the node did not compose, and why its output goes
// through the redactor.
//
// What it cannot do:
//
//   - Point anywhere. NO PARAMETERS: not a path, not a count, not a size.
//     The trees are the script's own site and that site's folder on the data
//     root; another site on the same host is never walked.
//   - Read a file. find reports a name, a size and a day; no byte of any
//     file's content is opened.
//   - Name the site's secrets. config/ is pruned from the walk.
//   - Flood the plane. Twenty-five files and a count of the rest, bounded in
//     the script, with the agent's output cap above as a backstop.
//   - Walk off the filesystem, change anything, or cost much: find -xdev
//     under nice and ionice.
//
// OBSERVE: a node whose policy accepts only observe words can trust that this
// one writes nothing. Not a machine word: on a host with no site of its own
// the script would have no site to walk.
func init() {
	Register(Primitive{
		Name:              "largest_files",
		Class:             ClassObserve,
		RequiresLogAccess: true,
		Description:       "This site's biggest files: the twenty-five of a megabyte or more in the site tree and its data-root folder, with sizes and days, config excluded.",

		// Empty on purpose. See the review above.
		Params: nil,

		Script: &ScriptSpec{
			Interpreter: "/bin/bash",
			ScriptPath:  largestFilesScript,
			Args:        nil,
			StdinFrom:   nil,

			// File names are text the node did not compose: a name can carry
			// an address or a token, so they go through the redactor.
			Redact: true,
		},

		// A walk of a large tree on a small box is minutes on a cold cache.
		// The script bounds each walk at four minutes; this bounds the word.
		Timeout: 9 * time.Minute,
	})
}

// largestFilesScript is the shipped walker, site-root relative. A constant so
// the test asserts the same string the registration uses.
const largestFilesScript = "maintenance_scripts/sysadmin_tools/largest_files.sh"
