package primitives

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

// restore_chain: restore this node from an incremental backup chain — the full,
// then every incremental up to a chosen run, applied in order, then that run's
// database dump.
//
// Chains are what the fleet actually produces, so this is the restore that
// matters most; it is also the one whose SSH shape was largest. The plane
// composed SIX steps around the script: make a workspace, download the chain
// manifest through a heredoc'd uploader program, open the chain envelope, run a
// python program built on the plane to decide which artifacts the manifest
// names, download each of them, take a pre-restore dump. Only the seventh was
// the restore.
//
// THIS PRIMITIVE IS THE SEVENTH STEP AND SAYS SO. A primitive runs one script,
// and the one script that does the restore is restore_chain.sh. So this does not
// silently do less than the SSH path did — it REFUSES, naming what is missing,
// when the workspace the earlier steps would have built is not on the node. See
// restoreChainArgs. Building the other six back is the dispatch round's work,
// and the shape it should take is one node-side script that opens the envelope,
// downloads what the manifest names, and calls restore_chain.sh — one program,
// one manifest entry, one primitive, and the artifact list stops being a python
// program the control plane composes.
//
// THE KEY IS RECOVERED ON THE NODE, WHICH IS ALREADY TRUE. Every chain seals to
// the node as well as to the control plane's recovery key, precisely so a node
// can open its own backups without anybody's private key travelling — the plane
// opened the envelope with the NODE's backup_site_key even over SSH, and its own
// recovery private key never left it. Nothing about that changes here; what
// changes is that the plane can no longer name the file the key is written to,
// or the directory the artifacts are read from. Both are derived below from the
// chain id, which is pattern-bound.
func init() {
	Register(Primitive{
		Name:        "restore_chain",
		Class:       ClassDestructive,
		Description: "Restore this node from one of its own incremental backup chains.",
		Params: []ParamSpec{
			// Which project the chain is restored into. Same bound as
			// restore_project: one directory segment, no separator.
			{Name: "project", Type: ParamString, Required: true, MaxLen: 128,
				Pattern: regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)},

			// Which chain. The pattern is the plane's own
			// (JobCommandBuilder validates /^chain-[0-9_]+$/), and it matters
			// twice as much here because this value becomes a directory NAME:
			// no separator and no dot means the workspace below can only ever
			// be one directory inside the node's own backup base.
			{Name: "chain_id", Type: ParamString, Required: true, MaxLen: 64,
				Pattern: regexp.MustCompile(`^chain-[0-9_]+$`)},

			// Restore as at this run rather than the newest. Bounded: a chain
			// with a hundred thousand runs does not exist, and an unbounded
			// integer here is an argument nobody checked.
			{Name: "seq", Type: ParamInt, Min: 0, Max: 100000},

			// Files only. Unlike restore_project's skip flags this one is in
			// the vocabulary because a chain restore has a legitimate
			// files-only use — recovering a tree onto a node whose database is
			// already the one you want.
			{Name: "skip_database", Type: ParamBool},

			// NO PROFILE, deliberately, and it is not an oversight: the
			// profile decides which shelf in the BUCKET a chain is read from,
			// which is work that has already happened by the time anything is
			// on this node. The workspace is restore_<chain_id> under the
			// node's backup base whichever profile the chain came from, which
			// is exactly where the SSH path put it.
		},
		Script: &ScriptSpec{
			Interpreter: "/bin/bash",
			ScriptPath:  restoreChainScript,
			ArgsFrom:    restoreChainArgs,
			StdinFrom:   nil,
		},
		// The SSH restore step allowed 7200s, and it is the one budget here
		// that is genuinely used: a chain restore verifies every artifact
		// against its recorded size and hash before writing anything, then
		// applies a full plus every incremental in order. Plus slack.
		Timeout: 2*time.Hour + 20*time.Minute,
	})
}

// restoreChainScript is site-root relative and outside public_html, so it
// verifies against the core release manifest.
const restoreChainScript = "maintenance_scripts/sysadmin_tools/restore_chain.sh"

func restoreChainArgs(ctx context.Context, env *ExecEnv, params Params) ([]string, error) {
	chainID := params.String("chain_id")
	work := chainWorkspace(ctx, env, chainID)

	// The two things the earlier steps would have left behind. Checked here,
	// before a root process starts, so the answer names what is missing instead
	// of arriving as restore_chain.sh's "--key-file is required" — which is
	// true, and tells an operator nothing about why.
	manifest := filepath.Join(work, chainManifestFile)
	if info, err := os.Stat(manifest); err != nil || !info.Mode().IsRegular() {
		return nil, refusedf("this node has no downloaded chain at %s: %s is missing. "+
			"Downloading a chain's artifacts is not yet something this agent can do on its own — "+
			"it needs the node-side step that reads the chain manifest and fetches what it names",
			work, chainManifestFile)
	}

	key := filepath.Join(work, chainKeyFile)
	if info, err := os.Stat(key); err != nil || !info.Mode().IsRegular() {
		return nil, refusedf("the chain at %s has no recovered data key (%s). "+
			"It is recovered on this node from this node's own backup_site_key, with "+
			"backup_envelope.php open against the chain manifest — a step this agent cannot yet "+
			"run on its own. No key may be sent to it: a key on the wire is a key in every stored job",
			work, chainKeyFile)
	}

	argv := []string{
		params.String("project"),
		"--artifacts", work,
		"--key-file", key,
		// Same reason as restore_project: there is no terminal to confirm at.
		// Compiled in rather than offered, because unlike restore_project this
		// script's prompt is not the plane's decision to make — a chain restore
		// reaching this point has already been approved at the ceiling.
		"--force",
	}
	if params.Has("seq") {
		argv = append(argv, "--seq", formatSeq(params.Int("seq")))
	}
	if params.Bool("skip_database") {
		argv = append(argv, "--skip-database")
	}
	return argv, nil
}
