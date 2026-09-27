package primitives

// copy_restore: apply a staged backup chain of the site this machine is a
// dormant copy of (specs/site_copy.md WP2). restore_chain.sh does the work,
// with two flags the ordinary restore never passes:
//
//   - --adopt-secret-key: this machine keeps its own Globalvars_site.php and
//     takes the source's secret_box_key into it, so what the source sealed
//     opens here;
//   - --skip-ssl: the reconcile arms no certificate retry. The certificate
//     travels with the copy, and a copy asks Let's Encrypt for nothing.
//
// It shares the workspace, the project check and the argv shape with
// restore_chain (restore_paths.go), and differs in three things:
//
//   - WHERE IT RUNS. Only under `quiet copy`, which only the dormant install
//     sets. The dispatcher refuses it under `quiet switchover` (Quiet:
//     QuietCopy); copyRestoreArgs refuses it on a live site.
//   - WHY THE MANIFEST IS TRUSTED. Not this machine's upload ledger, which has
//     never heard of its source's runs, but the source's vouch: the runs the
//     source listed for this copy, recorded in this site's state directory
//     (copyVouchedFile). The manifest fixes every artifact's size and hash,
//     and restore_chain.sh checks them all before it writes anything.
//   - NO APPROVAL, so it is an operate word. The restore approval guards a
//     machine that holds someone's data from a management node choosing its
//     bytes. A dormant copy holds nothing of its own, its bytes are vouched
//     for by the source, and the owner approved at the source, where the
//     secrets leave.
//
// HOSTILE-CALLER REVIEW (rule 5).
//
// What is the worst a compromised management node can do with this word?
// Apply an older vouched run to a copy, or apply one again. The copy is
// dormant, so nothing it holds is anyone's yet, and every apply replays the
// chain from its full. The final copy is checked against the frozen source by
// the census (WP3) before the switch, which is where an older run would show.
//
// What it cannot do:
//
//   - Restore over a live site, or a frozen source: the state gate. The agent
//     can set only `quiet switchover`; `quiet copy` comes from the installer.
//   - Choose the bytes: a manifest the source did not vouch for is refused.
//   - Name a path or a database: the workspace comes from the chain id, the
//     project is this machine's own (restoreChainProject).

import (
	"bufio"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// copyVouchedFile is, in this site's state directory, the runs a dormant copy
// may apply: one line per run, `<manifest sha256> <chain id>`. It is written
// by the step that opens the source's signed export and checks it (WP4), and
// removed with the rest of the state when the copy is promoted. Root's
// directory, so nothing the site runs can add a line.
const copyVouchedFile = "vouched"

func init() {
	Register(Primitive{
		Name:        "copy_restore",
		Class:       ClassOperate,
		Description: "Apply a staged backup chain of the site this machine is a dormant copy of, taking that site's secret key.",
		Params: []ParamSpec{
			// This machine's own project, cross-checked as restore_chain's is.
			{Name: "project", Type: ParamString, Required: true, MaxLen: 128,
				Pattern: regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)},
			// Which chain; it names the workspace, so no separator and no dot.
			{Name: "chain_id", Type: ParamString, Required: true, MaxLen: 64,
				Pattern: regexp.MustCompile(`^chain-[0-9_]+$`)},
			// Apply as at this run rather than the newest.
			{Name: "seq", Type: ParamInt, Min: 0, Max: 100000},
		},
		Script: &ScriptSpec{
			Interpreter: "/bin/bash",
			ScriptPath:  restoreChainScript,
			ArgsFrom:    copyRestoreArgs,
		},
		// restore_chain's work budget, without its approval window.
		Timeout: 2*time.Hour + 20*time.Minute,
		Quiet:   QuietCopy,
	})
}

func copyRestoreArgs(ctx context.Context, env *ExecEnv, params Params) ([]string, error) {
	if env == nil || env.SiteRoot == "" {
		return nil, refusedf("copy_restore: this machine has no site to restore into")
	}
	st, err := ReadSiteState(env)
	if err != nil {
		return nil, refusedf("copy_restore: %v", err)
	}
	if st.Reason != "copy" {
		return nil, refusedf("copy_restore runs only on a dormant copy (quiet copy), and this site is not one. " +
			"A site's own backups come back with restore_chain, under its owner's approval")
	}

	chainID := params.String("chain_id")
	work := chainWorkspace(ctx, env, chainID)
	if err := requireChainFiles(work,
		"a copy's chain is downloaded under its source's name, and its data key opened from the source's sealed export"); err != nil {
		return nil, err
	}
	if err := requireVouched(env, chainID, filepath.Join(work, chainManifestFile)); err != nil {
		return nil, err
	}
	project, err := restoreChainProject(env, params)
	if err != nil {
		return nil, err
	}

	argv := []string{
		project,
		"--artifacts", work,
		"--key-file", filepath.Join(work, chainKeyFile),
		"--force",
		"--adopt-secret-key",
		"--skip-ssl",
	}
	if params.Has("seq") {
		argv = append(argv, "--seq", formatSeq(params.Int("seq")))
	}
	return argv, nil
}

// requireVouched refuses unless the staged manifest is one the source vouched
// for under this chain id.
//
// A record anything but root could have written vouches for nothing, and is
// refused as the upload ledger is (writable by group or other).
func requireVouched(env *ExecEnv, chainID, manifest string) error {
	path := filepath.Join(siteStateDir(env), copyVouchedFile)
	info, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return refusedf("this copy has no runs vouched for by its source (%s is absent), so it will not "+
			"apply chain %s: the vouch is written when the source's signed export is opened", path, chainID)
	}
	if err != nil {
		return refusedf("cannot read this copy's vouched runs (%s): %v", path, err)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return refusedf("this copy's vouched runs (%s) are writable by other accounts (mode %04o), "+
			"so they vouch for nothing; chain %s is not applied", path, info.Mode().Perm(), chainID)
	}

	sum, err := hashFile(manifest)
	if err != nil {
		return refusedf("could not read the staged manifest of chain %s to check it: %v", chainID, err)
	}

	f, err := os.Open(path)
	if err != nil {
		return refusedf("cannot read this copy's vouched runs (%s): %v", path, err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) == 2 && fields[0] == sum && fields[1] == chainID {
			return nil
		}
	}
	if err := sc.Err(); err != nil {
		return refusedf("cannot read this copy's vouched runs (%s): %v", path, err)
	}
	return refusedf("the staged manifest of chain %s (%s…) is not one the source vouched for; "+
		"this copy applies only runs its source listed for it", chainID, short(sum))
}
