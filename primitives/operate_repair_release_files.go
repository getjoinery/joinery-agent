package primitives

import (
	"context"
	"fmt"
	"time"
)

// repair_release_files: put every deployment file that differs from the signed
// release back, in one word with no parameters (specs/release_file_repair_by_hash.md).
//
// Why it exists: a node whose five self-update files do not match its installed
// manifest cannot upgrade, and the upgrade is the only other thing that would
// repair them. restore_release_file does one named file on demand; this does
// all of them, and because it takes no parameter it is a word a compiled recipe
// may run (recipe release_files, every ten minutes), so the node puts itself
// right instead of waiting for a person to click five times, or to log in.
//
// Each file is restored exactly as restore_release_file restores it
// (restoreReleaseFile): the kept copy when one verifies, else the management
// node asked for the file by the hash the manifest lists; bytes that do not
// hash to the manifest's value are refused; the file replaced is kept.
//
// REFUSED on a site that is a source checkout (IsSourceCheckout: the publishing
// site, a developer's box, whose deployment files legitimately differ from the
// last published manifest between publishes), when the manifest is unusable
// (manifestheal.go's case) and when every file already matches (nothing to
// repair). A file that cannot be restored is
// named in `failed` with its reason; the word fails outright only when nothing
// at all could be put back, so a plane job and the recipe both learn exactly
// what remains.
//
// HOSTILE-CALLER REVIEW (rule 5). The same as restore_release_file's, five
// times over: the worst a compromised management node can do is have the five
// release files put back to the bytes the publisher signed, which is the effect
// of their never having been changed. No path, version or source can be named.
// Accepted.
func init() {
	Register(Primitive{
		Name:        "repair_release_files",
		Class:       ClassOperate,
		Description: "Put every one of the five deployment files an upgrade replaces first that differs from the installed signed release back to the bytes it signed, keeping each file replaced.",
		Params:      nil,
		Run:         runRepairReleaseFiles,
		Timeout:     10 * time.Minute,
	})
}

func runRepairReleaseFiles(ctx context.Context, env *ExecEnv, _ Params) (map[string]interface{}, error) {
	if env != nil && IsSourceCheckout(env.SiteRoot) {
		return nil, refusedf("cannot repair the deployment files: this site is a source checkout (a .git at its root), so its files are the developer's and nothing here writes release bytes over them")
	}
	artifacts, err := releaseManifest(env)
	if err != nil {
		return nil, refusedf("cannot repair the deployment files: %v", err)
	}
	names, checked := DifferingSelfUpdateFiles(env)
	if !checked {
		return nil, refusedf("cannot repair the deployment files: the manifest cannot be used")
	}
	if len(names) == 0 {
		return nil, refusedf("every deployment file matches the signed release; nothing to repair")
	}
	version := InstalledVersion(env)

	restored := []map[string]interface{}{}
	failed := []map[string]interface{}{}
	for _, rel := range names {
		res, err := restoreReleaseFile(ctx, env, artifacts, version, rel)
		if err != nil {
			failed = append(failed, map[string]interface{}{"file": rel, "reason": err.Error()})
			continue
		}
		restored = append(restored, map[string]interface{}{
			"file":          rel,
			"source":        res["source"],
			"replaced_kept": res["replaced_kept"],
		})
	}
	if len(restored) == 0 {
		return nil, fmt.Errorf("none of the %d differing deployment files could be put back: %s",
			len(names), failed[0]["reason"])
	}
	return map[string]interface{}{
		"ok":       len(failed) == 0,
		"version":  version,
		"restored": restored,
		"failed":   failed,
	}, nil
}
