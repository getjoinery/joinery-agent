package primitives

import (
	"context"
	"time"
)

// restore_release_file {file}: put one deployment file back to the bytes the
// installed release signed (specs/release_file_repair.md, and the hash-first
// fetch of specs/release_file_repair_by_hash.md).
//
// Why it exists: an upgrade that stopped before deploying can leave one of the
// five self-update files different from the installed manifest. The agent then
// refuses to run upgrade.php, and the upgrade that would repair it is refused by
// that same check. The agent's own guard (release_files.go) puts the files back
// after a stopped upgrade; this word is for a node that is already in that
// state, or whose copies were lost. repair_release_files is the same for every
// differing file at once, and recipe release_files runs that on the node's own
// clock, so a node in this state does not wait for a person.
//
// `file` is one of the five names, a closed set compiled into the agent (rule
// 1): no path arrives from the wire.
//
// THE BYTES come from this agent's own kept copy when one verifies against the
// manifest, and otherwise from the management node, asked for the file by the
// sha256 the manifest lists (ExecEnv.FetchReleaseFile). Where they came from
// does not matter to what is written: the sha256 the installed, key-verified
// manifest lists for that exact path decides, and bytes that do not hash to it
// are refused. The site's VERSION is a hint for the plane and a label in the
// result; a node whose VERSION cannot be read is still repaired.
//
// REFUSED when the file already matches (nothing to repair), when the manifest
// itself is unusable (manifestheal.go's case, whose remedy is the opposite: a
// new manifest, not a new file), when no source has a verifying copy, and on a
// site that is a source checkout (IsSourceCheckout: the publishing site, a
// developer's box), whose files are the developer's.
//
// WHAT IT KEEPS. The file it replaces is saved under
// /etc/joinery-agent/release-files/replaced/, because a modified file in a
// root-run path is evidence as well as a fault, and repairing it must not erase
// the only copy.
//
// HOSTILE-CALLER REVIEW (rule 5).
//
// What is the worst a compromised management node can do with this word? Have
// one of five release files put back to the bytes the publisher signed. It
// cannot name a path, a version or a source of bytes; offering the wrong bytes
// restores nothing. The same effect as the file never having been changed.
// Accepted.
//
// What it does not do: read anything. The result names the file, where the bytes
// came from, and two hashes.
func init() {
	Register(Primitive{
		Name:        "restore_release_file",
		Class:       ClassOperate,
		Description: "Put one of the five deployment files an upgrade replaces first (upgrade.php and its four companions) back to the bytes the installed release signed, keeping the file it replaces.",
		Params: []ParamSpec{{
			Name:     "file",
			Type:     ParamEnum,
			Required: true,
			Values:   SelfUpdateFiles,
		}},
		Run:     runRestoreReleaseFile,
		Timeout: 5 * time.Minute,
	})
}

func runRestoreReleaseFile(ctx context.Context, env *ExecEnv, p Params) (map[string]interface{}, error) {
	rel := p.String("file")
	if !IsSelfUpdateFile(rel) {
		return nil, refusedf("%s is not a file this word restores", rel)
	}
	if env != nil && IsSourceCheckout(env.SiteRoot) {
		return nil, refusedf("cannot restore %s: this site is a source checkout (a .git at its root), so its files are the developer's and nothing here writes release bytes over them", rel)
	}
	artifacts, err := releaseManifest(env)
	if err != nil {
		return nil, refusedf("cannot restore %s: %v", rel, err)
	}
	return restoreReleaseFile(ctx, env, artifacts, InstalledVersion(env), rel)
}
