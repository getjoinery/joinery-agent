package primitives

import (
	"context"
	"time"
)

// restore_release_file {file}: put one deployment file back to the bytes the
// installed release signed (specs/release_file_repair.md).
//
// Why it exists: an upgrade that stopped before deploying can leave one of the
// five self-update files different from the installed manifest. The agent then
// refuses to run upgrade.php, and the upgrade that would repair it is refused by
// that same check. The agent's own guard (release_files.go) puts the files back
// after a stopped upgrade; this word is for a node that is already in that
// state, or whose copies were lost.
//
// `file` is one of the five names, a closed set compiled into the agent (rule
// 1): no path arrives from the wire.
//
// THE BYTES come from this agent's own kept copy when one verifies against the
// manifest, and otherwise from the management node, which reads the file out of
// the published core archive of the installed version (ExecEnv.FetchReleaseFile).
// Where they came from does not matter to what is written: the sha256 the
// installed, key-verified manifest lists for that exact path decides, and bytes
// that do not hash to it are refused.
//
// REFUSED when the file already matches (nothing to repair), when the manifest
// itself is unusable (manifestheal.go's case, whose remedy is the opposite: a
// new manifest, not a new file), when the VERSION cannot be read, and when no
// source has a verifying copy.
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
	artifacts, err := releaseManifest(env)
	if err != nil {
		return nil, refusedf("cannot restore %s: %v", rel, err)
	}
	version := InstalledVersion(env)
	if version == "" {
		return nil, refusedf("cannot restore %s: the site's VERSION cannot be read, so the release it belongs to is not known", rel)
	}
	want, err := artifacts.ExpectedHash(rel)
	if err != nil {
		return nil, refusedf("cannot restore %s: %v", rel, err)
	}
	if b, err := readSelfUpdateFile(env, rel); err == nil && relSHA(b) == want {
		return nil, refusedf("%s already matches the signed release; nothing to restore", rel)
	}

	body, source := []byte(nil), ""
	if b, ok := snapshotBytes(version, rel, want); ok {
		body, source = b, "kept copy"
	} else if env.FetchReleaseFile != nil {
		b, err := env.FetchReleaseFile(ctx, version, rel)
		if err != nil {
			return nil, refusedf("cannot restore %s: no kept copy, and the management node could not supply it: %v", rel, err)
		}
		if relSHA(b) != want {
			return nil, refusedf("cannot restore %s: the bytes the management node offered are not the file the signed manifest lists", rel)
		}
		body, source = b, "management node"
	} else {
		return nil, refusedf("cannot restore %s: no kept copy, and this agent has no way to ask for one", rel)
	}

	replaced, err := WriteReleaseFile(env.SiteRoot, rel, body, want)
	if err != nil {
		return nil, err
	}
	result := map[string]interface{}{
		"file":    rel,
		"version": version,
		"source":  source,
		"sha256":  want,
	}
	if len(replaced) > 0 {
		result["replaced_sha256"] = relSHA(replaced)
		result["replaced_kept"] = true
	} else {
		result["replaced_kept"] = false
	}
	return result, nil
}
