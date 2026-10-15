package recipes

import (
	"context"
	"fmt"

	"joinery-agent/primitives"
)

// Recipe release_files: the deployment files an upgrade starts from match the
// signed release, or they are put back (specs/release_file_repair_by_hash.md).
//
// Why a recipe. A node whose five self-update files (utils/upgrade.php and its
// four companions) do not match its installed manifest cannot run an upgrade,
// and an upgrade is the only other thing that would repair them. Before this
// recipe the way out was a person: the Restore signed copy button on the node's
// page, or, when that too was refused, a shell. A stuck node is the worst state
// this system has, so the node now puts itself right on its own clock: the
// check every ten minutes, the repair after two failing checks in a row, a case
// when three repairs do not take.
//
// The check is upgrade_preflight (observe, no parameters), read for two of its
// facts only: `manifest` and `files`. Its other checks (disk, theme, lock,
// VERSION) are a rollout's business, not this recipe's, and never make it fail.
// The repair is repair_release_files (operate, no parameters): each differing
// file back to the bytes the manifest lists, from the kept copy or from the
// management node asked by hash, and nothing written that does not hash to the
// manifest's value. Verify is the check again.
//
// The reading of the check:
//
//   - the manifest is usable and every file matches: PASS.
//   - the manifest is usable and a file differs: FAIL, naming the files.
//   - the manifest is unusable: UNKNOWN. That is the manifest healer's case
//     (manifestheal.go), whose remedy is a new manifest, not new files, and a
//     repair here would be refused for the same reason. Never repaired.
//   - the word refused or failed: UNKNOWN, never repaired.
//
// Release-scoped (ScopeRelease): the five files live in a site tree, so a
// machine with no site has none to check; and a site that is a SOURCE CHECKOUT
// (a .git at its root: the publishing site, a developer's box) is never ticked,
// because there a deployment file legitimately differs from the last published
// manifest between publishes, and the repair would write the released bytes
// over the developer's edit. The words refuse there too (release_files.go
// IsSourceCheckout), so the rule holds with or without the recipe. Both words
// carry their own hostile-caller review; this recipe adds no surface: no
// parameter, no value of its own, and a repair that can only ever write bytes
// the publisher signed.
func init() {
	Register(Recipe{
		Name:        "release_files",
		Scope:       ScopeRelease,
		Description: "The five deployment files an upgrade starts from match the signed release; otherwise put back the bytes the release signed, from the kept copy or the management node.",
		MinInterval: TickInterval,
		CheckWord:   "upgrade_preflight",
		RepairWord:  "repair_release_files",
		Check: func(ctx context.Context, env *Env) Verdict {
			result, err := env.Run(ctx, "upgrade_preflight")
			return releaseFilesVerdict(result, err)
		},
		Repair: func(ctx context.Context, env *Env) (string, error) {
			result, err := env.Run(ctx, "repair_release_files")
			return repairReleaseFilesOutcome(result, err)
		},
	})
}

// preflightCheck finds one named check in an upgrade_preflight result, as the
// word returns it in-process ([]map) or after a round trip ([]interface{}).
func preflightCheck(result map[string]interface{}, name string) (ok bool, reason string, found bool) {
	read := func(c map[string]interface{}) bool {
		if c["check"] != name {
			return false
		}
		ok, _ = c["ok"].(bool)
		reason, _ = c["reason"].(string)
		return true
	}
	switch checks := result["checks"].(type) {
	case []map[string]interface{}:
		for _, c := range checks {
			if read(c) {
				return ok, reason, true
			}
		}
	case []interface{}:
		for _, x := range checks {
			if c, isMap := x.(map[string]interface{}); isMap && read(c) {
				return ok, reason, true
			}
		}
	}
	return false, "", false
}

// releaseFilesVerdict reads an upgrade_preflight result into a verdict about
// the deployment files alone.
func releaseFilesVerdict(result map[string]interface{}, err error) Verdict {
	if err != nil {
		if primitives.Refused(err) {
			return Verdict{Unknown, "upgrade_preflight refused: " + err.Error()}
		}
		return Verdict{Unknown, "upgrade_preflight failed: " + err.Error()}
	}
	manifestOK, manifestReason, found := preflightCheck(result, "manifest")
	if !found {
		return Verdict{Unknown, "upgrade_preflight did not say whether the manifest is usable"}
	}
	if !manifestOK {
		return Verdict{Unknown, "the signed manifest cannot be used, which is the manifest healer's case, not this recipe's: " + manifestReason}
	}
	filesOK, filesReason, found := preflightCheck(result, "files")
	if !found {
		return Verdict{Unknown, "upgrade_preflight did not say whether the deployment files match"}
	}
	if !filesOK {
		return Verdict{Fail, filesReason}
	}
	return Verdict{Pass, filesReason}
}

// repairReleaseFilesOutcome reads a repair_release_files result: which files
// were put back and from where, and a failure naming what remains.
func repairReleaseFilesOutcome(result map[string]interface{}, err error) (string, error) {
	if err != nil {
		return "", err
	}
	detail := ""
	switch restored := result["restored"].(type) {
	case []map[string]interface{}:
		for _, r := range restored {
			detail += fmt.Sprintf("%v from the %v; ", r["file"], r["source"])
		}
	case []interface{}:
		for _, x := range restored {
			if r, isMap := x.(map[string]interface{}); isMap {
				detail += fmt.Sprintf("%v from the %v; ", r["file"], r["source"])
			}
		}
	}
	if detail == "" {
		return "", fmt.Errorf("repair_release_files put nothing back")
	}
	if ok, _ := result["ok"].(bool); !ok {
		return detail, fmt.Errorf("repair_release_files put back %sbut a file remains that it could not", detail)
	}
	return "put back " + detail, nil
}
