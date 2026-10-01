package primitives

// copy_stage: download the chain a dormant copy will apply
// (specs/site_copy.md WP4, G7). The copy's own stage_chain cannot: it accepts
// only artifacts in this machine's own upload ledger, which has never heard
// of its source's runs, and it opens the chain with this machine's own site
// key, which the source's chain is not sealed to. Rather than teach it about
// copies, this word stages the other way:
//
//   - THE MANIFEST is accepted only when its hash is one the source vouched
//     for under this chain id (the vouch copy_import wrote). It is checked
//     before any artifact is fetched, so a substituted manifest costs one
//     small download, not a chain.
//   - EVERY ARTIFACT is checked against the vouched manifest's size and hash.
//   - NO KEY is written: copy_import already wrote chain.key from the export,
//     and this word refuses until it has.
//
// utils/copy_stage.php does the transfer, with BackupFetch, as stage_chain
// does. The vouched hashes and the workspace reach it in argv from here: the
// node reads its own vouch and derives its own workspace, and the plane
// supplies only links.
//
// ClassOperate: downloading into a copy's workspace destroys nothing. Only
// under `quiet copy`, as its two neighbours.
//
// HOSTILE-CALLER REVIEW (rule 5). The worst a compromised management node can
// do is withhold links or serve wrong bytes, and both fail here by name. It
// cannot choose the workspace, the manifest, or which artifacts are used.

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// copyStageScript stages a copy's chain (public_html/utils/copy_stage.php).
const copyStageScript = "public_html/utils/copy_stage.php"

func init() {
	Register(Primitive{
		Name:        "copy_stage",
		Class:       ClassOperate,
		Description: "Download the backup chain a dormant copy will apply, accepting only the manifest its source vouched for.",
		Params: []ParamSpec{
			{Name: "chain_id", Type: ParamString, Required: true, MaxLen: 64, Pattern: chainIDPattern},
			{Name: "manifest_url", Type: ParamString, Required: true, MaxLen: 2048, Pattern: signedURLPattern},
			{Name: "artifact_urls", Type: ParamMap, Required: true,
				MaxEntries: chainLinksMax, MaxKeyLen: 255, MaxLen: 2048,
				KeyPattern: backupFileName,
				Pattern:    signedURLPattern},
			{Name: "seq", Type: ParamInt, Min: 0, Max: 100000},
		},
		Script: &ScriptSpec{
			Interpreter: "/usr/bin/php",
			ScriptPath:  copyStageScript,
			ArgsFrom:    copyStageArgs,
			StdinFrom:   copyStageConfig,
		},
		Timeout:     2*time.Hour + 20*time.Minute,
		Quiet:       QuietCopy,
		ParamsBytes: ChainParamsBytes,
	})
}

func copyStageArgs(ctx context.Context, env *ExecEnv, params Params) ([]string, error) {
	if env == nil || env.SiteRoot == "" {
		return nil, refusedf("copy_stage: this machine has no site to stage for")
	}
	st, err := ReadSiteState(env)
	if err != nil {
		return nil, refusedf("copy_stage: %v", err)
	}
	if st.Reason != "copy" {
		return nil, refusedf("copy_stage runs only on a dormant copy (quiet copy), and this site is not one. " +
			"A site's own chains are staged with stage_chain")
	}
	chainID := params.String("chain_id")
	vouched, err := vouchedManifests(env, chainID)
	if err != nil {
		return nil, refusedf("copy_stage: %v", err)
	}
	if len(vouched) == 0 {
		return nil, refusedf("the source vouched for no run of chain %s, so it will not be downloaded. "+
			"Export it from the source and import it here first", chainID)
	}
	work := chainWorkspace(ctx, env, chainID)
	if info, err := os.Stat(filepath.Join(work, chainKeyFile)); err != nil || !info.Mode().IsRegular() {
		return nil, refusedf("chain %s has no key here yet (%s): it is written when the source's export is "+
			"imported (copy_import), which comes first", chainID, filepath.Join(work, chainKeyFile))
	}
	argv := []string{"--workspace", work}
	for _, v := range vouched {
		argv = append(argv, "--vouched", v)
	}
	return argv, nil
}

func copyStageConfig(params Params) (string, error) {
	config := map[string]interface{}{
		"chain_id":      params.String("chain_id"),
		"manifest_url":  params.String("manifest_url"),
		"artifact_urls": params.Map("artifact_urls"),
	}
	if params.Has("seq") {
		config["seq"] = params.Int("seq")
	}
	body, err := json.Marshal(config)
	if err != nil {
		return "", err
	}
	return string(body), nil
}
