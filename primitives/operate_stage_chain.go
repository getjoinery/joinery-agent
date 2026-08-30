package primitives

import (
	"encoding/json"
	"regexp"
	"time"
)

// stage_chain: put an incremental backup chain back on this node, ready for
// restore_chain to replay it.
//
// WHY THIS EXISTS AT ALL. Chains are what the fleet actually produces — every
// node with a backup policy inherits chain mode — so this is the staging the
// common restore needs, not an option for the unusual case. restore_chain says
// so in its own file: the SSH path composed SIX steps around the script, and
// the primitive is the seventh and refuses when the other six have not happened.
// This is the other six, as one program on the node.
//
// ClassOperate. Downloading a chain into a fresh workspace destroys nothing —
// no schema is dropped, no tree replaced, nothing already on the machine is
// overwritten. That separation is the point: staging can happen with no approval
// at all, and the destructive half stays as small as it can be. It also means an
// operator can stage a chain, look at what arrived, and then decide.
//
// WHAT MOVED OFF THE PLANE, and it is more than step count. The plane used to
// build a Python program that read the manifest and worked out which artifacts a
// given run needs, then ship it to be run on the node. That made the chain
// layout a thing TWO implementations computed, free to drift, with the
// authoritative one on the machine that did not write the chain. Here the
// manifest is read by the machine that wrote it, with the same BackupChain code
// that produced it, and the caller supplies links keyed by bare artifact name
// with no say in which are used.
//
// NO KEY CROSSES, which is unchanged and load-bearing. The chain data key is
// recovered on the node, from the node's own config/backup_site_key, against the
// envelope inside the manifest — every chain seals to the node as well as to the
// management node's recovery key precisely so this can happen without anybody's
// private key travelling. There is no parameter below through which key material
// could arrive, so a job carrying one is refused by Validate. A chain that does
// not open with this machine's own key belongs to a different machine, and the
// script says so rather than asking for a better key.
//
// NO BUCKET CREDENTIAL CROSSES either: pre-signed links, one object each,
// expiring. See download_backup, which states the whole of that argument.
func init() {
	Register(Primitive{
		Name:        "stage_chain",
		Class:       ClassOperate,
		Description: "Download one of this node's own backup chains and recover its data key, ready to restore.",
		Params: []ParamSpec{
			// The chain, by id. The same pattern the plane validates and
			// restore_chain binds, and it matters as much here because the id
			// becomes a DIRECTORY NAME: no separator and no dot means the
			// workspace can only ever be one directory inside the node's own
			// backup base.
			{Name: "chain_id", Type: ParamString, Required: true, MaxLen: 64,
				Pattern: regexp.MustCompile(`^chain-[0-9_]+$`)},

			// Which shelf the chain came from. Needed here and NOT in
			// restore_chain, and the difference is real: the profile decides
			// which ledger the artifacts are checked against, which is work
			// that happens while they are arriving. By the time restore_chain
			// runs, everything is in one workspace and the question is settled.
			{Name: "profile", Type: ParamEnum, Required: true,
				Values: []string{"site", "manager"}},

			// The manifest's own signed link. Fetched first, because it names
			// every artifact with the size and hash each must match and carries
			// the sealed data keys — a directory of files-0003.tar.gz.enc
			// without it is not a backup.
			{Name: "manifest_url", Type: ParamString, Required: true, MaxLen: 2048,
				Pattern: signedURLPattern},

			// Signed links for the chain's objects, keyed by bare artifact
			// name. A MAP rather than a list, and keyed by name rather than
			// ordered, because the node decides which ones it needs after
			// reading the manifest: the plane supplies what it can sign and has
			// no say in what is used. A key with a separator in it is the
			// caller naming a path again, and the script refuses it.
			// Bounded in four directions: how many links, how long a name may
			// be, how long a link may be, and (by MaxParamsBytes, applied to
			// the whole object) how large the job may get. A chain here runs a
			// week before a fresh full, so ten or so artifacts is the real
			// shape; the cap is well above that and well under the job ceiling.
			{Name: "artifact_urls", Type: ParamMap, Required: true,
				MaxEntries: 64, MaxKeyLen: 255, MaxLen: 2048,
				KeyPattern: backupFileName,
				Pattern:    signedURLPattern},

			// Restore as at this run rather than the newest — the same bound
			// restore_chain declares, so a chain staged for run N is a chain
			// restore_chain can be asked for run N of.
			{Name: "seq", Type: ParamInt, Min: 0, Max: 100000},
		},
		Script: &ScriptSpec{
			Interpreter: "/usr/bin/php",
			ScriptPath:  "public_html/utils/stage_chain.php",
			Args:        nil,
			StdinFrom:   stageChainConfig,
		},
		// A chain is a full plus every incremental, so this is the largest
		// transfer in the vocabulary — more than one archive, each of them
		// possibly gigabytes. The SSH path allowed S3Signer's transfer budget
		// plus an hour for exactly this step; that number, plus slack.
		Timeout: 2*time.Hour + 20*time.Minute,
	})
}

// stageChainConfig renders the script's configuration from validated params.
func stageChainConfig(params Params) (string, error) {
	config := map[string]interface{}{
		"chain_id":      params.String("chain_id"),
		"profile":       params.String("profile"),
		"manifest_url":  params.String("manifest_url"),
		"artifact_urls": params.Map("artifact_urls"),
	}
	// Absent means "the newest run", and it means it more clearly by being
	// absent than by being a default the script has to interpret.
	if params.Has("seq") {
		config["seq"] = params.Int("seq")
	}

	body, err := json.Marshal(config)
	if err != nil {
		return "", err
	}
	return string(body), nil
}
