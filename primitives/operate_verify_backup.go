package primitives

import (
	"encoding/json"
	"regexp"
	"time"
)

// verify_backup: prove one of this node's own backups can be recovered,
// without restoring it.
//
// WHY THIS EXISTS. A backup that has never been opened is a hope. The shelf
// listing proves a backup is present; restore_chain's dry run proves it is
// intact against its manifest; stage_chain proves this machine's own key opens
// the envelope. Nothing proved the archives themselves could be read to the
// end, or that a restore of them would produce a tree and a database, short of
// restoring over the live site. This is that proof, run as a job the node
// performs on itself, the way a backup is.
//
// TWO LEVELS, both non-destructive. Level 2 stages the set a restore of the
// run would need and decrypts every artifact to a pipe, reading it to the end.
// Level 3 does that and then replays the files into a scratch directory under
// the backup working area and loads the dump into a throwaway database on the
// node's own PostgreSQL, counts what came back, and deletes both. Level 1 —
// the shelf check — is the plane's and needs no job.
//
// ClassOperate, and that classification is doing real work: nothing on the
// live site is touched at either level, so a verify needs no approval and can
// run unattended on a schedule — which is the point of it. A future change
// that made a level touch the live tree or the live database would be turning
// a proof into a restore, and belongs in the restore family with its approval.
//
// EVERYTHING ABOUT WHAT MAY BE FETCHED IS stage_chain's. The script shares the
// staging code (includes/BackupStaging.php), so a verify can never fetch
// something a Prepare would refuse: the manifest is read on the node, the
// artifact list comes from the manifest, every fetch is checked against the
// node-side upload ledger, and the chain key is recovered from the node's own
// config/backup_site_key. No key crosses and no bucket credential crosses —
// there is no parameter below through which either could arrive.
//
// OFFLOADED FILES (specs/backup_offloaded_files.md § Verification) ride on two
// more optional link maps. epoch_envelope_urls: a signed link per epoch
// envelope the run's index names, which the node opens with its own key — the
// proof that the objects on the shelf are recoverable here, with no request
// per object. object_urls: at level 3, the sample the plane picked from that
// same index (the 5 largest and 15 random), which the node fetches, checks
// against the index's hash, decrypts and compares to the rehearsed database.
// Links, never a read credential, and never more than a sample can need.
//
// The node's history row is the authority for "verified": the script stamps
// the run it verified, and the VERIFY_* lines it prints are the plane's copy.
func init() {
	Register(Primitive{
		Name:        "verify_backup",
		Class:       ClassOperate,
		Description: "Open and read one of this node's own backups, or rehearse restoring it into scratch, to prove it is recoverable.",
		Params: []ParamSpec{
			// The chain, by id — the same pattern stage_chain binds, for the
			// same reason: it becomes a directory name on the node.
			{Name: "chain_id", Type: ParamString, Required: true, MaxLen: 64,
				Pattern: regexp.MustCompile(`^chain-[0-9_]+$`)},

			// Which shelf the chain came from, which decides which ledger the
			// artifacts are checked against as they arrive.
			{Name: "profile", Type: ParamEnum, Required: true,
				Values: []string{"site", "manager"}},

			// How much to prove. 2 opens and reads; 3 rehearses a restore into
			// scratch. Level 1 is not a job, and a level this primitive does
			// not know is refused here rather than interpreted on the node.
			{Name: "level", Type: ParamInt, Required: true, Min: 2, Max: 3},

			// The manifest's own signed link, fetched first — see stage_chain.
			{Name: "manifest_url", Type: ParamString, Required: true, MaxLen: 2048,
				Pattern: signedURLPattern},

			// Signed links for the chain's objects, keyed by bare artifact
			// name, bounded on every axis — see stage_chain, whose map this is.
			{Name: "artifact_urls", Type: ParamMap, Required: true,
				MaxEntries: 64, MaxKeyLen: 255, MaxLen: 2048,
				KeyPattern: backupFileName,
				Pattern:    signedURLPattern},

			// Verify as at this run rather than the newest. The scheduled
			// verify never sends it — the newest run is the one a restore
			// would start from — but an operator may pick any run from the
			// node's Backups tab.
			{Name: "seq", Type: ParamInt, Min: 0, Max: 100000},

			// The run's offloaded files: the epoch envelopes to open, keyed by
			// epoch id (backup_run's map, same bounds), and the rehearsal's
			// sample, keyed by the object's bare name in the index and capped
			// at the sample size the plane picks.
			{Name: "epoch_envelope_urls", Type: ParamMap,
				MaxEntries: 64, MaxKeyLen: 32, MaxLen: 2048,
				KeyPattern: epochIDPattern,
				Pattern:    signedURLPattern},
			{Name: "object_urls", Type: ParamMap,
				MaxEntries: verifySampleMax, MaxKeyLen: 255, MaxLen: 2048,
				KeyPattern: backupFileName,
				Pattern:    signedURLPattern},
		},
		Script: &ScriptSpec{
			Interpreter: "/usr/bin/php",
			ScriptPath:  "public_html/utils/verify_backup.php",
			Args:        nil,
			StdinFrom:   verifyBackupConfig,
		},
		// A whole chain's transfer (stage_chain's budget) plus reading every
		// byte of it, plus — at level 3 — a replay and a database load. Three
		// hours is well above the largest managed node's measured time and
		// still bounds a verify that has hung.
		Timeout: 3 * time.Hour,
	})
}

// verifySampleMax is the most objects a rehearsal opens: BackupVerifier's
// SAMPLE_LARGEST + SAMPLE_RANDOM. A map larger than that is not a sample.
const verifySampleMax = 20

// verifyBackupConfig renders the script's configuration from validated params.
func verifyBackupConfig(params Params) (string, error) {
	config := map[string]interface{}{
		"chain_id":      params.String("chain_id"),
		"profile":       params.String("profile"),
		"level":         params.Int("level"),
		"manifest_url":  params.String("manifest_url"),
		"artifact_urls": params.Map("artifact_urls"),
	}
	// Absent means "the newest run", as it does for stage_chain.
	if params.Has("seq") {
		config["seq"] = params.Int("seq")
	}
	// Absent means the run's offloaded files were not linked; the script
	// answers for that by name rather than guessing.
	if params.Has("epoch_envelope_urls") {
		config["epoch_envelope_urls"] = params.Map("epoch_envelope_urls")
	}
	if params.Has("object_urls") {
		config["object_urls"] = params.Map("object_urls")
	}

	body, err := json.Marshal(config)
	if err != nil {
		return "", err
	}
	return string(body), nil
}
