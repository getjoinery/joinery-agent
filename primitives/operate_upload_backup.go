package primitives

import (
	"encoding/json"
	"regexp"
	"time"
)

// upload_backup: put one backup that is already on this node into the
// management node's storage target — the Backups tab's per-file action, for an
// archive sitting local-only because its original upload hit a transient
// provider failure.
//
// The transfer runs on the node because the file is on the node; routing a
// multi-gigabyte archive through the control plane would drag it down and push
// it back up again for nothing. That much is unchanged from the SSH path.
// Everything else is different, and the difference is the migration.
//
// WHAT THE SSH PATH DID, so it is on the record where the replacement lives:
// the plane read includes/S3Signer.php and node_uploader.php off its own disk,
// concatenated them with a credentials block, and heredoc'd the result onto the
// node to run under `php -` as root. The plane composed a program and shipped it
// to be executed. That is the exact capability this architecture exists to
// delete, and no amount of care inside the composed program would have made it
// acceptable.
//
// Here the plane names a primitive and supplies declared, bounded values. The
// node runs public_html/utils/upload_backup.php — a file already on its disk,
// verified against the signed release manifest before the interpreter starts.
// It is a CORE script, deliberately: node_uploader.php lives in the
// server_manager plugin, which is the MANAGEMENT plugin and is active on
// control planes and nowhere else (§10.3), so a primitive resolving a script
// there would verify against a plugin manifest a managed node does not have and
// refuse on every node in the fleet.
//
// THE PLANE CANNOT NAME A PATH. This is the strongest single thing the primitive
// buys and it is worth being explicit about. The SSH step resolved
// UPLOAD_FILE from a string the plane composed, so a compromised plane could
// name any file on any node — the config carrying the database password, a
// private key, a user's mail — and have the node upload it to a bucket the
// attacker controlled: read-anything-from-every-node, wearing a backup job's
// clothes. The vocabulary below has no path in it. There is a filename, it must
// look like a backup artifact, and the node resolves it inside its own
// compiled-in backup directory.
//
// AND IT CANNOT DELETE. The SSH upload_step took a delete_local flag and chained
// an `rm` onto the upload. The per-file action always passed false — "an
// operator asking for an offsite copy of a file they are looking at did not ask
// for that file to disappear" — but that was a promise the builder kept, one
// argument away from being broken by a future caller. No parameter here can ask
// for a deletion, and the script it invokes contains no code that removes a
// file. The promise is now a property of the shape.
//
// The storage credential IS supplied by the plane, the same intended asymmetry
// backup_run carries: the bucket belongs to the management node. It travels on
// stdin, never argv, because argv is visible to every process on the box.
func init() {
	Register(Primitive{
		Name:        "upload_backup",
		Class:       ClassOperate,
		Description: "Upload one existing backup file from this node to the management node's storage target.",
		Params: []ParamSpec{
			// A NAME, never a path. The pattern excludes the separator, and by
			// requiring an alphanumeric first character it excludes "." and ".."
			// as well. What it names still has to look like a backup — that is
			// checked below, against the same suffix list list_backups reports
			// from, so the set of files this can upload is exactly the set the
			// node was willing to admit it has.
			{Name: "filename", Type: ParamString, Required: true, MaxLen: 255,
				Pattern: regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)},

			// Where it goes. Bucket, prefix and slug are path material in
			// someone else's bucket, so each is bound to what can safely be a
			// path segment: a traversal in any of them would write over another
			// node's backups.
			{Name: "bucket", Type: ParamString, Required: true, MaxLen: 255,
				Pattern: regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)},
			{Name: "path_prefix", Type: ParamString, Required: true, MaxLen: 255,
				Pattern: regexp.MustCompile(`^[A-Za-z0-9_-]+(/[A-Za-z0-9_-]+)*$`)},
			{Name: "slug", Type: ParamString, Required: true, MaxLen: 64,
				Pattern: regexp.MustCompile(`^[A-Za-z0-9_-]+$`)},

			// The storage credential. Bounded and base64-shaped; never logged,
			// never in argv, never in the result.
			{Name: "credentials_b64", Type: ParamString, Required: true, MaxLen: 8192,
				Pattern: regexp.MustCompile(`^[A-Za-z0-9+/=]+$`)},

			// Send the archive's key file with it. A BOOLEAN, and that is the
			// whole design: the plane asks for "the key that belongs to the
			// archive I named", and the NODE derives the name. Letting the plane
			// send a .keys.json filename instead would have handed it back the
			// ability to name a file, which is the one thing this vocabulary
			// exists to take away. An encrypted archive without its envelope is
			// an offsite copy nobody can open — see the script's header — so
			// this is not a convenience, it is what makes the upload worth
			// making.
			{Name: "include_envelope", Type: ParamBool},
		},
		Script: &ScriptSpec{
			Interpreter: "/usr/bin/php",
			ScriptPath:  "public_html/utils/upload_backup.php",
			// No arguments at all. run_backup.php carries --profile=manager and
			// its header explains why argv is dangerous; this script needs
			// nothing there, so `ps` on a node discloses that an upload is
			// running and not one thing about which file or which bucket.
			Args:      nil,
			StdinFrom: uploadBackupConfig,
		},
		// The SSH step this replaces allowed S3Signer's whole transfer budget
		// plus slack. A large archive on a slow link legitimately takes that
		// long, and a deadline under the work is just a way to fail uploads on
		// a timer. The number is that budget: one hour per attempt
		// (TRANSFER_TIMEOUT_SECONDS) plus a 20-minute retry window
		// (RETRY_WINDOW_SECONDS), plus slack — and S3Signer says why it must not
		// be smaller, "a step budget smaller than the retry budget would have
		// the agent kill the upload mid-retry". The 5-minute DefaultTimeout
		// would kill a multi-gigabyte archive every time and report a working
		// link as a failure.
		Timeout: 85 * time.Minute,
	})
}

// uploadBackupConfig renders the script's configuration from validated params.
//
// The last check lives here rather than in the ParamSpec because a suffix list
// is not a regular expression anyone should have to read as one, and because
// the list already exists: backupExtensions, which mirrors BackupNaming's and is
// what list_backups reports from. A name that passed the pattern but is not a
// backup artifact is refused as a decision, not run and failed.
func uploadBackupConfig(params Params) (string, error) {
	filename := params.String("filename")
	if !isBackupArtifact(filename) {
		return "", refusedf("%q is not the name of a backup artifact, so this node will not upload it", filename)
	}

	config := map[string]interface{}{
		"bucket":          params.String("bucket"),
		"path_prefix":     params.String("path_prefix"),
		"slug":            params.String("slug"),
		"filename":        filename,
		"credentials_b64": params.String("credentials_b64"),
	}
	// Absent unless asked for, rather than sent as a false: the script treats an
	// unknown key as a refusal, so a config that always carried this field would
	// fail against a node whose core predates it. A node that has not upgraded
	// should keep doing what it always did, not stop uploading.
	if params.Bool("include_envelope") {
		config["include_envelope"] = true
	}

	body, err := json.Marshal(config)
	if err != nil {
		return "", err
	}
	return string(body), nil
}
