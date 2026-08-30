package primitives

import (
	"encoding/json"
	"regexp"
	"time"
)

// download_backup: bring one of this node's own backups back off the shelf, so
// there is something on the machine for a restore to restore from.
//
// THE MIRROR OF upload_backup, AND THE REASON RESTORE DID NOT WORK. Every node
// in the fleet deletes its local archive once it is safely uploaded — which is
// right for a small disk, and means the normal state of a machine is "my backups
// are all offsite". The three restore primitives take the NAME of a file they
// expect to find in their own backup directory. That file is never there. So
// opening the authorization gate on its own would have produced a restore that
// was permitted and still restored nothing, and this is why availability was
// built before authorization rather than alongside it.
//
// ClassOperate, NOT ClassDestructive, and that is the whole reason the two
// halves are separable. Writing a file into a backup directory destroys nothing:
// nothing is overwritten that a restore was going to read, no schema is dropped,
// no tree is replaced. So this ships and works with no approval mechanism at all,
// on nodes that cannot yet be asked to approve anything.
//
// NO BUCKET CREDENTIAL CROSSES, and this is the sharpest thing in the file. A
// node holds a WRITE-ONLY credential by design (bkt_node_credentials): it may
// add to the shelf and may not read from it, because a node that could read the
// shelf is a node whose compromise reaches every other node's backups. A restore
// needs a read. The answer is not a narrower credential — it is not a credential:
// the plane signs ONE object key, for a bounded time, on the machine that already
// holds the key, and hands over the signature. There is no parameter here through
// which access_key, secret_key or a credentials blob could arrive, so a job
// carrying one is refused by Validate before any of this runs. The URL cannot be
// re-pointed either: the object key is inside the signature.
//
// THE PLANE STILL CANNOT NAME A PATH. It names a URL, which is a place in
// somebody else's bucket, and a FILENAME, which the node resolves inside its own
// backup directory for the named profile. Neither of those is a path on this
// machine.
//
// AND THE BYTES ARE CHECKED AGAINST THIS NODE'S OWN RECORD. The plane chooses
// the bucket, the signature and the name a file lands under, and the operator
// approving a later restore approves a NAME, never the bytes — so without a
// check the plane could serve anything under an approved name. The node-side
// upload ledger closes it: written by the backup run itself, at upload time, on
// this machine, before the bytes were anywhere the plane could reach. Two
// attacks die there, and the second is the one that carries it: forgery, and
// REPLAY — this machine's own genuine month-old archive served under a
// fresh-looking name, which every signature and every envelope would happily
// confirm. The enforcement is in the script (BackupFetch), because the ledger is
// checked before a byte moves and the script is what moves them.
func init() {
	Register(Primitive{
		Name:        "download_backup",
		Class:       ClassOperate,
		Description: "Fetch one of this node's own backups from cloud storage into its backup directory.",
		Params: []ParamSpec{
			// A NAME, never a path. Same pattern as upload_backup and the three
			// restores: it excludes the separator, and requiring an
			// alphanumeric first character excludes "." and ".." as well.
			{Name: "filename", Type: ParamString, Required: true, MaxLen: 255,
				Pattern: backupFileName},

			// WHOSE backup directory it lands in — a profile, which the node
			// maps to a directory, not a location. Required for the reason
			// every other backup primitive requires it: the two profiles keep
			// separate directories, and an archive put in the wrong one is
			// either invisible to the restore that wanted it or is a different
			// party's archive of the same name.
			{Name: "profile", Type: ParamEnum, Required: true,
				Values: []string{"site", "manager"}},

			// The signed link. A place in the plane's bucket, expiring, naming
			// one object. Bounded and https-only: the signature is a bearer
			// token, so a plaintext fetch would hand it to the network, and a
			// redirect is refused by the script for the same reason a
			// substituted object would be.
			{Name: "url", Type: ParamString, Required: true, MaxLen: 2048,
				Pattern: signedURLPattern},

			// The archive's key file, when it is wanted. A URL rather than a
			// boolean — unlike upload_backup, which could derive a local path,
			// a download needs a second signature and only the plane can make
			// one. What the plane still cannot do is NAME the sidecar: the
			// script derives "<archive>.keys.json" from the archive it was
			// given and fetches this URL under that name, so a link pointed at
			// something else lands as the sidecar and is refused by the ledger.
			{Name: "envelope_url", Type: ParamString, MaxLen: 2048,
				Pattern: signedURLPattern},
		},
		Script: &ScriptSpec{
			Interpreter: "/usr/bin/php",
			ScriptPath:  "public_html/utils/download_backup.php",
			// No argv at all, the same discipline upload_backup keeps: `ps` on
			// a node discloses that a download is running and not one thing
			// about which object, which bucket, or which signature.
			Args:      nil,
			StdinFrom: downloadBackupConfig,
		},
		// The same budget the upload direction gets, and for the same reason:
		// S3Signer's per-attempt transfer window is an hour, a multi-gigabyte
		// archive on a slow link genuinely uses it, and a deadline under the
		// work is a scheduled way to fail restores. An envelope fetch rides in
		// front of it and costs seconds.
		Timeout: 85 * time.Minute,
	})
}

// signedURLPattern bounds a pre-signed link to https and the URI character set.
// Shared by both link parameters so there is one answer to what a link may look
// like.
var signedURLPattern = regexp.MustCompile(`^https://[-A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%]+$`)

// downloadBackupConfig renders the script's configuration from validated params.
//
// The suffix check lives here rather than in the ParamSpec for the reason
// upload_backup gives: a suffix list is not a regular expression anyone should
// have to read as one, and the list already exists. A name that passed the
// pattern but is not a backup artifact is refused as a decision, not fetched and
// then puzzled over.
func downloadBackupConfig(params Params) (string, error) {
	filename := params.String("filename")
	if !isBackupArtifact(filename) {
		return "", refusedf("%q is not the name of a backup artifact, so this node will not fetch it", filename)
	}

	config := map[string]interface{}{
		"filename": filename,
		"profile":  params.String("profile"),
		"url":      params.String("url"),
	}
	// Absent unless asked for, never sent as an empty string: the script
	// refuses an unrecognised key and treats an empty required value as a
	// mistake, so a config that always carried this field would fail on a node
	// whose core predates it.
	if params.Has("envelope_url") {
		config["envelope_url"] = params.String("envelope_url")
	}

	body, err := json.Marshal(config)
	if err != nil {
		return "", err
	}
	return string(body), nil
}
