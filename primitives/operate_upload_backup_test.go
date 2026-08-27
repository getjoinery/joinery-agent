package primitives

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// upload_backup replaces the step that concatenated two PHP files and heredoc'd
// them onto a node to run as root. What matters is not that an upload works —
// it is what this can no longer be asked to do.

func uploadParams(t *testing.T, raw map[string]interface{}) (Params, error) {
	t.Helper()
	p, ok := Lookup("upload_backup")
	if !ok {
		t.Fatal("upload_backup should be registered")
	}
	return Validate(p.Params, raw)
}

func validUploadParams() map[string]interface{} {
	return map[string]interface{}{
		"filename":        "jeremytunnell_2026-08-27_full.tar.gz.enc",
		"bucket":          "joinery-backups",
		"path_prefix":     "joinery-backups",
		"slug":            "jeremytunnell",
		"credentials_b64": "QUtJQVNFQ1JFVA==",
	}
}

func TestAValidUploadJobIsAccepted(t *testing.T) {
	if _, err := uploadParams(t, validUploadParams()); err != nil {
		t.Fatalf("a well-formed upload job should validate: %v", err)
	}
}

func TestThePlaneCannotNameAPathToUpload(t *testing.T) {
	// The whole point. Under SSH the absolute path arrived from the plane, so a
	// compromised plane could name any file on any node — the config with the
	// database password, a private key, a user's mail — and have it uploaded to
	// a bucket it controlled. There is no path in this vocabulary, and nothing
	// that can be bent into one.
	for _, bad := range []string{
		"/etc/shadow",
		"../../config/Globalvars_site.php",
		"..",
		".",
		".hidden.tar.gz",
		"backups/site.tar.gz",
		"site.tar.gz\x00.png",
		"site .tar.gz",
		"",
	} {
		params := validUploadParams()
		params["filename"] = bad

		if _, err := uploadParams(t, params); err == nil {
			t.Errorf("filename %q should be refused; it is a path or worse", bad)
		}
	}
}

func TestOnlyABackupArtifactCanBeUploaded(t *testing.T) {
	// A name can pass the pattern and still not be a backup. The suffix list is
	// the same one list_backups reports from, so the set of files this can send
	// away is exactly the set the node was willing to admit it has.
	params, err := uploadParams(t, validUploadParams())
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if _, err := uploadBackupConfig(params); err != nil {
		t.Fatalf("a real artifact name should compose: %v", err)
	}

	for _, bad := range []string{"Globalvars_site.php", "id_rsa", "notes.txt", "backup.tar", "agent_signing_key"} {
		raw := validUploadParams()
		raw["filename"] = bad
		p, err := uploadParams(t, raw)
		if err != nil {
			continue // refused earlier, which is also correct
		}
		if _, err := uploadBackupConfig(p); err == nil {
			t.Errorf("%q is not a backup artifact and must not be uploaded", bad)
		} else if !Refused(err) {
			t.Errorf("%q should be a refusal, not a failure: %v", bad, err)
		}
	}
}

func TestNothingCanAskTheUploadToDeleteAnything(t *testing.T) {
	// The SSH step took a delete_local flag and chained an `rm` onto the upload.
	// The per-file action always passed false, but that was a promise the
	// builder kept rather than a thing the shape prevented.
	for _, field := range []string{"delete_local", "delete_local_after_upload", "delete_after_upload", "rm"} {
		params := validUploadParams()
		params[field] = true

		if _, err := uploadParams(t, params); err == nil {
			t.Errorf("a job carrying %q must be refused as out-of-vocabulary", field)
		}
	}

	p, _ := Lookup("upload_backup")
	for _, spec := range p.Params {
		if strings.Contains(spec.Name, "delete") {
			t.Errorf("upload_backup declares %q — deletion must not be expressible here", spec.Name)
		}
	}
}

func TestTheUploadCannotBeToldWhereInTheBucketToWrite(t *testing.T) {
	// The object key is composed on the node from the prefix, the slug and the
	// file's own name. A job cannot supply the key, and the pieces it does
	// supply cannot carry a traversal into another node's backups.
	params := validUploadParams()
	params["remote_key"] = "someone-else/secrets"
	if _, err := uploadParams(t, params); err == nil {
		t.Error("a job supplying the object key must be refused")
	}

	for _, bad := range []string{"../other", "a b", "semi;colon", "with/slash", ""} {
		params := validUploadParams()
		params["slug"] = bad
		if _, err := uploadParams(t, params); err == nil {
			t.Errorf("slug %q should be refused", bad)
		}
	}
	for _, bad := range []string{"../..", "/absolute", "prefix/../..", "a b", ""} {
		params := validUploadParams()
		params["path_prefix"] = bad
		if _, err := uploadParams(t, params); err == nil {
			t.Errorf("path prefix %q should be refused", bad)
		}
	}
}

func TestUndeclaredUploadParametersAreRefusedRatherThanPassedThrough(t *testing.T) {
	params := validUploadParams()
	params["local_path"] = "/backups/site.tar.gz"

	if _, err := uploadParams(t, params); err == nil {
		t.Fatal("an undeclared parameter must be refused; there is no pass-through")
	}
}

func TestNoEncryptionKeyCanReachTheUpload(t *testing.T) {
	// A4. The bucket belongs to the management node; the encryption key belongs
	// to the node. Nothing about an upload needs a key at all, so there is no
	// parameter through which one can arrive.
	for _, field := range []string{"recovery_public_key", "recovery_private_key", "recovery_fpr", "recipients"} {
		params := validUploadParams()
		params[field] = "anything at all"

		if _, err := uploadParams(t, params); err == nil {
			t.Errorf("a job carrying %q must be refused as out-of-vocabulary", field)
		}
	}
}

func TestTheStorageCredentialTravelsOnStdinAndNotInArgv(t *testing.T) {
	p, _ := Lookup("upload_backup")
	if p.Script == nil {
		t.Fatal("upload_backup should be a script primitive")
	}
	if p.Script.StdinFrom == nil {
		t.Fatal("upload_backup must deliver its configuration on stdin")
	}
	// Nothing in argv at all: on a node, ps shows that an upload is running and
	// not which file, which bucket, or whose credential.
	if len(p.Script.Args) != 0 {
		t.Errorf("upload_backup should pass no arguments, got %v", p.Script.Args)
	}
}

func TestTheUploadConfigIsComposedOnTheNode(t *testing.T) {
	params, err := uploadParams(t, validUploadParams())
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	body, err := uploadBackupConfig(params)
	if err != nil {
		t.Fatalf("compose: %v", err)
	}

	var config map[string]interface{}
	if err := json.Unmarshal([]byte(body), &config); err != nil {
		t.Fatalf("the composed config should be JSON: %v", err)
	}

	want := map[string]bool{"bucket": true, "path_prefix": true, "slug": true, "filename": true, "credentials_b64": true}
	for key := range want {
		if _, ok := config[key]; !ok {
			t.Errorf("the script needs %q and it is missing", key)
		}
	}
	// The composer writes a fixed set of keys, which is what makes "the plane
	// cannot add a field" true rather than merely intended. The script refuses
	// an unrecognised key, so a sixth one here would fail every upload.
	for key := range config {
		if !want[key] {
			t.Errorf("the composed config carries %q, which the script will refuse", key)
		}
	}
}

func TestUploadBackupIsOperateAndInvokesAShippedCoreScript(t *testing.T) {
	p, _ := Lookup("upload_backup")

	if p.Class != ClassOperate {
		t.Errorf("upload_backup is operate, not %q", p.Class)
	}
	// CORE, not the server_manager plugin. server_manager is the management
	// plugin and is active on control planes and nowhere else, so a script
	// resolved under public_html/plugins/ would verify against a manifest a
	// managed node does not have — and refuse on every node in the fleet.
	if p.Script.ScriptPath != "public_html/utils/upload_backup.php" {
		t.Errorf("upload_backup should invoke the core uploader, got %q", p.Script.ScriptPath)
	}
	if strings.Contains(p.Script.ScriptPath, "plugins/") {
		t.Error("the uploader must not live in a plugin; a managed node may not carry it")
	}
}

func TestTheUploadIsGivenLongerThanTheTransferItself(t *testing.T) {
	// The node kills a primitive that outruns its timeout, and the default is
	// five minutes — shorter than a multi-gigabyte archive takes on any link
	// worth uploading over. S3Signer's own budget is one hour per attempt plus a
	// twenty-minute retry window; a timeout under that does not fail slow
	// uploads, it kills healthy ones mid-retry and reports a working link as
	// broken.
	p, _ := Lookup("upload_backup")

	const s3TransferBudget = 80 * time.Minute // TRANSFER_TIMEOUT_SECONDS + RETRY_WINDOW_SECONDS
	if p.Timeout <= s3TransferBudget {
		t.Errorf("upload_backup allows %v, which is inside S3Signer's own %v budget", p.Timeout, s3TransferBudget)
	}
	if p.Timeout == DefaultTimeout {
		t.Error("upload_backup must declare its own timeout; the default kills real transfers")
	}
}

func TestTheEnvelopeIsAskedForByFlagAndNeverByName(t *testing.T) {
	// The plane may ask for "the key that belongs to the archive I named". It may
	// not name a file. Handing it a filename parameter for the envelope would
	// give back exactly the capability this vocabulary exists to remove, so the
	// only way to ask is a boolean.
	for _, field := range []string{"envelope", "envelope_name", "envelope_filename", "sidecar", "keys_file"} {
		params := validUploadParams()
		params[field] = "anything.keys.json"

		if _, err := uploadParams(t, params); err == nil {
			t.Errorf("a job carrying %q must be refused; the envelope is derived, not named", field)
		}
	}

	// And the flag cannot smuggle one in as a string.
	params := validUploadParams()
	params["include_envelope"] = "../../config/Globalvars_site.php"
	if _, err := uploadParams(t, params); err == nil {
		t.Fatal("include_envelope must be a boolean")
	}
}

func TestTheEnvelopeFlagReachesTheScriptOnlyWhenAskedFor(t *testing.T) {
	// Absent means absent. The script refuses an unrecognised key, so a config
	// that always carried this field would fail on a node whose core predates
	// it — a node that has not upgraded should keep doing what it always did.
	params, err := uploadParams(t, validUploadParams())
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	body, err := uploadBackupConfig(params)
	if err != nil {
		t.Fatalf("compose: %v", err)
	}
	var config map[string]interface{}
	if err := json.Unmarshal([]byte(body), &config); err != nil {
		t.Fatalf("compose: %v", err)
	}
	if _, present := config["include_envelope"]; present {
		t.Error("an unrequested envelope must not appear in the config at all")
	}

	raw := validUploadParams()
	raw["include_envelope"] = true
	params, err = uploadParams(t, raw)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	body, _ = uploadBackupConfig(params)
	if err := json.Unmarshal([]byte(body), &config); err != nil {
		t.Fatalf("compose: %v", err)
	}
	if config["include_envelope"] != true {
		t.Errorf("a requested envelope should reach the script as true, got %v", config["include_envelope"])
	}
	// Still a fixed key set — the flag is the sixth and last.
	want := map[string]bool{"bucket": true, "path_prefix": true, "slug": true,
		"filename": true, "credentials_b64": true, "include_envelope": true}
	for key := range config {
		if !want[key] {
			t.Errorf("the composed config carries %q, which the script will refuse", key)
		}
	}
}
