package primitives

import (
	"encoding/json"
	"strings"
	"testing"
)

// Bringing a backup back: what the plane may say, and what it may not.
//
// The vocabulary is doing three separate jobs here and each is worth its own
// assertion. It stops the plane naming a path on the node. It stops the plane
// handing the node a bucket credential — the node's own is write-only, and the
// read it gets is one signed object rather than a wider key. And it stops the
// plane naming a key file, which is what would let a signed link be pointed at
// something and landed under a name a restore then trusts.

func downloadPrimitive(t *testing.T) Primitive {
	t.Helper()
	p, ok := Lookup("download_backup")
	if !ok {
		t.Fatal("download_backup should be registered")
	}
	return p
}

func TestDownloadBackupIsOperateNotDestructive(t *testing.T) {
	// The classification is the reason this half shipped ahead of the approval
	// machinery. Writing a file into a backup directory destroys nothing, so it
	// works on nodes that cannot yet be asked to approve anything — and a
	// restore stops being permitted-but-impossible.
	if class := downloadPrimitive(t).Class; class != ClassOperate {
		t.Errorf("download_backup is class %q, want %q — a fetch destroys nothing, and marking it "+
			"destructive would put the recovery path behind the approval it exists to precede",
			class, ClassOperate)
	}
}

func TestDownloadBackupTakesNoCredential(t *testing.T) {
	// A node holds a WRITE-ONLY bucket credential on purpose: a node that could
	// read the shelf is a node whose compromise reaches every other node's
	// backups. The read a restore needs is granted as a signature over one
	// object, not as a key — so there must be no field a key could arrive in.
	banned := []string{
		"credential", "credentials", "credentials_b64", "access_key", "secret_key",
		"secret", "token", "bucket", "path_prefix", "region", "endpoint", "key",
	}
	for _, spec := range downloadPrimitive(t).Params {
		for _, word := range banned {
			if strings.Contains(spec.Name, word) {
				t.Errorf("download_backup declares %q — a bucket credential must not be sendable "+
					"to a node, and neither must anything that reads as one", spec.Name)
			}
		}
	}
}

func TestDownloadBackupRefusesANameThatIsNotABackup(t *testing.T) {
	p := downloadPrimitive(t)
	params, err := Validate(p.Params, map[string]interface{}{
		"filename": "notabackup.txt",
		"profile":  "manager",
		"url":      "https://example.invalid/o?X-Amz-Signature=abc",
	})
	if err != nil {
		t.Fatalf("the name is well-formed, so validation should pass: %v", err)
	}
	if _, err := p.Script.StdinFrom(params); !Refused(err) {
		t.Fatalf("a name that is not a backup artifact must be refused as a decision, got %v", err)
	}
}

func TestDownloadBackupRefusesAPathAndAnUnsignedLink(t *testing.T) {
	p := downloadPrimitive(t)
	for _, bad := range []map[string]interface{}{
		{"filename": "../../etc/passwd", "profile": "manager", "url": "https://x.invalid/o"},
		{"filename": "sub/dir/db.sql.gz", "profile": "manager", "url": "https://x.invalid/o"},
		{"filename": ".hidden.sql.gz", "profile": "manager", "url": "https://x.invalid/o"},
		// http, not https: a pre-signed link is a bearer token, and a plaintext
		// fetch hands it to the network.
		{"filename": "db.sql.gz", "profile": "manager", "url": "http://x.invalid/o"},
		// A shell metacharacter in a link. There is no shell in this path, but
		// the pattern is what makes that true rather than incidental.
		{"filename": "db.sql.gz", "profile": "manager", "url": "https://x.invalid/o;rm -rf /"},
		// No profile: the node would not know which directory, or which ledger.
		{"filename": "db.sql.gz", "url": "https://x.invalid/o"},
	} {
		if _, err := Validate(p.Params, bad); err == nil {
			t.Errorf("download_backup accepted %v", bad)
		}
	}
}

func TestDownloadBackupSendsTheEnvelopeLinkOnlyWhenAsked(t *testing.T) {
	// The script refuses an unrecognised key, so a config that always carried
	// this field would fail outright against a node whose core predates it.
	p := downloadPrimitive(t)

	params, err := Validate(p.Params, map[string]interface{}{
		"filename": "db_2026-08-30.sql.gz.enc",
		"profile":  "manager",
		"url":      "https://x.invalid/o?X-Amz-Signature=abc",
	})
	if err != nil {
		t.Fatal(err)
	}
	body, err := p.Script.StdinFrom(params)
	if err != nil {
		t.Fatal(err)
	}
	var config map[string]interface{}
	if err := json.Unmarshal([]byte(body), &config); err != nil {
		t.Fatal(err)
	}
	if _, present := config["envelope_url"]; present {
		t.Error("envelope_url is present when it was not asked for")
	}
	if config["profile"] != "manager" || config["filename"] != "db_2026-08-30.sql.gz.enc" {
		t.Errorf("the config does not carry what was asked: %v", config)
	}

	params, _ = Validate(p.Params, map[string]interface{}{
		"filename":     "db_2026-08-30.sql.gz.enc",
		"profile":      "manager",
		"url":          "https://x.invalid/o?X-Amz-Signature=abc",
		"envelope_url": "https://x.invalid/k?X-Amz-Signature=def",
	})
	body, _ = p.Script.StdinFrom(params)
	json.Unmarshal([]byte(body), &config)
	if config["envelope_url"] != "https://x.invalid/k?X-Amz-Signature=def" {
		t.Errorf("the envelope link did not travel: %v", config)
	}
}

func TestDownloadBackupRunsNoArgv(t *testing.T) {
	// ps on a node discloses that a download is running, and not one thing about
	// which object, which bucket, or which signature.
	p := downloadPrimitive(t)
	if p.Script.Args != nil || p.Script.ArgsFrom != nil {
		t.Error("download_backup puts something in argv — a signed link there is visible to every " +
			"process on the box")
	}
}
