package primitives

import (
	"encoding/json"
	"strings"
	"testing"
)

// backup_run is the first operate primitive and the first script-invoking one.
// Two things matter more than whether it works: what it will NOT accept, and
// where the storage credential is allowed to appear.

func backupRunParams(t *testing.T, raw map[string]interface{}) (Params, error) {
	t.Helper()
	p, ok := Lookup("backup_run")
	if !ok {
		t.Fatal("backup_run should be registered")
	}
	return Validate(p.Params, raw)
}

func validBackupParams() map[string]interface{} {
	return map[string]interface{}{
		"type":            "project",
		"mode":            "chain",
		"target_name":     "b2-main",
		"provider":        "b2",
		"bucket":          "joinery-backups",
		"path_prefix":     "joinery-backups",
		"slug":            "jeremytunnell",
		"credentials_b64": "QUtJQVNFQ1JFVA==",
	}
}

func TestAValidBackupJobIsAccepted(t *testing.T) {
	if _, err := backupRunParams(t, validBackupParams()); err != nil {
		t.Fatalf("a well-formed backup job should validate: %v", err)
	}
}

func TestNoEncryptionKeyCanReachTheNode(t *testing.T) {
	// A4, as a property of the vocabulary rather than a check someone runs.
	// Sealing to a public key always APPEARS to succeed, so a compromised plane
	// that could supply one could silently re-seal every node's next backup —
	// the whole database, all mail — to a key it holds. There is no parameter
	// through which one can arrive.
	for _, field := range []string{
		"recovery_public_key",
		"recovery_private_key",
		"recovery_fpr",
		"recipients",
	} {
		params := validBackupParams()
		params[field] = "anything at all"

		if _, err := backupRunParams(t, params); err == nil {
			t.Errorf("a job carrying %q must be refused as out-of-vocabulary", field)
		}
	}
}

func TestUndeclaredParametersAreRefusedRatherThanPassedThrough(t *testing.T) {
	params := validBackupParams()
	params["extra_flag"] = "--something"

	if _, err := backupRunParams(t, params); err == nil {
		t.Fatal("an undeclared parameter must be refused; there is no pass-through")
	}
}

func TestTheSlugCannotEscapeItsBucketPath(t *testing.T) {
	// The slug becomes a path segment in the bucket. A value with a separator or
	// a traversal in it would write another node's backups, or somewhere else
	// entirely.
	for _, bad := range []string{"../other", "a/b", "with space", "semi;colon", ""} {
		params := validBackupParams()
		params["slug"] = bad

		if _, err := backupRunParams(t, params); err == nil {
			t.Errorf("slug %q should be refused", bad)
		}
	}
}

func TestRetentionValuesAreBounded(t *testing.T) {
	// A wire value should not be able to ask a node to keep a decade of local
	// copies on a disk the plane cannot see.
	params := validBackupParams()
	params["keep_local_days"] = 100000

	if _, err := backupRunParams(t, params); err == nil {
		t.Fatal("an out-of-range retention should be refused")
	}
}

func TestTheEngineConfigIsComposedOnTheNode(t *testing.T) {
	// The plane sends parameters; the node builds the config. That is what makes
	// "the plane cannot add a field" true — a field it does not declare never
	// reaches the composer, and the composer writes a fixed set of keys.
	params, err := backupRunParams(t, validBackupParams())
	if err != nil {
		t.Fatalf("validate: %v", err)
	}

	body, err := backupRunConfig(params)
	if err != nil {
		t.Fatalf("compose: %v", err)
	}

	var config map[string]interface{}
	if err := json.Unmarshal([]byte(body), &config); err != nil {
		t.Fatalf("the composed config should be JSON: %v", err)
	}
	for _, key := range []string{"target_name", "provider", "bucket", "path_prefix", "credentials_b64", "slug", "type", "mode"} {
		if _, ok := config[key]; !ok {
			t.Errorf("the engine needs %q and it is missing", key)
		}
	}
	// Optional fields absent from the job stay absent from the config, so the
	// engine applies its own defaults rather than receiving a zero that looks
	// deliberate.
	if _, present := config["keep_local_days"]; present {
		t.Error("an unsupplied optional must not be sent as a zero the engine reads as a choice")
	}
}

func TestTheCredentialTravelsOnStdinAndNotInArgv(t *testing.T) {
	// The reason stdin was added to the framework at all. run_backup.php's own
	// header: "Stdin rather than an argument on purpose. Anything in argv is
	// visible to every [process on the box]."
	p, _ := Lookup("backup_run")
	if p.Script == nil {
		t.Fatal("backup_run should be a script primitive")
	}
	if p.Script.StdinFrom == nil {
		t.Fatal("backup_run must deliver its config on stdin")
	}
	for _, arg := range p.Script.Args {
		if strings.Contains(arg, "credential") || strings.Contains(arg, "{config") {
			t.Errorf("argv element %q would put the config where ps can read it", arg)
		}
	}
	if len(p.Script.Args) != 1 || p.Script.Args[0] != "--profile=manager" {
		t.Errorf("argv should carry only the profile flag, got %v", p.Script.Args)
	}
}

func TestBackupRunIsOperateAndInvokesTheShippedEngine(t *testing.T) {
	p, _ := Lookup("backup_run")

	if p.Class != ClassOperate {
		t.Errorf("backup_run is operate, not %q", p.Class)
	}
	// The same script the SSH path invoked: the engine is untouched, only the
	// route to it changed.
	if p.Script.ScriptPath != "public_html/utils/run_backup.php" {
		t.Errorf("backup_run should invoke the shipped backup engine, got %q", p.Script.ScriptPath)
	}
}
