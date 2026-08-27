package primitives

import (
	"encoding/json"
	"regexp"
	"time"
)

// backup_run: take this node's backup and upload it to the management node's
// storage target. The first operate primitive, and the first script-invoking
// one (§6 Phase 2 ordering, §4 inventory).
//
// It invokes the same script the SSH path invokes — utils/run_backup.php
// --profile=manager, config on stdin — so the backup ENGINE is untouched: same
// chains, same envelope, same restore semantics. What changes is everything
// around it. The plane no longer composes a shell command; it names a primitive
// and supplies declared, bounded parameters. The node verifies the script
// against the signed release manifest before running it as root. And the
// parameter list below is the whole vocabulary — anything else is refused here,
// not passed through.
//
// A4 IS ENFORCED BY THE PARAMETER LIST, not by a check that has to run.
// The plane must never supply encryption key material: sealing to a public key
// always appears to succeed, so a compromised plane could silently re-seal
// every node's next backup — the whole database, all mail — to an attacker's
// key. Under the old shape, refusing that meant BackupRunner inspecting a config
// the plane composed. Here there is no parameter through which a key could
// arrive: recovery_public_key, recovery_private_key, recovery_fpr and recipients
// are not declared, so a job carrying one is refused as out-of-vocabulary before
// any of this runs. The node seals to its own proven key, read locally, and a
// node with no proven key refuses loudly — both of which remain the engine's job.
//
// The storage credential IS supplied by the plane, and that is the intended
// asymmetry: the bucket belongs to the management node, the encryption key
// belongs to the node. It travels on stdin rather than argv precisely so it does
// not appear in ps on every node on every run.
func init() {
	Register(Primitive{
		Name:        "backup_run",
		Class:       ClassOperate,
		Description: "Run this node's backup to the management node's storage target.",
		Params: []ParamSpec{
			// What to back up, and how. Enums rather than strings: the engine
			// branches on these, and an unexpected value should be refused at
			// the boundary rather than defaulted somewhere inside.
			{Name: "type", Type: ParamEnum, Required: true, Values: []string{"project", "database"}},
			{Name: "mode", Type: ParamEnum, Required: true, Values: []string{"chain", "full"}},

			// Where it goes. The slug becomes a bucket path segment, so it is
			// pattern-bound to what can safely be one.
			{Name: "target_name", Type: ParamString, Required: true, MaxLen: 128},
			{Name: "provider", Type: ParamString, Required: true, MaxLen: 32, Pattern: regexp.MustCompile(`^[a-z0-9_-]+$`)},
			{Name: "bucket", Type: ParamString, Required: true, MaxLen: 255},
			{Name: "path_prefix", Type: ParamString, Required: true, MaxLen: 255},
			{Name: "slug", Type: ParamString, Required: true, MaxLen: 64, Pattern: regexp.MustCompile(`^[A-Za-z0-9_-]+$`)},

			// The storage credential. Bounded and base64-shaped; never logged,
			// never in argv, never in the result.
			{Name: "credentials_b64", Type: ParamString, Required: true, MaxLen: 8192, Pattern: regexp.MustCompile(`^[A-Za-z0-9+/=]+$`)},

			// Retention and chain policy. Bounded so a wire value cannot ask for
			// a decade of local copies on a node's disk.
			{Name: "full_interval_days", Type: ParamInt, Min: 1, Max: 365},
			{Name: "keep_local_days", Type: ParamInt, Min: 0, Max: 365},
			{Name: "delete_local_after_upload", Type: ParamBool},
		},
		Script: &ScriptSpec{
			Interpreter: "/usr/bin/php",
			ScriptPath:  "public_html/utils/run_backup.php",
			Args:        []string{"--profile=manager"},
			// The engine's config, composed here from validated parameters.
			StdinFrom: backupRunConfig,
		},
		// Matches the SSH step this replaces (S3Signer's transfer budget plus
		// room for the dump itself). A full project backup of a large node is
		// genuinely hours of work, and the deadline has to exceed the work or it
		// becomes a scheduled way to kill backups.
		Timeout: 4*time.Hour + 20*time.Minute,
	})
}

// backupRunConfig renders the engine's config object from validated parameters.
//
// This is the ONLY place a config for run_backup.php is composed on this node,
// and it composes it from a fixed set of keys. The plane cannot add a key by
// sending one: an undeclared parameter never reaches here, and a declared one
// lands in exactly the field named below. That is what makes "the plane supplies
// no key material" a property of the shape rather than a rule someone enforces.
func backupRunConfig(params Params) (string, error) {
	config := map[string]interface{}{
		"target_name":     params.String("target_name"),
		"provider":        params.String("provider"),
		"bucket":          params.String("bucket"),
		"path_prefix":     params.String("path_prefix"),
		"credentials_b64": params.String("credentials_b64"),
		"slug":            params.String("slug"),
		"type":            params.String("type"),
		"mode":            params.String("mode"),
	}
	if params.Has("full_interval_days") {
		config["full_interval_days"] = params.Int("full_interval_days")
	}
	if params.Has("keep_local_days") {
		config["keep_local_days"] = params.Int("keep_local_days")
	}
	if params.Has("delete_local_after_upload") {
		config["delete_local_after_upload"] = params.Bool("delete_local_after_upload")
	}

	body, err := json.Marshal(config)
	if err != nil {
		return "", err
	}
	return string(body), nil
}
