package primitives

import (
	"encoding/json"
	"strings"
	"testing"
)

// Verifying a backup: the same staging contract as stage_chain, plus a level,
// and nothing on the live site touched at any level — which is what makes it
// an operate primitive a schedule may dispatch with no approval.

func verifyPrimitive(t *testing.T) Primitive {
	t.Helper()
	p, ok := Lookup("verify_backup")
	if !ok {
		t.Fatal("verify_backup should be registered")
	}
	return p
}

func TestVerifyBackupIsOperateNotDestructive(t *testing.T) {
	// Reading a backup to the end, or replaying it into scratch and a
	// throwaway database, destroys nothing — so a verify needs no approval and
	// can run on a schedule. A destructive classification here would refuse
	// the scheduled proof everywhere.
	if class := verifyPrimitive(t).Class; class != ClassOperate {
		t.Errorf("verify_backup is class %q, want %q", class, ClassOperate)
	}
}

func TestVerifyBackupIsAScriptPrimitive(t *testing.T) {
	// The proof runs the script that ships in the same release as this agent,
	// verified against the signed release manifest before it runs as root.
	p := verifyPrimitive(t)
	if p.Script == nil || p.Script.ScriptPath != "public_html/utils/verify_backup.php" {
		t.Errorf("verify_backup should run public_html/utils/verify_backup.php, got %+v", p.Script)
	}
	if p.Script != nil && p.Script.StdinFrom == nil {
		t.Error("verify_backup's configuration crosses on stdin, and nothing renders it")
	}
}

func TestVerifyBackupTakesNoCredentialAndNoKey(t *testing.T) {
	// The same two promises stage_chain makes. No bucket credential; and no
	// decryption key, because the chain data key is recovered on the node
	// from the node's own backup_site_key.
	banned := []string{
		"credential", "credentials_b64", "access_key", "secret_key", "secret",
		"bucket", "path_prefix", "key_file", "keyfile", "private", "recovery",
		"site_key", "data_key", "passphrase",
	}
	for _, spec := range verifyPrimitive(t).Params {
		for _, word := range banned {
			if strings.Contains(spec.Name, word) {
				t.Errorf("verify_backup declares %q — neither a bucket credential nor a decryption "+
					"key may be sendable to a node", spec.Name)
			}
		}
	}
}

func TestVerifyBackupBoundsItsLevel(t *testing.T) {
	// Level 1 is the plane's shelf check and is not a job; level 4 does not
	// exist. Either is refused here, not interpreted on the node.
	p := verifyPrimitive(t)
	base := func(level interface{}) map[string]interface{} {
		return map[string]interface{}{
			"chain_id":      "chain-20260830_010203",
			"profile":       "manager",
			"level":         level,
			"manifest_url":  "https://x.invalid/m?X-Amz-Signature=a",
			"artifact_urls": map[string]interface{}{"files-0000.tar.gz.enc": "https://x.invalid/o?X-Amz-Signature=b"},
		}
	}
	for _, bad := range []interface{}{float64(1), float64(4), float64(0), "2"} {
		if _, err := Validate(p.Params, base(bad)); err == nil {
			t.Errorf("verify_backup accepted level %v", bad)
		}
	}
	for _, good := range []float64{2, 3} {
		if _, err := Validate(p.Params, base(good)); err != nil {
			t.Errorf("verify_backup refused level %v: %v", good, err)
		}
	}
	// And a job with no level at all: the schedule always says 2, the
	// operator always chooses, so an absent level is a malformed job.
	params := base(float64(2))
	delete(params, "level")
	if _, err := Validate(p.Params, params); err == nil {
		t.Error("verify_backup accepted a job with no level")
	}
}

func TestVerifyBackupConfigCarriesLevelAndLinks(t *testing.T) {
	// The whole link map travels (the node picks from what its manifest
	// names), the level travels, and seq travels only when asked for.
	p := verifyPrimitive(t)
	params, err := Validate(p.Params, map[string]interface{}{
		"chain_id":     "chain-20260830_010203",
		"profile":      "manager",
		"level":        float64(3),
		"manifest_url": "https://x.invalid/m?X-Amz-Signature=a",
		"artifact_urls": map[string]interface{}{
			"files-0000.tar.gz.enc": "https://x.invalid/f0?X-Amz-Signature=b",
			"files-0001.tar.gz.enc": "https://x.invalid/f1?X-Amz-Signature=c",
			"db-0001.sql.gz.enc":    "https://x.invalid/d1?X-Amz-Signature=d",
		},
		"seq": float64(1),
	})
	if err != nil {
		t.Fatalf("a well-formed verify job should validate: %v", err)
	}

	body, err := p.Script.StdinFrom(params)
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		ChainID      string            `json:"chain_id"`
		Profile      string            `json:"profile"`
		Level        int64             `json:"level"`
		ManifestURL  string            `json:"manifest_url"`
		ArtifactURLs map[string]string `json:"artifact_urls"`
		Seq          *int64            `json:"seq"`
	}
	if err := json.Unmarshal([]byte(body), &config); err != nil {
		t.Fatal(err)
	}
	if config.Level != 3 {
		t.Errorf("the level did not travel: %+v", config)
	}
	if len(config.ArtifactURLs) != 3 {
		t.Errorf("the node was sent %d links, not the 3 the plane could sign", len(config.ArtifactURLs))
	}
	if config.ChainID != "chain-20260830_010203" || config.Profile != "manager" || config.ManifestURL == "" {
		t.Errorf("the config does not carry what was asked: %+v", config)
	}
	if config.Seq == nil || *config.Seq != 1 {
		t.Errorf("the run number did not travel: %+v", config.Seq)
	}

	bare, _ := Validate(p.Params, map[string]interface{}{
		"chain_id":      "chain-20260830_010203",
		"profile":       "manager",
		"level":         float64(2),
		"manifest_url":  "https://x.invalid/m?X-Amz-Signature=a",
		"artifact_urls": map[string]interface{}{"files-0000.tar.gz.enc": "https://x.invalid/f0?X-Amz-Signature=b"},
	})
	body, _ = p.Script.StdinFrom(bare)
	if strings.Contains(body, "\"seq\"") {
		t.Errorf("an unasked-for run number was sent as a default: %s", body)
	}
}

func TestVerifyBackupRefusesWhatStageChainRefuses(t *testing.T) {
	// The link map and the chain id are stage_chain's, bound the same way: a
	// link keyed by a path, a plaintext link, a chain id that is not one.
	p := verifyPrimitive(t)
	base := func() map[string]interface{} {
		return map[string]interface{}{
			"chain_id":     "chain-20260830_010203",
			"profile":      "manager",
			"level":        float64(2),
			"manifest_url": "https://x.invalid/m?X-Amz-Signature=a",
		}
	}
	for _, badKey := range []string{"../escape", "sub/dir/files-0000.tar.gz.enc", ".hidden", "/absolute"} {
		params := base()
		params["artifact_urls"] = map[string]interface{}{badKey: "https://x.invalid/o?X-Amz-Signature=b"}
		if _, err := Validate(p.Params, params); err == nil {
			t.Errorf("verify_backup accepted a link keyed by %q", badKey)
		}
	}
	params := base()
	params["artifact_urls"] = map[string]interface{}{"files-0000.tar.gz.enc": "http://x.invalid/o"}
	if _, err := Validate(p.Params, params); err == nil {
		t.Error("verify_backup accepted a plaintext link — a signature is a bearer token")
	}
	for _, bad := range []string{"../../etc", "chain-../x", "chain", "chain-2026/08", ""} {
		params := base()
		params["chain_id"] = bad
		params["artifact_urls"] = map[string]interface{}{"files-0000.tar.gz.enc": "https://x.invalid/o?X-Amz-Signature=b"}
		if _, err := Validate(p.Params, params); err == nil {
			t.Errorf("verify_backup accepted chain id %q", bad)
		}
	}
}
