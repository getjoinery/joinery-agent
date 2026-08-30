package primitives

import (
	"encoding/json"
	"strings"
	"testing"
)

// Staging a chain: the plane supplies links, the NODE decides which to use.
//
// That division is the whole point of the primitive, and it is the thing a
// future change is most likely to erode — the tempting shortcut is to have the
// plane work out which artifacts a run needs and send only those, which puts the
// chain layout back into two implementations with the authoritative one running
// on the machine that did not write the chain.

func stagePrimitive(t *testing.T) Primitive {
	t.Helper()
	p, ok := Lookup("stage_chain")
	if !ok {
		t.Fatal("stage_chain should be registered")
	}
	return p
}

func TestStageChainIsOperateNotDestructive(t *testing.T) {
	// Downloading into a fresh workspace destroys nothing, so staging needs no
	// approval and the destructive half stays as small as it can be.
	if class := stagePrimitive(t).Class; class != ClassOperate {
		t.Errorf("stage_chain is class %q, want %q", class, ClassOperate)
	}
}

func TestStageChainTakesNoCredentialAndNoKey(t *testing.T) {
	// Two separate promises. No bucket credential, for download_backup's reason.
	// And no DECRYPTION key: the chain data key is recovered on the node from
	// the node's own backup_site_key, because a key on the wire is a key in
	// every stored job record.
	banned := []string{
		"credential", "credentials_b64", "access_key", "secret_key", "secret",
		"bucket", "path_prefix", "key_file", "keyfile", "private", "recovery",
		"site_key", "data_key", "passphrase",
	}
	for _, spec := range stagePrimitive(t).Params {
		for _, word := range banned {
			if strings.Contains(spec.Name, word) {
				t.Errorf("stage_chain declares %q — neither a bucket credential nor a decryption "+
					"key may be sendable to a node", spec.Name)
			}
		}
	}
}

func TestStageChainBoundsItsLinkMap(t *testing.T) {
	// The one composite parameter in the vocabulary. Bounded in four directions,
	// because an unbounded map is a hole with a schema.
	var links ParamSpec
	for _, spec := range stagePrimitive(t).Params {
		if spec.Name == "artifact_urls" {
			links = spec
		}
	}
	if links.Type != ParamMap {
		t.Fatal("artifact_urls should be a map")
	}
	if links.MaxEntries <= 0 || links.MaxLen <= 0 || links.KeyPattern == nil || links.Pattern == nil {
		t.Errorf("artifact_urls is not bounded on every axis: entries=%d value=%d keyPattern=%v pattern=%v",
			links.MaxEntries, links.MaxLen, links.KeyPattern != nil, links.Pattern != nil)
	}
}

func TestStageChainRefusesLinksKeyedByAPath(t *testing.T) {
	// A key with a separator in it is the caller naming a path again, through
	// the one map it is allowed to send.
	p := stagePrimitive(t)
	base := map[string]interface{}{
		"chain_id":     "chain-20260830_010203",
		"profile":      "manager",
		"manifest_url": "https://x.invalid/m?X-Amz-Signature=a",
	}
	for _, badKey := range []string{"../escape", "sub/dir/files-0000.tar.gz.enc", ".hidden", "/absolute"} {
		params := map[string]interface{}{}
		for k, v := range base {
			params[k] = v
		}
		params["artifact_urls"] = map[string]interface{}{
			badKey: "https://x.invalid/o?X-Amz-Signature=b",
		}
		if _, err := Validate(p.Params, params); err == nil {
			t.Errorf("stage_chain accepted a link keyed by %q", badKey)
		}
	}

	// And a link that is not a signed https URL.
	params := map[string]interface{}{}
	for k, v := range base {
		params[k] = v
	}
	params["artifact_urls"] = map[string]interface{}{
		"files-0000.tar.gz.enc": "http://x.invalid/o",
	}
	if _, err := Validate(p.Params, params); err == nil {
		t.Error("stage_chain accepted a plaintext link — a signature is a bearer token")
	}
}

func TestStageChainPassesTheWholeLinkMapThrough(t *testing.T) {
	// The plane supplies what it can sign; the node picks from what its own
	// manifest names. So every link travels, and none of them is a decision.
	p := stagePrimitive(t)
	params, err := Validate(p.Params, map[string]interface{}{
		"chain_id":     "chain-20260830_010203",
		"profile":      "manager",
		"manifest_url": "https://x.invalid/m?X-Amz-Signature=a",
		"artifact_urls": map[string]interface{}{
			"files-0000.tar.gz.enc": "https://x.invalid/f0?X-Amz-Signature=b",
			"files-0001.tar.gz.enc": "https://x.invalid/f1?X-Amz-Signature=c",
			"db-0001.sql.gz.enc":    "https://x.invalid/d1?X-Amz-Signature=d",
		},
		"seq": float64(1),
	})
	if err != nil {
		t.Fatalf("a well-formed staging job should validate: %v", err)
	}

	body, err := p.Script.StdinFrom(params)
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		ChainID      string            `json:"chain_id"`
		Profile      string            `json:"profile"`
		ManifestURL  string            `json:"manifest_url"`
		ArtifactURLs map[string]string `json:"artifact_urls"`
		Seq          *int64            `json:"seq"`
	}
	if err := json.Unmarshal([]byte(body), &config); err != nil {
		t.Fatal(err)
	}
	if len(config.ArtifactURLs) != 3 {
		t.Errorf("the node was sent %d links, not the 3 the plane could sign", len(config.ArtifactURLs))
	}
	if config.ChainID != "chain-20260830_010203" || config.Profile != "manager" {
		t.Errorf("the config does not carry what was asked: %+v", config)
	}
	if config.Seq == nil || *config.Seq != 1 {
		t.Errorf("the run number did not travel: %+v", config.Seq)
	}

	// Absent means "the newest run", and it means it more clearly by being
	// absent than by being a default the script has to interpret.
	bare, _ := Validate(p.Params, map[string]interface{}{
		"chain_id":     "chain-20260830_010203",
		"profile":      "manager",
		"manifest_url": "https://x.invalid/m?X-Amz-Signature=a",
		"artifact_urls": map[string]interface{}{
			"files-0000.tar.gz.enc": "https://x.invalid/f0?X-Amz-Signature=b",
		},
	})
	body, _ = p.Script.StdinFrom(bare)
	if strings.Contains(body, "\"seq\"") {
		t.Errorf("an unasked-for run number was sent as a default: %s", body)
	}
}

func TestStageChainRefusesAChainIdThatIsNotOne(t *testing.T) {
	// The id becomes a DIRECTORY NAME on the node, so no separator and no dot is
	// what keeps the workspace inside the node's own backup base.
	p := stagePrimitive(t)
	for _, bad := range []string{"../../etc", "chain-../x", "chain", "chain-2026/08", ""} {
		_, err := Validate(p.Params, map[string]interface{}{
			"chain_id":      bad,
			"profile":       "manager",
			"manifest_url":  "https://x.invalid/m?X-Amz-Signature=a",
			"artifact_urls": map[string]interface{}{"files-0000.tar.gz.enc": "https://x.invalid/o?X-Amz-Signature=b"},
		})
		if err == nil {
			t.Errorf("stage_chain accepted chain id %q", bad)
		}
	}
}
