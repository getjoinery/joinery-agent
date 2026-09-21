package primitives

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
)

// Bringing offloaded files home: a page of links at a time, driven by the
// plane, with nothing on the node overwritten and no key or credential able
// to arrive.

func restoreObjectsPrimitive(t *testing.T) Primitive {
	t.Helper()
	p, ok := Lookup("restore_objects")
	if !ok {
		t.Fatal("restore_objects should be registered")
	}
	return p
}

func restoreObjectsBase() map[string]interface{} {
	return map[string]interface{}{
		"chain_id":  "chain-20260830_010203",
		"profile":   "manager",
		"seq":       float64(3),
		"mode":      "missing",
		"index_url": "https://x.invalid/i?X-Amz-Signature=a",
	}
}

func TestRestoreObjectsIsOperateNotDestructive(t *testing.T) {
	// The script overwrites nothing and deletes nothing in any bucket — the
	// drain flow's shape, which already runs unattended. Destructive here
	// would put an approval in front of every page of a paged loop.
	if class := restoreObjectsPrimitive(t).Class; class != ClassOperate {
		t.Errorf("restore_objects is class %q, want %q", class, ClassOperate)
	}
}

func TestRestoreObjectsIsAScriptPrimitive(t *testing.T) {
	p := restoreObjectsPrimitive(t)
	if p.Script == nil || p.Script.ScriptPath != "public_html/utils/restore_objects.php" {
		t.Errorf("restore_objects should run public_html/utils/restore_objects.php, got %+v", p.Script)
	}
	if p.Script != nil && p.Script.StdinFrom == nil {
		t.Error("restore_objects' configuration crosses on stdin, and nothing renders it")
	}
}

func TestRestoreObjectsTakesNoCredentialAndNoKey(t *testing.T) {
	banned := []string{
		"credential", "credentials_b64", "access_key", "secret_key", "secret",
		"bucket", "path_prefix", "key_file", "keyfile", "private", "recovery",
		"site_key", "data_key", "passphrase", "epoch_key",
	}
	for _, spec := range restoreObjectsPrimitive(t).Params {
		for _, word := range banned {
			if strings.Contains(spec.Name, word) {
				t.Errorf("restore_objects declares %q — neither a bucket credential nor a decryption "+
					"key may be sendable to a node", spec.Name)
			}
		}
	}
}

func TestRestoreObjectsSurveyCarriesNoLinks(t *testing.T) {
	// The first job names the run and the mode and links the index; the
	// script reads an absent object map as "tell me what you would bring".
	p := restoreObjectsPrimitive(t)
	params, err := Validate(p.Params, restoreObjectsBase())
	if err != nil {
		t.Fatalf("a survey should validate: %v", err)
	}
	body, err := p.Script.StdinFrom(params)
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		ChainID  string `json:"chain_id"`
		Profile  string `json:"profile"`
		Seq      int64  `json:"seq"`
		Mode     string `json:"mode"`
		IndexURL string `json:"index_url"`
	}
	if err := json.Unmarshal([]byte(body), &config); err != nil {
		t.Fatal(err)
	}
	if config.ChainID != "chain-20260830_010203" || config.Profile != "manager" || config.Seq != 3 ||
		config.Mode != "missing" || config.IndexURL == "" {
		t.Errorf("the survey config does not carry what was asked: %+v", config)
	}
	if strings.Contains(body, "object_urls") || strings.Contains(body, "epoch_envelope_urls") {
		t.Errorf("a survey sent link maps it was not given: %s", body)
	}
}

func TestRestoreObjectsPageCarriesLinksAndEnvelopes(t *testing.T) {
	p := restoreObjectsPrimitive(t)
	params := restoreObjectsBase()
	params["mode"] = "all"
	params["epoch_envelope_urls"] = map[string]interface{}{
		"epoch-20260901_000000": "https://x.invalid/e?X-Amz-Signature=b",
	}
	params["object_urls"] = map[string]interface{}{
		"beach.jpg":       "https://x.invalid/o1?X-Amz-Signature=c",
		"blob_43cnle.bin": "https://x.invalid/o2?X-Amz-Signature=d",
	}
	validated, err := Validate(p.Params, params)
	if err != nil {
		t.Fatalf("a page should validate: %v", err)
	}
	body, _ := p.Script.StdinFrom(validated)
	var config struct {
		Mode      string            `json:"mode"`
		Envelopes map[string]string `json:"epoch_envelope_urls"`
		Objects   map[string]string `json:"object_urls"`
	}
	if err := json.Unmarshal([]byte(body), &config); err != nil {
		t.Fatal(err)
	}
	if config.Mode != "all" || len(config.Envelopes) != 1 || len(config.Objects) != 2 {
		t.Errorf("the page config does not carry the maps as sent: %s", body)
	}
}

func TestRestoreObjectsRequiresRunAndMode(t *testing.T) {
	// The index is one artifact of one run: the node does not pick a newest
	// here, so an absent seq is a malformed job. A mode the script does not
	// know, or none, is refused here rather than interpreted on the node.
	p := restoreObjectsPrimitive(t)
	params := restoreObjectsBase()
	delete(params, "seq")
	if _, err := Validate(p.Params, params); err == nil {
		t.Error("restore_objects accepted a job with no run number")
	}
	params = restoreObjectsBase()
	delete(params, "mode")
	if _, err := Validate(p.Params, params); err == nil {
		t.Error("restore_objects accepted a job with no mode")
	}
	for _, bad := range []interface{}{"some", "MISSING", "", float64(1)} {
		params = restoreObjectsBase()
		params["mode"] = bad
		if _, err := Validate(p.Params, params); err == nil {
			t.Errorf("restore_objects accepted mode %v", bad)
		}
	}
	params = restoreObjectsBase()
	params["index_url"] = "http://x.invalid/i"
	if _, err := Validate(p.Params, params); err == nil {
		t.Error("restore_objects accepted a plaintext index link — a signature is a bearer token")
	}
}

func TestRestoreObjectsLinksAreBounded(t *testing.T) {
	// A page is at most restoreObjectsPageMax objects and the envelopes of at
	// most 64 epochs, keyed by bare names and epoch ids; a key with a
	// separator, or an epoch that is not one, is refused.
	p := restoreObjectsPrimitive(t)
	for _, badKey := range []string{"../escape", "sub/dir/x.jpg", ".hidden", "/absolute"} {
		params := restoreObjectsBase()
		params["object_urls"] = map[string]interface{}{badKey: "https://x.invalid/o?X-Amz-Signature=b"}
		if _, err := Validate(p.Params, params); err == nil {
			t.Errorf("restore_objects accepted an object link keyed by %q", badKey)
		}
	}
	for _, badEpoch := range []string{"epoch-1", "chain-20260830_010203", "beach.jpg", "epoch-20260901_000000/x"} {
		params := restoreObjectsBase()
		params["epoch_envelope_urls"] = map[string]interface{}{badEpoch: "https://x.invalid/e?X-Amz-Signature=b"}
		if _, err := Validate(p.Params, params); err == nil {
			t.Errorf("restore_objects accepted an envelope link keyed by %q", badEpoch)
		}
	}
	tooMany := map[string]interface{}{}
	for i := 0; i <= restoreObjectsPageMax; i++ {
		tooMany["o"+strconv.Itoa(i)+".bin"] = "https://x.invalid/o?X-Amz-Signature=b"
	}
	params := restoreObjectsBase()
	params["object_urls"] = tooMany
	if _, err := Validate(p.Params, params); err == nil {
		t.Errorf("restore_objects accepted %d object links; a page is at most %d", len(tooMany), restoreObjectsPageMax)
	}
	epochs := map[string]interface{}{}
	for i := 0; i < 65; i++ {
		epochs["epoch-202609"+strconv.Itoa(10+i%20)+"_"+strconv.Itoa(100000+i)] = "https://x.invalid/e?X-Amz-Signature=b"
	}
	params = restoreObjectsBase()
	params["epoch_envelope_urls"] = epochs
	if _, err := Validate(p.Params, params); err == nil {
		t.Error("restore_objects accepted 65 envelope links; the map is bounded at 64")
	}
}
