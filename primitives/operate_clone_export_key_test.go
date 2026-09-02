package primitives

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// clone_export_arm hands the source site of a clone one key for the length of
// a provision. The property that has to survive every edit of this file is
// that the SETTING NAME is not on the wire: the plane supplies a key and
// cannot say where it lands.

func cloneArmParams(t *testing.T, raw map[string]interface{}) (Params, error) {
	t.Helper()
	p, ok := Lookup("clone_export_arm")
	if !ok {
		t.Fatal("clone_export_arm should be registered")
	}
	return Validate(p.Params, raw)
}

func TestCloneArmCarriesOneValueAndNoSettingName(t *testing.T) {
	p, _ := Lookup("clone_export_arm")
	if len(p.Params) != 1 || p.Params[0].Name != "export_key" {
		t.Fatalf("clone_export_arm should declare exactly one value parameter, export_key; got %+v", p.Params)
	}
	for _, key := range []string{
		"setting", "setting_name", "name", "value", "settings", "key", "table",
		"sql", "query", "statement", "sitename", "site_name", "web_root", "container",
	} {
		params := map[string]interface{}{"export_key": "abc123", key: "anything"}
		if _, err := cloneArmParams(t, params); err == nil {
			t.Errorf("a job carrying %q must be refused; the setting name is compiled into the node-side script", key)
		}
	}
}

func TestCloneArmKeyIsBoundedAndEmptyDisarms(t *testing.T) {
	for _, good := range []string{"", "0123456789abcdef0123456789abcdef", "Key_with-dash", strings.Repeat("a", 128)} {
		if _, err := cloneArmParams(t, map[string]interface{}{"export_key": good}); err != nil {
			t.Errorf("export_key %q should be accepted: %v", good, err)
		}
	}
	if _, err := cloneArmParams(t, map[string]interface{}{}); err != nil {
		t.Errorf("an absent key is a disarm and should be accepted: %v", err)
	}
	for _, bad := range []string{
		"has space", "a'b", "a\"b", "a;b", "$(id)", "a/b", "a.b", "über", strings.Repeat("a", 129),
	} {
		if _, err := cloneArmParams(t, map[string]interface{}{"export_key": bad}); err == nil {
			t.Errorf("export_key %q should be refused", bad)
		}
	}
}

func TestCloneArmIsOperateAndInvokesTheCoreScriptWithNoArgv(t *testing.T) {
	p, _ := Lookup("clone_export_arm")
	if p.Class != ClassOperate {
		t.Errorf("arming an export changes state; it is operate, not %q", p.Class)
	}
	if p.Script == nil {
		t.Fatal("clone_export_arm should be a script primitive")
	}
	if p.Script.ScriptPath != cloneExportArmScript {
		t.Errorf("should invoke %q, got %q", cloneExportArmScript, p.Script.ScriptPath)
	}
	if len(p.Script.Args) != 0 {
		t.Errorf("argv should be empty, got %v — the key is a credential and must not appear in ps", p.Script.Args)
	}
	if p.Script.StdinFrom == nil {
		t.Fatal("the key travels on stdin")
	}
	if owner := owningArtifact(cloneExportArmScript); owner != "" {
		t.Errorf("the script resolved to artifact %q; it ships in the core archive", owner)
	}
}

func TestCloneArmAlwaysEmitsTheKeySoAnOmittedOneClears(t *testing.T) {
	p, _ := Lookup("clone_export_arm")
	params, err := cloneArmParams(t, map[string]interface{}{})
	if err != nil {
		t.Fatal(err)
	}
	body, err := p.Script.StdinFrom(params)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]string
	if err := json.Unmarshal([]byte(body), &decoded); err != nil {
		t.Fatalf("stdin should be one JSON object: %v", err)
	}
	if v, ok := decoded["export_key"]; !ok || v != "" {
		t.Errorf("an omitted key should be emitted as empty so the export is disarmed, got %q (present: %v)", v, ok)
	}
	if len(decoded) != 1 {
		t.Errorf("the object should hold exactly the key, got %v", decoded)
	}
}

func TestCloneArmScriptReadsTheKeyOnStdinAndNothingInArgv(t *testing.T) {
	root, verifier := signedScriptRoot(t, cloneExportArmScript,
		"<?php echo 'argc=', $argc-1, \"\\n\", stream_get_contents(STDIN), \"\\n\";")
	env := &ExecEnv{SiteRoot: root, WebRoot: filepath.Join(root, "public_html"), Manifest: verifier}
	result, err := Execute(context.Background(), env, ShippedPolicy(), Request{
		JobID: 1, Primitive: "clone_export_arm",
		Params: map[string]interface{}{"export_key": "deadbeef"},
	})
	if err != nil {
		t.Fatalf("a verified script should execute: %v", err)
	}
	output := result["output"].(string)
	if !strings.Contains(output, "argc=0") {
		t.Errorf("nothing should reach argv. Output: %q", output)
	}
	if !strings.Contains(output, `"export_key":"deadbeef"`) {
		t.Errorf("the key should arrive on stdin. Output: %q", output)
	}
}

func TestAModifiedCloneArmScriptIsRefused(t *testing.T) {
	root, verifier := signedScriptRoot(t, cloneExportArmScript, "<?php exit(0);")
	full := filepath.Join(root, filepath.FromSlash(cloneExportArmScript))
	if err := os.WriteFile(full, []byte("<?php echo 'pwned';"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := Execute(context.Background(), &ExecEnv{
		SiteRoot: root, WebRoot: filepath.Join(root, "public_html"), Manifest: verifier,
	}, ShippedPolicy(), Request{JobID: 1, Primitive: "clone_export_arm", Params: map[string]interface{}{}})
	if err == nil {
		t.Fatal("a script that no longer matches its signed hash must not execute")
	} else if !Refused(err) {
		t.Errorf("a hash mismatch is a refusal, not a run that failed: %v", err)
	}
}
