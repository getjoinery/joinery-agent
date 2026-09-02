package primitives

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fleet_enroll replaces a second SSH session at install completion that
// scraped the site's database password and piped a psql heredoc. The property
// that has to survive every edit of this file is that the three SETTING NAMES
// are not on the wire.

func fleetParams(t *testing.T, raw map[string]interface{}) (Params, error) {
	t.Helper()
	p, ok := Lookup("fleet_enroll")
	if !ok {
		t.Fatal("fleet_enroll should be registered")
	}
	return Validate(p.Params, raw)
}

func fleetGood() map[string]interface{} {
	return map[string]interface{}{
		"service_url": "https://operator.example.com",
		"public_key":  "public_abcdefgh12345678",
		"secret_key":  "secret_abcdefgh12345678",
	}
}

func TestFleetEnrollCarriesThreeValuesAndNoSettingName(t *testing.T) {
	p, _ := Lookup("fleet_enroll")
	if len(p.Params) != 3 {
		t.Fatalf("fleet_enroll should declare exactly three value parameters, it declares %d", len(p.Params))
	}
	if _, err := fleetParams(t, fleetGood()); err != nil {
		t.Fatalf("the platform's own key shape should be accepted: %v", err)
	}
	for _, key := range []string{
		"setting", "setting_name", "name", "value", "settings", "key", "table",
		"sql", "query", "statement", "db_name", "db_user", "db_password", "pgpassword",
		"sitename", "site_name", "web_root", "container",
	} {
		params := fleetGood()
		params[key] = "anything"
		if _, err := fleetParams(t, params); err == nil {
			t.Errorf("a job carrying %q must be refused; the three setting names are compiled into the node-side script", key)
		}
	}
}

func TestFleetEnrollEveryValueIsRequired(t *testing.T) {
	for _, missing := range []string{"service_url", "public_key", "secret_key"} {
		params := fleetGood()
		delete(params, missing)
		if _, err := fleetParams(t, params); err == nil {
			t.Errorf("a job without %q should be refused; a half-seeded site offers an Enroll that cannot work", missing)
		}
	}
}

func TestFleetEnrollValuesAreBoundedToThePlatformShapes(t *testing.T) {
	for _, bad := range []string{"http://operator.example.com", "https://a.example.com/x?a=1",
		"javascript:alert(1)", "https://user:pw@a.example.com", "operator.example.com"} {
		params := fleetGood()
		params["service_url"] = bad
		if _, err := fleetParams(t, params); err == nil {
			t.Errorf("service_url %q should be refused", bad)
		}
	}
	for _, good := range []string{"https://operator.example.com", "https://operator.example.com:8443/", "https://a.b.example.com/path"} {
		params := fleetGood()
		params["service_url"] = good
		if _, err := fleetParams(t, params); err != nil {
			t.Errorf("service_url %q should be accepted: %v", good, err)
		}
	}
	for _, bad := range []string{"secret_abcdefgh12345678", "public_ABC", "public_a'b", "public_short", "public_" + strings.Repeat("a", 65)} {
		params := fleetGood()
		params["public_key"] = bad
		if _, err := fleetParams(t, params); err == nil {
			t.Errorf("public_key %q should be refused", bad)
		}
	}
	for _, bad := range []string{"public_abcdefgh12345678", "secret_a b", "secret_'x", "secret_short"} {
		params := fleetGood()
		params["secret_key"] = bad
		if _, err := fleetParams(t, params); err == nil {
			t.Errorf("secret_key %q should be refused", bad)
		}
	}
}

func TestFleetEnrollIsOperateAndInvokesTheCoreScriptWithNoArgv(t *testing.T) {
	p, _ := Lookup("fleet_enroll")
	if p.Class != ClassOperate {
		t.Errorf("writing three settings changes state; it is operate, not %q", p.Class)
	}
	if p.Script == nil {
		t.Fatal("fleet_enroll should be a script primitive")
	}
	if p.Script.ScriptPath != fleetEnrollScript {
		t.Errorf("should invoke %q, got %q", fleetEnrollScript, p.Script.ScriptPath)
	}
	if len(p.Script.Args) != 0 {
		t.Errorf("argv should be empty, got %v — the secret must not appear in ps", p.Script.Args)
	}
	if p.Script.StdinFrom == nil {
		t.Fatal("the three values travel on stdin as one composed object")
	}
	if owner := owningArtifact(fleetEnrollScript); owner != "" {
		t.Errorf("the script resolved to artifact %q; it ships in the core archive", owner)
	}
}

func TestFleetEnrollComposedObjectCarriesExactlyTheThreeValues(t *testing.T) {
	p, _ := Lookup("fleet_enroll")
	params, err := fleetParams(t, fleetGood())
	if err != nil {
		t.Fatal(err)
	}
	body, err := p.Script.StdinFrom(params)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]string
	if err := json.Unmarshal([]byte(body), &decoded); err != nil {
		t.Fatal(err)
	}
	want := fleetGood()
	for key, value := range want {
		if decoded[key] != value {
			t.Errorf("%q should be %q, got %q", key, value, decoded[key])
		}
	}
	if len(decoded) != len(want) {
		t.Errorf("the object should hold exactly the three values, got %v", decoded)
	}
}

func TestFleetEnrollScriptReadsStdinAndNothingInArgv(t *testing.T) {
	root, verifier := signedScriptRoot(t, fleetEnrollScript,
		"<?php echo 'argc=', $argc-1, \"\\n\", stream_get_contents(STDIN), \"\\n\";")
	env := &ExecEnv{SiteRoot: root, WebRoot: filepath.Join(root, "public_html"), Manifest: verifier}
	result, err := Execute(context.Background(), env, ShippedPolicy(), Request{
		JobID: 1, Primitive: "fleet_enroll", Params: fleetGood(),
	})
	if err != nil {
		t.Fatalf("a verified script should execute: %v", err)
	}
	output := result["output"].(string)
	if !strings.Contains(output, "argc=0") {
		t.Errorf("nothing should reach argv. Output: %q", output)
	}
	if !strings.Contains(output, `"secret_key":"secret_abcdefgh12345678"`) {
		t.Errorf("the composed object should arrive on stdin. Output: %q", output)
	}
}

func TestAModifiedFleetEnrollScriptIsRefused(t *testing.T) {
	root, verifier := signedScriptRoot(t, fleetEnrollScript, "<?php exit(0);")
	full := filepath.Join(root, filepath.FromSlash(fleetEnrollScript))
	if err := os.WriteFile(full, []byte("<?php echo 'pwned';"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := Execute(context.Background(), &ExecEnv{
		SiteRoot: root, WebRoot: filepath.Join(root, "public_html"), Manifest: verifier,
	}, ShippedPolicy(), Request{JobID: 1, Primitive: "fleet_enroll", Params: fleetGood()})
	if err == nil {
		t.Fatal("a script that no longer matches its signed hash must not execute")
	} else if !Refused(err) {
		t.Errorf("a hash mismatch is a refusal, not a run that failed: %v", err)
	}
}
