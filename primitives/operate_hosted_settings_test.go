package primitives

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

// The hosted tier's two settings writers. A general map-taking one was built
// for this feature and removed; the property these tests exist to keep is that
// neither of them, nor anything else in the vocabulary, lets a SETTING NAME
// arrive from the wire.

func hostedParams(t *testing.T, name string, raw map[string]interface{}) (Params, error) {
	t.Helper()
	p, ok := Lookup(name)
	if !ok {
		t.Fatalf("%s should be registered", name)
	}
	return Validate(p.Params, raw)
}

func TestNoHostedPrimitiveAcceptsASettingName(t *testing.T) {
	// THE assertion. The mail one matters most: a site whose outbound mail can
	// be redirected is a site whose password-reset email can be redirected, so
	// a primitive able to name a setting would reach every managed node's
	// accounts through a vocabulary that looks modest.
	for _, name := range []string{"hosted_mail_settings", "hosted_plan_notice"} {
		for _, key := range []string{
			"setting", "settings", "setting_name", "name", "value", "key",
			"table", "sql", "query", "statement", "column",
			"smtp_host", "smtp_password", "email_service", "web_root", "sitename",
		} {
			base := map[string]interface{}{key: "anything"}
			if _, err := hostedParams(t, name, base); err == nil {
				t.Errorf("%s carrying %q must be refused; the setting names are compiled into the "+
					"node-side script and never cross the wire", name, key)
			}
		}
	}
}

func TestTheGeneralSettingsWriterIsGone(t *testing.T) {
	// It existed briefly. If it comes back, the argument in
	// operate_hosted_mail_settings.go is the one to answer first.
	if _, ok := Lookup("settings_converge"); ok {
		t.Error("a general settings writer is registered again — read the comment in " +
			"operate_hosted_mail_settings.go before deciding that is right")
	}
}

func TestMailSettingsCarryEightValuesAndNoMore(t *testing.T) {
	p, _ := Lookup("hosted_mail_settings")
	declared := map[string]ParamSpec{}
	for _, s := range p.Params {
		declared[s.Name] = s
	}
	for _, want := range []string{"service", "host", "port", "username", "password",
		"sender", "helo", "hostname"} {
		if _, ok := declared[want]; !ok {
			t.Errorf("hosted_mail_settings should declare %q", want)
		}
	}
	if len(declared) != 8 {
		t.Errorf("it should declare exactly eight values, it declares %d", len(declared))
	}
	if p.Class != ClassOperate {
		t.Errorf("writing settings changes state; it is operate, not %q", p.Class)
	}
	if p.Script == nil || p.Script.ScriptPath != hostedMailSettingsScript {
		t.Errorf("it should invoke %q", hostedMailSettingsScript)
	}
	if len(p.Script.Args) != 0 {
		t.Errorf("argv should be empty, got %v — one of these values is a password", p.Script.Args)
	}
	if owner := owningArtifact(hostedMailSettingsScript); owner != "" {
		t.Errorf("the script resolved to artifact %q; it ships in the core archive", owner)
	}
}

func TestOnlySmtpOrNothingIsAcceptedAsAMailService(t *testing.T) {
	for _, good := range []string{"smtp", ""} {
		if _, err := hostedParams(t, "hosted_mail_settings",
			map[string]interface{}{"service": good}); err != nil {
			t.Errorf("service %q should be accepted: %v", good, err)
		}
	}
	for _, bad := range []string{"sendmail", "SMTP", "ses", "mailgun", "smtp "} {
		if _, err := hostedParams(t, "hosted_mail_settings",
			map[string]interface{}{"service": bad}); err == nil {
			t.Errorf("service %q should be refused rather than written", bad)
		}
	}
}

func TestAMailHostIsAHostnameAndNothingElse(t *testing.T) {
	for _, good := range []string{"mail.smtp2go.com", "localhost", ""} {
		if _, err := hostedParams(t, "hosted_mail_settings",
			map[string]interface{}{"host": good}); err != nil {
			t.Errorf("host %q should be accepted: %v", good, err)
		}
	}
	// A scheme, a port or a path arriving inside the host field is a second
	// value smuggled into one slot.
	for _, bad := range []string{
		"https://mail.example.com", "mail.example.com:587", "mail.example.com/x",
		"mail example com", "mail.example.com\nsecond",
	} {
		if _, err := hostedParams(t, "hosted_mail_settings",
			map[string]interface{}{"host": bad}); err == nil {
			t.Errorf("host %q should be refused", bad)
		}
	}
}

func TestAMailPasswordIsPrintableAndOneLine(t *testing.T) {
	// Deliberately permissive about content — a provider mints what it likes —
	// and strict about it being one value.
	for _, good := range []string{"aB3!$%^&*()_+-=", "", strings.Repeat("x", 256)} {
		if _, err := hostedParams(t, "hosted_mail_settings",
			map[string]interface{}{"password": good}); err != nil {
			t.Errorf("password of length %d should be accepted: %v", len(good), err)
		}
	}
	for _, bad := range []string{"two\nlines", "a\x00b", "tab\there", strings.Repeat("x", 257)} {
		if _, err := hostedParams(t, "hosted_mail_settings",
			map[string]interface{}{"password": bad}); err == nil {
			t.Errorf("password %q should be refused", bad)
		}
	}
}

func TestEveryMailValueIsEmittedSoAnOmittedOneClears(t *testing.T) {
	// A push that could only ADD would leave a dead credential on a site whose
	// owner has moved to their own mail account, and the site would keep trying
	// to send through it.
	p, _ := Lookup("hosted_mail_settings")
	params, err := hostedParams(t, "hosted_mail_settings", map[string]interface{}{"service": ""})
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
	if len(decoded) != 8 {
		t.Errorf("all eight keys should be emitted every time, got %v", decoded)
	}
	for key, value := range decoded {
		if value != "" {
			t.Errorf("an omitted %q should be emitted as empty so it clears, got %q", key, value)
		}
	}
	// A zero port renders empty rather than "0" — no mail server listens on 0,
	// and writing it would be a configuration that looks set and is not.
	if decoded["port"] != "" {
		t.Errorf("an absent port should clear, not write %q", decoded["port"])
	}
}

func TestTheBannerRendersBillingStatesOnly(t *testing.T) {
	for _, good := range []string{"trial", "subscribed", "grace", "shutdown", ""} {
		if _, err := hostedParams(t, "hosted_plan_notice",
			map[string]interface{}{"state": good}); err != nil {
			t.Errorf("state %q should be accepted: %v", good, err)
		}
	}
	// Suspension is NOT a billing state: it is independent of whether the
	// customer is paying, and folding it in loses one fact to say the other.
	for _, bad := range []string{"suspended", "paused", "TRIAL", "active"} {
		if _, err := hostedParams(t, "hosted_plan_notice",
			map[string]interface{}{"state": bad}); err == nil {
			t.Errorf("state %q should be refused", bad)
		}
	}
}

func TestTheBannerCannotCarryACredential(t *testing.T) {
	p, _ := Lookup("hosted_plan_notice")
	for _, s := range p.Params {
		switch s.Name {
		case "password", "username", "host", "service":
			t.Errorf("the banner declares %q — the mail credentials and the banner must not "+
				"share a doorway", s.Name)
		}
	}
	// And the one value that becomes a live link stays pinned to https.
	for _, bad := range []string{"http://example.com", "javascript:alert(1)", "//example.com"} {
		if _, err := hostedParams(t, "hosted_plan_notice",
			map[string]interface{}{"manage_url": bad}); err == nil {
			t.Errorf("manage_url %q should be refused", bad)
		}
	}
}

func TestBothScriptsReadStdinAndNothingInArgv(t *testing.T) {
	for _, tc := range []struct {
		primitive string
		script    string
		params    map[string]interface{}
		expect    string
	}{
		{"hosted_mail_settings", hostedMailSettingsScript,
			map[string]interface{}{"service": "smtp", "host": "mail.smtp2go.com"},
			`"host":"mail.smtp2go.com"`},
		{"hosted_plan_notice", hostedPlanNoticeScript,
			map[string]interface{}{"state": "trial"},
			`"state":"trial"`},
	} {
		root, verifier := signedScriptRoot(t, tc.script,
			"<?php echo 'argc=', $argc-1, \"\\n\", stream_get_contents(STDIN), \"\\n\";")
		result, err := Execute(context.Background(), &ExecEnv{
			SiteRoot: root,
			WebRoot:  filepath.Join(root, "public_html"),
			Manifest: verifier,
		}, ShippedPolicy(), Request{JobID: 1, Primitive: tc.primitive, Params: tc.params})
		if err != nil {
			t.Fatalf("%s: a verified script should execute: %v", tc.primitive, err)
		}
		output := result["output"].(string)
		if !strings.Contains(output, "argc=0") {
			t.Errorf("%s: nothing should reach argv, where a password would be visible in ps. "+
				"Output: %q", tc.primitive, output)
		}
		if !strings.Contains(output, tc.expect) {
			t.Errorf("%s: the composed object should arrive on stdin. Output: %q", tc.primitive, output)
		}
	}
}
