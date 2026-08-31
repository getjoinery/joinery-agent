package primitives

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// managed_domain_notice replaces a shell command that scraped the site's
// database password out of a PHP config file and piped hand-escaped SQL into
// psql. The one property that has to survive every future edit of this file is
// that the SETTING NAMES are not on the wire — the plane supplies four values
// and cannot say where they land.

func noticeParams(t *testing.T, raw map[string]interface{}) (Params, error) {
	t.Helper()
	p, ok := Lookup("managed_domain_notice")
	if !ok {
		t.Fatal("managed_domain_notice should be registered")
	}
	return Validate(p.Params, raw)
}

func noticeDeclared() map[string]ParamSpec {
	p, _ := Lookup("managed_domain_notice")
	out := map[string]ParamSpec{}
	for _, s := range p.Params {
		out[s.Name] = s
	}
	return out
}

func TestNoSettingNameCanArriveThroughThisPrimitive(t *testing.T) {
	// THE assertion. A generic write-a-setting primitive would hand a
	// compromised plane the whole stg_settings table — every credential, every
	// gate — through a vocabulary that looks modest. The declared list is a
	// security boundary, and this is what makes it one.
	declared := noticeDeclared()
	if len(declared) != 4 {
		t.Fatalf("managed_domain_notice should declare exactly four value parameters, it declares %d", len(declared))
	}
	for _, name := range []string{"domain", "expiry_time", "state", "manage_url"} {
		if _, ok := declared[name]; !ok {
			t.Errorf("the notice should declare %q", name)
		}
	}

	// Every shape through which a name, a table, or a statement could arrive.
	for _, key := range []string{
		"setting",      // "just tell me which setting"
		"setting_name", //
		"name",         //
		"value",        //
		"settings",     // a map of them, which is the same thing wholesale
		"key",          //
		"table",        //
		"sql",          // the shape this replaces
		"query",        //
		"statement",    //
		"column",       //
		"prefix",       //
		"db_name",      // the credentials the shell used to scrape
		"db_user",      //
		"db_password",  //
		"pgpassword",   //
		"sitename",     // and the plane's belief about this node's name
		"site_name",    //
		"web_root",     //
		"container",    //
	} {
		params := map[string]interface{}{"domain": "example.com", key: "anything"}
		if _, err := noticeParams(t, params); err == nil {
			t.Errorf("a job carrying %q must be refused; the four setting names are compiled into "+
				"the node-side script and never cross the wire", key)
		}
	}
}

func TestOnlyTheFourCustodyStatesPlusSilenceAreAccepted(t *testing.T) {
	// An unrecognised state is refused at the node rather than rendered onto a
	// customer's admin page.
	for _, good := range []string{"operator_managed", "push_requested", "push_sent", "self_custody", ""} {
		_, err := noticeParams(t, map[string]interface{}{"domain": "example.com", "state": good})
		if err != nil {
			t.Errorf("state %q is one of the real custody states and should be accepted: %v", good, err)
		}
	}
	for _, bad := range []string{"OPERATOR_MANAGED", "expired", "self custody", "operator_managed ", "0", "true"} {
		if _, err := noticeParams(t, map[string]interface{}{"domain": "example.com", "state": bad}); err == nil {
			t.Errorf("state %q should be refused rather than rendered", bad)
		}
	}
}

func TestTheOneLinkACustomerClicksIsPinnedToHttps(t *testing.T) {
	// manage_url is the only plane-supplied value that renders as a live link on
	// a customer's own admin notice, which makes it the only new plane-to-node
	// influence this design introduces.
	for _, good := range []string{
		"https://manage.example.com/profile/server_manager/domain",
		"https://example.com/",
	} {
		if _, err := noticeParams(t, map[string]interface{}{"domain": "example.com", "manage_url": good}); err != nil {
			t.Errorf("manage_url %q should be accepted: %v", good, err)
		}
	}
	for _, bad := range []string{
		"http://example.com/x",                       // not TLS
		"javascript:alert(1)",                        //
		"data:text/html,<script>",                    //
		"https://example.com/x?a=1",                  // a query string is not in the character class
		"//example.com/x",                            //
		"https://example.com/x\">clickme",            //
		strings.Repeat("https://a.example.com/", 40), // over its 512-byte bound
	} {
		if _, err := noticeParams(t, map[string]interface{}{"domain": "example.com", "manage_url": bad}); err == nil {
			t.Errorf("manage_url %q should be refused", bad)
		}
	}
	if declared := noticeDeclared()["manage_url"]; declared.MaxLen != 512 {
		t.Errorf("manage_url should carry its own bound rather than DefaultMaxLen, got %d", declared.MaxLen)
	}
}

func TestTheExpiryIsADateNotFreeText(t *testing.T) {
	for _, good := range []string{"2027-03-14", "2027-03-14 09:15:00"} {
		if _, err := noticeParams(t, map[string]interface{}{"domain": "example.com", "expiry_time": good}); err != nil {
			t.Errorf("expiry_time %q should be accepted: %v", good, err)
		}
	}
	for _, bad := range []string{"soon", "14/03/2027", "2027-03-14T09:15:00Z", "2027-3-4"} {
		if _, err := noticeParams(t, map[string]interface{}{"domain": "example.com", "expiry_time": bad}); err == nil {
			t.Errorf("expiry_time %q should be refused; it is rendered to a customer as a deadline", bad)
		}
	}
}

func TestTheNoticeIsOperateAndInvokesTheCoreScriptWithNoArgv(t *testing.T) {
	p, _ := Lookup("managed_domain_notice")

	if p.Class != ClassOperate {
		t.Errorf("writing four settings changes state; it is operate, not %q", p.Class)
	}
	if p.Script == nil {
		t.Fatal("managed_domain_notice should be a script primitive")
	}
	if p.Script.ScriptPath != managedDomainNoticeScript {
		t.Errorf("should invoke %q, got %q", managedDomainNoticeScript, p.Script.ScriptPath)
	}
	if len(p.Script.Args) != 0 {
		t.Errorf("argv should be empty, got %v — an element here is a place for a wire value to appear", p.Script.Args)
	}
	if p.Script.StdinFrom == nil {
		t.Fatal("the four values travel on stdin as one composed object")
	}
	if owner := owningArtifact(managedDomainNoticeScript); owner != "" {
		t.Errorf("the script resolved to artifact %q; it ships in the core archive and must "+
			"verify against the site-root manifest", owner)
	}
}

func TestEveryKeyIsWrittenSoAClearedValueIsActuallyCleared(t *testing.T) {
	// A push that could only ADD would leave a stale expiry date on a customer's
	// site after a renewal, and a stale custody state after the domain has moved
	// into their own account. The watcher converges on desired state, which only
	// works if an omitted value clears rather than persists.
	p, _ := Lookup("managed_domain_notice")

	params, err := noticeParams(t, map[string]interface{}{"domain": "example.com"})
	if err != nil {
		t.Fatalf("the domain alone is a well-formed notice: %v", err)
	}
	body, err := p.Script.StdinFrom(params)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]string
	if err := json.Unmarshal([]byte(body), &decoded); err != nil {
		t.Fatalf("stdin should be one JSON object: %v", err)
	}
	if len(decoded) != 4 {
		t.Errorf("all four keys should be emitted every time, got %v", decoded)
	}
	for _, key := range []string{"expiry_time", "state", "manage_url"} {
		if v, ok := decoded[key]; !ok || v != "" {
			t.Errorf("an omitted %q should be emitted as empty so it clears, got %q (present: %v)", key, v, ok)
		}
	}
	if decoded["domain"] != "example.com" {
		t.Errorf("the domain should be carried through, got %q", decoded["domain"])
	}
}

func TestTheComposedObjectCarriesNothingButTheFourValues(t *testing.T) {
	p, _ := Lookup("managed_domain_notice")
	params, err := noticeParams(t, map[string]interface{}{
		"domain":      "example.com",
		"expiry_time": "2027-03-14 09:15:00",
		"state":       "push_sent",
		"manage_url":  "https://manage.example.com/profile/server_manager/domain",
	})
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
	want := map[string]string{
		"domain":      "example.com",
		"expiry_time": "2027-03-14 09:15:00",
		"state":       "push_sent",
		"manage_url":  "https://manage.example.com/profile/server_manager/domain",
	}
	for key, value := range want {
		if decoded[key] != value {
			t.Errorf("%q should be %q, got %q", key, value, decoded[key])
		}
	}
	if len(decoded) != len(want) {
		t.Errorf("the object should hold exactly the four values, got %v", decoded)
	}
}

// --- End to end, against a signed tree ---------------------------------------

func TestTheScriptReadsTheObjectOnStdinAndNothingInArgv(t *testing.T) {
	root, verifier := signedScriptRoot(t, managedDomainNoticeScript,
		"<?php echo 'argc=', $argc-1, \"\\n\", stream_get_contents(STDIN), \"\\n\";")

	env := &ExecEnv{
		SiteRoot: root,
		WebRoot:  filepath.Join(root, "public_html"),
		Manifest: verifier,
	}
	result, err := Execute(context.Background(), env, ShippedPolicy(), Request{
		JobID:     1,
		Primitive: "managed_domain_notice",
		Params: map[string]interface{}{
			"domain":     "example.com",
			"state":      "operator_managed",
			"manage_url": "https://manage.example.com/profile/server_manager/domain",
		},
	})
	if err != nil {
		t.Fatalf("a verified script should execute: %v", err)
	}
	output := result["output"].(string)
	if !strings.Contains(output, "argc=0") {
		t.Errorf("nothing should reach argv, where it would be visible in ps. Output: %q", output)
	}
	if !strings.Contains(output, `"state":"operator_managed"`) {
		t.Errorf("the composed object should arrive on stdin. Output: %q", output)
	}
}

func TestAModifiedNoticeScriptIsRefusedBeforeItRunsAsRoot(t *testing.T) {
	root, verifier := signedScriptRoot(t, managedDomainNoticeScript, "<?php exit(0);")

	full := filepath.Join(root, filepath.FromSlash(managedDomainNoticeScript))
	if err := os.WriteFile(full, []byte("<?php echo 'pwned';"), 0o755); err != nil {
		t.Fatal(err)
	}

	_, err := Execute(context.Background(), &ExecEnv{
		SiteRoot: root,
		WebRoot:  filepath.Join(root, "public_html"),
		Manifest: verifier,
	}, ShippedPolicy(), Request{
		JobID:     1,
		Primitive: "managed_domain_notice",
		Params:    map[string]interface{}{"domain": "example.com"},
	})
	if err == nil {
		t.Fatal("a script that no longer matches its signed hash must not execute")
	} else if !Refused(err) {
		t.Errorf("a hash mismatch is a refusal, not a run that failed: %v", err)
	}
}
