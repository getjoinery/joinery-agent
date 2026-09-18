package redact

import (
	"strings"
	"testing"
)

// Each class the package promises to mask, and each thing it promises to
// leave: a redactor that eats the diagnosis is as useless as one that leaks it.

func TestCredentialValuesAreMaskedByKeyName(t *testing.T) {
	cases := map[string]string{
		`'password' => 'hunter2'`:                      `'password' => '********'`,
		`"token": "abc.def"`:                           `"token": "********"`,
		`"secret_key":"s3cr3t"`:                        `"secret_key":"********"`,
		`'credentials_b64' => 'QUJD'`:                  `'credentials_b64' => '********'`,
		`'credentials' => 'x'`:                         `'credentials' => '********'`,
		`PGPASSWORD=hunter2 psql`:                      `PGPASSWORD=******** psql`,
		`AWS_SECRET_ACCESS_KEY="a b"`:                  `AWS_SECRET_ACCESS_KEY=********`,
		`export GITHUB_TOKEN='t'`:                      `export GITHUB_TOKEN=********`,
		`API_KEY=k1`:                                   `API_KEY=********`,
		`password=hunter2 end`:                         `password=******** end`,
		`dsn user=y;dbpassword=z;dbname=x`:             `dsn user=y;dbpassword=********`,
		`?csrf_token=abc&x=1`:                          `?csrf_token=********`,
		`api_key=sk_live_1`:                            `api_key=********`,
		`client_secret=s`:                              `client_secret=********`,
		`primary_key=usr_user_id`:                      `primary_key=usr_user_id`,
		`--key=/root/.ssh/id`:                          `--key=/root/.ssh/id`,
		`cache_key=abc123`:                             `cache_key=abc123`,
		`ssh_key_path=/root/.ssh`:                      `ssh_key_path=/root/.ssh`,
		`secret-key: abcdef`:                           `secret-key: ********`,
		`--clone-key=deadbeef`:                         `--clone-key=********`,
		`Authorization: Bearer eyJhbGciOi.payload.sig`: `Authorization: Bearer ********`,
	}
	for in, want := range cases {
		if got := Text(in); got != want {
			t.Errorf("Text(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEveryPinnedKeyIsMasked(t *testing.T) {
	for _, k := range secretKeys {
		in := `'` + k + `' => 'value'`
		if got := Text(in); !strings.Contains(got, Mask) || strings.Contains(got, "value") {
			t.Errorf("key %q: Text(%q) = %q", k, in, got)
		}
	}
}

func TestEmailKeepsTheDomain(t *testing.T) {
	in := "could not send to jane.doe+x@Example.co.uk from bounce@mail.example.com"
	want := "could not send to <email>@Example.co.uk from <email>@mail.example.com"
	if got := Text(in); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestIPLiteralsAreMasked(t *testing.T) {
	cases := map[string]string{
		"client 203.0.113.9 denied":               "client <ip> denied",
		"listen 127.0.0.1:5432":                   "listen <ip>:5432",
		"from 2001:db8:85a3:0:0:8a2e:370:7334 ok": "from <ip> ok",
		"from 2001:db8::1 ok":                     "from <ip> ok",
		"from fe80::1%eth0":                       "from <ip>%eth0",
		"bind ::1":                                "bind <ip>",
	}
	for in, want := range cases {
		if got := Text(in); got != want {
			t.Errorf("Text(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestOpaqueTokensAreMasked(t *testing.T) {
	cases := map[string]string{
		"sha 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 done": "sha <token> done",
		"key=QWxhZGRpbjpvcGVuIHNlc2FtZTEyMzQ1Njc4OTA end":                           "key=<token> end",
		"key='QWxhZGRpbjpvcGVuIHNlc2FtZTEyMzQ1Njc4OTA=' end":                        "key='<token>' end",
	}
	for in, want := range cases {
		if got := Text(in); got != want {
			t.Errorf("Text(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestWhatIsNotMasked(t *testing.T) {
	keep := []string{
		"upgraded to 0.8.408 at 2026-09-17 23:10:00",
		"2026-09-17T23:10:00Z [error] PHP Warning",
		"in /var/www/html/joinerytest/public_html/includes/ThemeHelper.php on line 331",
		"setting server_manager_fleet_backup_window_start is unset",
		"class ManagedDomainNoticeRendererFactoryImplementation not found",
		"ssh_key_path=/root/.ssh/id_ed25519",
		"SSH_KEY_PATH=/root/.ssh/id_ed25519",
		"mac aa:bb:cc:dd:ee:ff",
		"release 1.34.0 running since 12:00:01",
		"the word 'token' appears here without a value",
		"abcdefghijklmnopqrstuvwxyzabcdefghijkl",
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"1234567890123456789012345678901234567890",
		"PathHelper::getThemeFilePath found it",
		"bind [::]:443 (the any-address names nobody)",
		"DbConnector::get_instance()->get_db_link()",
	}
	for _, in := range keep {
		if got := Text(in); got != in {
			t.Errorf("Text(%q) changed it to %q; it carries nothing to mask", in, got)
		}
	}
}

func TestEmptyAndPlain(t *testing.T) {
	if Text("") != "" {
		t.Error("empty in, empty out")
	}
	if Text("nothing here") != "nothing here" {
		t.Error("plain text passes through")
	}
}

func TestFieldsRecurses(t *testing.T) {
	m := map[string]interface{}{
		"text":  "user jane@example.com",
		"count": int64(3),
		"ok":    true,
		"nested": map[string]interface{}{
			"note": "PGPASSWORD=x",
		},
		"rows": []interface{}{
			map[string]interface{}{"note": "from 10.0.0.1"},
			"bare 10.0.0.2",
		},
		"list": []string{"a@b.co"},
		"maps": []map[string]interface{}{{"k": "c@d.co"}},
	}
	Fields(m)
	if m["text"] != "user <email>@example.com" {
		t.Errorf("text: %v", m["text"])
	}
	if m["count"] != int64(3) || m["ok"] != true {
		t.Error("non-strings must be untouched")
	}
	if m["nested"].(map[string]interface{})["note"] != "PGPASSWORD="+Mask {
		t.Errorf("nested: %v", m["nested"])
	}
	rows := m["rows"].([]interface{})
	if rows[0].(map[string]interface{})["note"] != "from <ip>" || rows[1] != "bare <ip>" {
		t.Errorf("rows: %v", rows)
	}
	if m["list"].([]string)[0] != "<email>@b.co" {
		t.Errorf("list: %v", m["list"])
	}
	if m["maps"].([]map[string]interface{})[0]["k"] != "<email>@d.co" {
		t.Errorf("maps: %v", m["maps"])
	}
}
