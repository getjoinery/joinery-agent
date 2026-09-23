package primitives

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func withFileHeadRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	old := fileHeadRoot
	fileHeadRoot = root
	t.Cleanup(func() { fileHeadRoot = old })
	return root
}

func writeUnder(t *testing.T, root, path, body string) {
	t.Helper()
	full := filepath.Join(root, path)
	if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
}

func runFileHeadWith(t *testing.T, env *ExecEnv, raw map[string]interface{}) (map[string]interface{}, error) {
	t.Helper()
	p, _ := Lookup("file_head")
	params, err := Validate(p.Params, raw)
	if err != nil {
		return nil, err
	}
	return p.Run(context.Background(), env, params)
}

// Rule 8: no path on the list reaches a file that is itself a secret.
func TestFileHeadNeverNamesASecret(t *testing.T) {
	forbidden := []string{
		"joinery-domains.cf", "/etc/opendkim/", "key.table", "signing.table",
		"letsencrypt", "joinery-agent.env", "Globalvars", "sudoers", "crypttab",
		"/etc/passwd", "/etc/shadow", "/etc/ssh", "sasl_passwd", "/root", "/home",
	}
	for name, f := range fileHeadFiles {
		for _, bad := range forbidden {
			if strings.Contains(f.Path, bad) {
				t.Errorf("file_head %q reads %q, which reaches %q — a secret is never readable", name, f.Path, bad)
			}
		}
		if strings.ContainsAny(f.Path, "*?[") {
			t.Errorf("file_head %q is a glob; every entry is a name", name)
		}
	}
}

func TestFileHeadShape(t *testing.T) {
	p, ok := Lookup("file_head")
	if !ok {
		t.Fatal("file_head should be registered")
	}
	if p.Class != ClassObserve || !p.RequiresLogAccess || p.Run == nil {
		t.Error("file_head is an embedded observe word behind the owner's switch")
	}
	for _, bad := range []map[string]interface{}{
		{"file": "/etc/shadow"},
		{"file": "postfix_domains"},
		{"file": "apache_site", "site": "../etc"},
		{"file": "apache_site", "site": "-x"},
		{"file": "postfix_main", "lines": 401.0},
		{"file": "postfix_main", "path": "/etc/shadow"},
	} {
		if _, err := Validate(p.Params, bad); err == nil {
			t.Errorf("%v must be refused", bad)
		}
	}
}

func TestFileHeadReadsRedactsAndCaps(t *testing.T) {
	root := withFileHeadRoot(t)
	writeUnder(t, root, "etc/rspamd/local.d/redis.conf", "servers = \"127.0.0.1:6379\";\npassword = \"hunter2\";\n")
	env := &ExecEnv{SiteRoot: "/var/www/html/joinerytest"}
	res, err := runFileHeadWith(t, env, map[string]interface{}{"file": "rspamd_redis"})
	if err != nil {
		t.Fatal(err)
	}
	text := res["text"].(string)
	if strings.Contains(text, "hunter2") || !strings.Contains(text, "password\n") || !strings.Contains(text, "127.0.0.1:6379") {
		t.Errorf("the password line must be the key alone and the address kept, got %q", text)
	}
	if res["path"] != "/etc/rspamd/local.d/redis.conf" || res["present"] != true {
		t.Errorf("path/present wrong: %v %v", res["path"], res["present"])
	}

	var long strings.Builder
	for i := 0; i < 500; i++ {
		long.WriteString("ServerName x\n")
	}
	writeUnder(t, root, "etc/apache2/sites-available/joinerytest.conf", long.String())
	res, _ = runFileHeadWith(t, env, map[string]interface{}{"file": "apache_site", "lines": 10.0})
	if res["lines_returned"] != 10 || res["truncated"] != true {
		t.Errorf("lines must cap at the asked count, got %v %v", res["lines_returned"], res["truncated"])
	}
}

func TestFileHeadSiteFilesUseTheNodesOwnSite(t *testing.T) {
	root := withFileHeadRoot(t)
	writeUnder(t, root, "etc/cron.d/joinery-mysite", "* * * * * root true\n")
	res, err := runFileHeadWith(t, &ExecEnv{SiteRoot: "/var/www/html/mysite"}, map[string]interface{}{"file": "cron_site"})
	if err != nil || res["present"] != true || res["path"] != "/etc/cron.d/joinery-mysite" {
		t.Fatalf("the node's own site should resolve: %v %v", res, err)
	}
	// A machine with no site must name one.
	if _, err := runFileHeadWith(t, &ExecEnv{}, map[string]interface{}{"file": "cron_site"}); err == nil || !Refused(err) {
		t.Errorf("a siteless machine with no site named must refuse, got %v", err)
	}
	res, err = runFileHeadWith(t, &ExecEnv{}, map[string]interface{}{"file": "cron_site", "site": "mysite"})
	if err != nil || res["present"] != true {
		t.Errorf("a named site on a machine should resolve: %v %v", res, err)
	}
}

func TestFileHeadAbsentIsReportedAndLinksAreNotFollowed(t *testing.T) {
	root := withFileHeadRoot(t)
	res, err := runFileHeadWith(t, &ExecEnv{}, map[string]interface{}{"file": "docker_daemon"})
	if err != nil || res["present"] != false {
		t.Fatalf("an absent file is reported absent: %v %v", res, err)
	}
	writeUnder(t, root, "secret/key", "BEGIN PRIVATE KEY\n")
	if err := os.MkdirAll(filepath.Join(root, "etc/docker"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "secret/key"), filepath.Join(root, "etc/docker/daemon.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := runFileHeadWith(t, &ExecEnv{}, map[string]interface{}{"file": "docker_daemon"}); err == nil || !Refused(err) {
		t.Errorf("a symlink in place of a listed file must refuse, got %v", err)
	}
}

func TestFileHeadPHPIniIsEffectiveLinesOfTheInstalledVersion(t *testing.T) {
	root := withFileHeadRoot(t)
	writeUnder(t, root, "etc/php/8.1/fpm/php.ini", "memory_limit = 64M\n")
	writeUnder(t, root, "etc/php/8.3/fpm/php.ini", "; a comment\n\n[PHP]\nmemory_limit = 256M\n;memory_limit = 1G\n")
	res, err := runFileHeadWith(t, &ExecEnv{}, map[string]interface{}{"file": "php_fpm_ini"})
	if err != nil {
		t.Fatal(err)
	}
	if res["path"] != "/etc/php/8.3/fpm/php.ini" || res["text"] != "[PHP]\nmemory_limit = 256M\n" {
		t.Errorf("php.ini should be 8.3's effective lines, got %v %q", res["path"], res["text"])
	}
}
