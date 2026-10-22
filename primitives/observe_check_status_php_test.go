package primitives

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// check_status says which PHP is installed and whether each php-fpm master
// still runs a binary an upgrade replaced (fleet_security_patching WP1): on
// 2026-10-21 six site containers served the unpatched PHP after their packages
// were upgraded, and nothing said so.
func TestCollectPHPReportsPackagesAndOldCodeServing(t *testing.T) {
	dir := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("dpkg/status", "Package: php8.5-fpm\nStatus: install ok installed\nVersion: 8.5.4-0ubuntu1.3\n\n"+
		"Package: php8.5-cli\nStatus: install ok installed\nVersion: 8.5.4-0ubuntu1.3\n\n"+
		"Package: php8.5-common\nStatus: deinstall ok config-files\nVersion: 8.5.4-0ubuntu1.1\n\n"+
		"Package: php8.5-mbstring\nStatus: install ok installed\nVersion: 8.5.4-0ubuntu1.3\n\n"+
		"Package: apache2\nStatus: install ok installed\nVersion: 2.4.66-2ubuntu2.5\n")
	proc := filepath.Join(dir, "proc")
	write("proc/stat", "cpu  1 2 3\nbtime 1761000000\n")
	stat := func(pid, comm, ppid string, ticks string) string {
		// pid (comm) state ppid pgrp session tty tpgid flags minflt cminflt majflt cmajflt utime stime cutime cstime priority nice threads itreal starttime
		return pid + " (" + comm + ") S " + ppid + " 1 1 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 " + ticks + " 0 0\n"
	}
	// The master on a replaced binary, two workers of it, one worker of
	// another master, and processes that are no php-fpm.
	write("proc/100/cmdline", "php-fpm: master process (/etc/php/8.5/fpm/php-fpm.conf)\x00")
	write("proc/100/stat", stat("100", "php-fpm8.5", "1", "50000"))
	write("proc/101/cmdline", "php-fpm: pool www\x00\x00")
	write("proc/101/stat", stat("101", "php-fpm8.5", "100", "70000"))
	write("proc/102/cmdline", "php-fpm: pool www\x00")
	write("proc/102/stat", stat("102", "php-fpm8.5", "100", "60000"))
	write("proc/200/cmdline", "php-fpm: master process (/etc/php/8.3/fpm/php-fpm.conf)\x00")
	write("proc/200/stat", stat("200", "weird ) name", "1", "90000"))
	write("proc/201/cmdline", "php-fpm: pool www\x00")
	write("proc/201/stat", stat("201", "php-fpm8.3", "200", "95000"))
	write("proc/300/cmdline", "/usr/sbin/apache2\x00-k\x00start\x00")
	write("proc/300/stat", stat("300", "apache2", "1", "1000"))
	write("proc/self/cmdline", "x")
	if err := os.Symlink("/usr/sbin/php-fpm8.5 (deleted)", filepath.Join(proc, "100", "exe")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/usr/sbin/php-fpm8.3", filepath.Join(proc, "200", "exe")); err != nil {
		t.Fatal(err)
	}

	write("dpkg/info/php8.5-fpm.list", "/usr/sbin/php-fpm8.5\n")
	when := time.Unix(1761000400, 0)
	if err := os.Chtimes(filepath.Join(dir, "dpkg/info/php8.5-fpm.list"), when, when); err != nil {
		t.Fatal(err)
	}
	saved := []string{dpkgStatusPath, procRoot, dpkgInfoDir}
	defer func() { dpkgStatusPath, procRoot, dpkgInfoDir = saved[0], saved[1], saved[2] }()
	dpkgStatusPath, procRoot, dpkgInfoDir = filepath.Join(dir, "dpkg/status"), proc, filepath.Join(dir, "dpkg/info")

	r := map[string]interface{}{}
	collectPHP(r)
	php, ok := r["php"].(map[string]interface{})
	if !ok {
		t.Fatalf("a machine with PHP reports it, got %v", r)
	}
	pkgs := php["packages"].([]map[string]interface{})
	if len(pkgs) != 2 || pkgs[0]["name"] != "php8.5-cli" || pkgs[1]["name"] != "php8.5-fpm" || pkgs[1]["version"] != "8.5.4-0ubuntu1.3" {
		t.Fatalf("the installed fpm and cli, by name with versions; a removed package and an extension are not listed, got %v", pkgs)
	}
	if pkgs[1]["installed_at"] != int64(1761000400) {
		t.Fatalf("a package's install time is its dpkg file list's, got %v", pkgs[1])
	}
	if _, has := pkgs[0]["installed_at"]; has {
		t.Fatalf("a package with no file list has no install time, got %v", pkgs[0])
	}
	fpm := php["fpm"].([]map[string]interface{})
	if len(fpm) != 2 {
		t.Fatalf("two masters, got %v", fpm)
	}
	if fpm[0]["binary"] != "/usr/sbin/php-fpm8.5" || fpm[0]["running_current"] != false {
		t.Fatalf("a master whose binary was replaced is not running the current code, got %v", fpm[0])
	}
	if fpm[0]["started_at"] != int64(1761000500) || fpm[0]["oldest_worker_started_at"] != int64(1761000600) {
		t.Fatalf("the master's start and its oldest worker's, from btime and the start ticks, got %v", fpm[0])
	}
	if fpm[1]["binary"] != "/usr/sbin/php-fpm8.3" || fpm[1]["running_current"] != true || fpm[1]["oldest_worker_started_at"] != int64(1761000950) {
		t.Fatalf("a master on its installed binary (a name with a parenthesis in it read past), got %v", fpm[1])
	}

	// A master whose binary /proc will not show: no claim either way.
	if err := os.Remove(filepath.Join(proc, "200", "exe")); err != nil {
		t.Fatal(err)
	}
	r = map[string]interface{}{}
	collectPHP(r)
	second := r["php"].(map[string]interface{})["fpm"].([]map[string]interface{})[1]
	if _, has := second["running_current"]; has {
		t.Fatalf("unreadable is absent, never true or false, got %v", second)
	}

	// No PHP at all (a Docker host): no key.
	dpkgStatusPath, procRoot = filepath.Join(dir, "absent"), filepath.Join(dir, "absent")
	r = map[string]interface{}{}
	collectPHP(r)
	if _, has := r["php"]; has {
		t.Fatalf("a machine with no PHP reports none, got %v", r)
	}
}
