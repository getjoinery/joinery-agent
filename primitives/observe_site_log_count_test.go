package primitives

import (
	"bytes"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// site_log_count: the closed parameter list, the walk back through the
// rotations, and the promise that a window it could not reach is said so.

func apacheLine(t time.Time, msg string) string {
	return "[" + t.Format("Mon Jan 02 15:04:05.000000 2006") + "] [proxy_fcgi:error] [pid 1] " + msg + "\n"
}

func writeGz(t *testing.T, env *ExecEnv, name, text string) {
	t.Helper()
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	w.Write([]byte(text))
	w.Close()
	if err := os.WriteFile(filepath.Join(env.SiteRoot, "logs", name), b.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}
}

func marker(res map[string]interface{}, name string) map[string]interface{} {
	return res["markers"].(map[string]interface{})[name].(map[string]interface{})
}

func TestSiteLogCountTakesOnlySince(t *testing.T) {
	p, ok := Lookup("site_log_count")
	if !ok {
		t.Fatal("site_log_count should be registered")
	}
	if p.Class != ClassObserve || !p.RequiresLogAccess {
		t.Fatal("site_log_count reads a log: observe, behind the owner's switch")
	}
	for _, key := range []string{"file", "path", "pattern", "grep", "lines"} {
		if _, err := Validate(p.Params, map[string]interface{}{"since": 1, key: "x"}); err == nil {
			t.Errorf("a job carrying %q must be refused; there is no pass-through", key)
		}
	}
	if _, err := Validate(p.Params, nil); err == nil {
		t.Error("since is required")
	}
}

func TestSiteLogCountReadsBackThroughRotations(t *testing.T) {
	env := siteLogEnv(t, "on")
	loc := time.UTC
	base := time.Date(2026, 10, 22, 23, 0, 0, 0, loc)
	since := base.Add(7 * time.Minute)

	// .2.gz: before the window, with a marker that must not count.
	writeGz(t, env, "error.log.2.gz", apacheLine(base.Add(-48*time.Hour), "PHP Fatal error: old")+apacheLine(base.Add(-25*time.Hour), "x"))
	// .1: starts before since, holds the swap-time miss.
	writeLog(t, env, "error.log.1",
		apacheLine(base, "PHP Fatal error: before the window")+
			apacheLine(since.Add(10*time.Second), "PHP message: PHP Warning: require(): Failed opening required '/var/www/x/public_html/serve.php'")+
			"  continuation without a time [GET_WRITE] counted at the line before\n")
	// current: newer than since, noise only plus one CRITICAL.
	noise := strings.Repeat(apacheLine(since.Add(30*time.Minute), "ROUTING ERROR: .php extension in URL"), 500)
	writeLog(t, env, "error.log", noise+apacheLine(since.Add(31*time.Minute), `PHP message: {"level":"CRITICAL","message":"x"}`))

	res, err := siteLogCount(context.Background(), env, since, loc)
	if err != nil {
		t.Fatal(err)
	}
	if res["covers_since"] != true {
		t.Fatalf("the read reached a line before since and must say it covers: %v", res["not_covered"])
	}
	if got := res["files_read"].([]string); len(got) != 2 {
		t.Fatalf("the walk stops at the first file reaching since; read %v", got)
	}
	if c := marker(res, "entry_script_missing")["count"]; c != 1 {
		t.Errorf("the serve.php miss in .1 must count once, got %v", c)
	}
	if c := marker(res, "php_fatal")["count"]; c != 0 {
		t.Errorf("fatals before since must not count, got %v", c)
	}
	if c := marker(res, "critical")["count"]; c != 1 {
		t.Errorf("CRITICAL in the current file must count, got %v", c)
	}
	if c := marker(res, "get_write")["count"]; c != 1 {
		t.Errorf("a continuation line inside the window must count, got %v", c)
	}
	if s := marker(res, "entry_script_missing")["samples"].([]string); len(s) != 1 || !strings.Contains(s[0], "serve.php") {
		t.Errorf("one sample of the miss is carried, got %v", s)
	}
}

func TestSiteLogCountSaysWhenItCannotReachSince(t *testing.T) {
	env := siteLogEnv(t, "on")
	loc := time.UTC
	since := time.Date(2026, 10, 22, 23, 7, 0, 0, loc)
	writeLog(t, env, "error.log", apacheLine(since.Add(20*time.Minute), "noise"))
	res, err := siteLogCount(context.Background(), env, since, loc)
	if err != nil {
		t.Fatal(err)
	}
	if res["covers_since"] != false {
		t.Fatal("a log that starts after since must not claim to cover it")
	}
	if nc, _ := res["not_covered"].(string); !strings.Contains(nc, "error.log.1") {
		t.Errorf("the reason names what is missing, got %q", nc)
	}
	if res["covered_from"] != since.Add(20*time.Minute).UTC().Format(time.RFC3339) {
		t.Errorf("covered_from is the oldest line read, got %v", res["covered_from"])
	}
}

func TestSiteLogCountWithNoLog(t *testing.T) {
	env := siteLogEnv(t, "on")
	res, err := siteLogCount(context.Background(), env, time.Now(), time.UTC)
	if err != nil {
		t.Fatal(err)
	}
	if res["present"] != false || res["covers_since"] != false || res["not_covered"] == "" {
		t.Fatalf("no log at all is present false, not covered, with a reason: %v", res)
	}
}

func TestSiteLogCountParsesApacheTimes(t *testing.T) {
	for _, s := range []string{
		"[Thu Oct 22 23:13:52.679400 2026] [x] y",
		"[Fri Oct 02 00:02:12.230137 2026] [x] y",
		"[Fri Oct  2 00:02:12.230137 2026] [x] y",
	} {
		if _, ok := lineTime(s, time.UTC); !ok {
			t.Errorf("%q must parse", s)
		}
	}
	if _, ok := lineTime("  #0 /var/www/x.php(12)", time.UTC); ok {
		t.Error("a trace line has no time")
	}
}

func cronLine(t time.Time, msg string) string {
	return "[" + t.UTC().Format("2006-01-02 15:04:05") + "] " + msg + "\n"
}

// A send or a DNS publish run from cron writes its error_log() line to the
// runner's stderr, which the cron entry appends to cron_scheduled_tasks.log,
// bare and untimed. Those lines count, at the time of the runner line before
// them, and a cron log that does not reach since makes the answer uncovered.
func TestSiteLogCountReadsTheScheduledTaskLog(t *testing.T) {
	env := siteLogEnv(t, "on")
	loc := time.UTC
	since := time.Date(2026, 11, 14, 17, 0, 0, 0, loc)
	writeLog(t, env, "error.log", apacheLine(since.Add(-time.Minute), "x")+
		apacheLine(since.Add(time.Minute), "PHP message: AuthoritativeDns: fallback to system resolver for example.com: CNAME answer"))
	writeLog(t, env, "cron_scheduled_tasks.log",
		cronLine(since.Add(-2*time.Minute), "Running task: Send queued campaigns (SendCampaigns)")+
			"MailboxDkimSigner: relay-fronted send for example.com leaving UNSIGNED — DKIM key missing\n"+
			cronLine(since.Add(2*time.Minute), "Running task: Send queued campaigns (SendCampaigns)")+
			"MailboxDkimSigner: relay-fronted send for example.com leaving UNSIGNED — DKIM key missing\n"+
			"DnsReconciler: record failed: create TXT _dmarc.example.com in example.com (RuntimeException)\n")

	res, err := siteLogCount(context.Background(), env, since, loc)
	if err != nil {
		t.Fatal(err)
	}
	if res["covers_since"] != true {
		t.Fatalf("both logs reach before since: %v", res["not_covered"])
	}
	if c := marker(res, "dkim_unsigned")["count"]; c != 1 {
		t.Errorf("only the unsigned line after since counts, at its runner line's time; got %v", c)
	}
	if c := marker(res, "dns_reconciler_failed")["count"]; c != 1 {
		t.Errorf("the reconciler's failed record counts from the cron log, got %v", c)
	}
	if c := marker(res, "authoritative_dns_fallback")["count"]; c != 1 {
		t.Errorf("the fallback line in the error log counts, got %v", c)
	}
	files := strings.Join(res["files_read"].([]string), ",")
	if !strings.Contains(files, "error.log") || !strings.Contains(files, "cron_scheduled_tasks.log") {
		t.Errorf("both logs are read, got %v", files)
	}
	logs := res["logs"].(map[string]interface{})
	if logs["cron_scheduled_tasks"].(map[string]interface{})["covers_since"] != true {
		t.Error("the cron log's own coverage is reported")
	}

	// A cron log whose oldest stamped line is after since: the whole answer
	// is uncovered and says which log fell short.
	writeLog(t, env, "cron_scheduled_tasks.log", cronLine(since.Add(5*time.Minute), "Running task: x"))
	res, err = siteLogCount(context.Background(), env, since, loc)
	if err != nil {
		t.Fatal(err)
	}
	if res["covers_since"] != false {
		t.Fatal("a cron log starting after since must make the answer uncovered")
	}
	if nc, _ := res["not_covered"].(string); !strings.Contains(nc, "cron_scheduled_tasks.log") {
		t.Errorf("the reason names the cron log, got %q", nc)
	}
}

// A site with no scheduled-task log has run nothing from cron: the error log
// alone decides coverage.
func TestSiteLogCountWithNoCronLog(t *testing.T) {
	env := siteLogEnv(t, "on")
	since := time.Date(2026, 11, 14, 17, 0, 0, 0, time.UTC)
	writeLog(t, env, "error.log", apacheLine(since.Add(-time.Minute), "x"))
	res, err := siteLogCount(context.Background(), env, since, time.UTC)
	if err != nil {
		t.Fatal(err)
	}
	if res["covers_since"] != true {
		t.Fatalf("no cron log is nothing missed: %v", res["not_covered"])
	}
	if res["logs"].(map[string]interface{})["cron_scheduled_tasks"].(map[string]interface{})["present"] != false {
		t.Error("the absent cron log is reported absent")
	}
}

func TestSiteLogCountParsesCronTimes(t *testing.T) {
	got, ok := cronLineTime("[2026-11-14 17:34:02] Running task: x")
	if !ok || !got.Equal(time.Date(2026, 11, 14, 17, 34, 2, 0, time.UTC)) {
		t.Errorf("a runner line's time is UTC, got %v %v", got, ok)
	}
	if _, ok := cronLineTime("MailboxDkimSigner: leaving UNSIGNED"); ok {
		t.Error("a bare stderr line has no time")
	}
}

// The three markers match the platform's own log prefixes exactly.
func TestSiteLogCountMailAndDnsMarkers(t *testing.T) {
	want := map[string]string{
		"dkim_unsigned":              "MailboxDkimSigner: relay-fronted send for a.example leaving UNSIGNED — DKIM key missing",
		"authoritative_dns_fallback": "AuthoritativeDns: fallback to system resolver for a.example: reply truncated",
		"dns_reconciler_failed":      "DnsReconciler: record failed: update MX a.example in a.example (Exception)",
	}
	for name, line := range want {
		found := false
		for _, m := range siteLogMarkers {
			if m.Name == name {
				found = true
				if !lineHasAll(line, m.All) {
					t.Errorf("%s does not match the platform's line %q", name, line)
				}
			}
		}
		if !found {
			t.Errorf("marker %s is missing", name)
		}
	}
}
