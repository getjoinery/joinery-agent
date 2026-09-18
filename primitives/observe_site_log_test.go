package primitives

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// site_log: the closed file list, the caps, and the switch. The tests are about
// what the hostile-caller review relies on: no path arrives from the wire, the
// read never leaves the site's log directory, and nothing is read when the
// owner has said no.

func siteLogEnv(t *testing.T, setting string) *ExecEnv {
	t.Helper()
	t.Setenv("AGENT_STATE_DIR", t.TempDir())
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "logs"), 0755); err != nil {
		t.Fatal(err)
	}
	return &ExecEnv{SiteRoot: root, WebRoot: filepath.Join(root, "public_html"), DB: fakeDB(settingAnswer(setting), nil)}
}

func writeLog(t *testing.T, env *ExecEnv, name, text string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(env.SiteRoot, "logs", name), []byte(text), 0644); err != nil {
		t.Fatal(err)
	}
}

func TestSiteLogTakesOnlyTheClosedList(t *testing.T) {
	p, ok := Lookup("site_log")
	if !ok {
		t.Fatal("site_log should be registered")
	}
	if p.Class != ClassObserve {
		t.Fatalf("site_log is %s; it reads and must be observe", p.Class)
	}
	for _, bad := range []interface{}{"access", "../config/Globalvars_site", "/etc/passwd", "error.log", "error/../../x", ""} {
		if _, err := Validate(p.Params, map[string]interface{}{"file": bad}); err == nil {
			t.Errorf("file=%v must be refused by the enum", bad)
		}
	}
	for _, key := range []string{"path", "glob", "since", "grep"} {
		if _, err := Validate(p.Params, map[string]interface{}{"file": "error", key: "x"}); err == nil {
			t.Errorf("a job carrying %q must be refused; there is no pass-through", key)
		}
	}
	if _, err := Validate(p.Params, map[string]interface{}{"file": "error", "lines": 201}); err == nil {
		t.Error("lines above the cap must be refused")
	}
	if _, err := Validate(p.Params, map[string]interface{}{"file": "error", "lines": 0}); err == nil {
		t.Error("lines of zero must be refused")
	}
	if _, err := Validate(p.Params, nil); err == nil {
		t.Error("file is required")
	}
}

func TestSiteLogResolvesUnderTheLogDirectoryOnly(t *testing.T) {
	for _, name := range siteLogFiles {
		for _, previous := range []bool{false, true} {
			got := siteLogPath("/srv/site", name, previous)
			if !strings.HasPrefix(got, "/srv/site/logs/") {
				t.Errorf("%s previous=%v resolved to %s, outside the log directory", name, previous, got)
			}
			if strings.HasSuffix(got, ".gz") {
				t.Errorf("%s resolved to a compressed rotation %s", name, got)
			}
			if previous && !strings.HasSuffix(got, ".log.1") {
				t.Errorf("previous must be the .1 rotation, got %s", got)
			}
			if !previous && !strings.HasSuffix(got, ".log") {
				t.Errorf("current must be the .log file, got %s", got)
			}
		}
	}
}

func TestSiteLogRefusesWhenTheOwnerSaysNo(t *testing.T) {
	env := siteLogEnv(t, "0")
	writeLog(t, env, "error.log", "a secret line\n")
	_, err := runSiteLog(context.Background(), env, mustValidate(t, "site_log", map[string]interface{}{"file": "error"}))
	if err == nil || !Refused(err) || err.Error() != LogAccessRefusal {
		t.Fatalf("expected the owner's refusal, got %v", err)
	}
}

func TestSiteLogRefusesInEveryOffState(t *testing.T) {
	p := mustValidate(t, "site_log", map[string]interface{}{"file": "error"})
	// Database down, marker off.
	env := siteLogEnv(t, "")
	env.DB = fakeDB(nil, errDown)
	if err := ProjectLogAccess(false); err != nil {
		t.Fatal(err)
	}
	if _, err := runSiteLog(context.Background(), env, p); err == nil || !Refused(err) {
		t.Fatalf("db down + marker off: expected refusal, got %v", err)
	}
	// Database down, marker missing.
	env = siteLogEnv(t, "")
	env.DB = fakeDB(nil, errDown)
	if _, err := runSiteLog(context.Background(), env, p); err == nil || !Refused(err) {
		t.Fatalf("db down + no marker: expected refusal, got %v", err)
	}
	// Database down, marker on: the file word works.
	if err := ProjectLogAccess(true); err != nil {
		t.Fatal(err)
	}
	writeLog(t, env, "error.log", "line one\nline two\n")
	res, err := runSiteLog(context.Background(), env, p)
	if err != nil {
		t.Fatalf("db down + marker on: %v", err)
	}
	if res["text"] != "line one\nline two\n" {
		t.Fatalf("text: %q", res["text"])
	}
}

func TestSiteLogMissingFileIsPresentFalse(t *testing.T) {
	env := siteLogEnv(t, "1")
	res, err := runSiteLog(context.Background(), env, mustValidate(t, "site_log", map[string]interface{}{"file": "joinery_ai_worker"}))
	if err != nil {
		t.Fatalf("a missing log is not an error: %v", err)
	}
	if res["present"] != false || res["text"] != "" || res["lines_returned"] != 0 {
		t.Fatalf("missing file result: %v", res)
	}
}

func TestSiteLogTailsAndCaps(t *testing.T) {
	env := siteLogEnv(t, "1")
	var b strings.Builder
	for i := 1; i <= 300; i++ {
		b.WriteString("line ")
		b.WriteString(strings.Repeat("x", 3))
		b.WriteString(" ")
		b.WriteString(itoa(i))
		b.WriteString("\n")
	}
	writeLog(t, env, "error.log", b.String())

	res, err := runSiteLog(context.Background(), env, mustValidate(t, "site_log", map[string]interface{}{"file": "error"}))
	if err != nil {
		t.Fatal(err)
	}
	if res["lines_returned"] != siteLogDefaultLines {
		t.Fatalf("absent lines must mean %d, got %v", siteLogDefaultLines, res["lines_returned"])
	}
	text := res["text"].(string)
	if !strings.HasPrefix(text, "line xxx 201\n") || !strings.HasSuffix(text, "line xxx 300\n") {
		t.Fatalf("expected the last 100 lines, got %q...%q", text[:20], text[len(text)-20:])
	}
	if res["truncated"] != true {
		t.Error("dropping lines must say truncated")
	}
	if res["present"] != true || res["size_bytes"].(int64) == 0 || res["modified_time"] == "" {
		t.Errorf("file facts: %v", res)
	}

	res, _ = runSiteLog(context.Background(), env, mustValidate(t, "site_log", map[string]interface{}{"file": "error", "lines": 5}))
	if res["lines_returned"] != 5 {
		t.Fatalf("lines=5 returned %v", res["lines_returned"])
	}

	// The byte cap: 200 lines of 1 KiB is 200 KiB; only the last 32 KiB are
	// read, cut to a line boundary.
	b.Reset()
	for i := 0; i < 200; i++ {
		b.WriteString(strings.Repeat("y", 1023))
		b.WriteString("\n")
	}
	writeLog(t, env, "error.log", b.String())
	res, _ = runSiteLog(context.Background(), env, mustValidate(t, "site_log", map[string]interface{}{"file": "error", "lines": 200}))
	if n := res["lines_returned"].(int); n > 32 || n < 30 {
		t.Fatalf("byte cap should leave about 31 whole lines, got %d", n)
	}
	if len(res["text"].(string)) > siteLogMaxBytes {
		t.Fatal("text exceeds the byte cap")
	}
	if res["truncated"] != true {
		t.Error("a byte-capped read must say truncated")
	}
}

func TestSiteLogReadsThePreviousRotationOnly(t *testing.T) {
	env := siteLogEnv(t, "1")
	writeLog(t, env, "error.log", "today\n")
	writeLog(t, env, "error.log.1", "yesterday\n")
	writeLog(t, env, "error.log.2.gz", "compressed\n")
	res, err := runSiteLog(context.Background(), env, mustValidate(t, "site_log", map[string]interface{}{"file": "error", "previous": true}))
	if err != nil {
		t.Fatal(err)
	}
	if res["text"] != "yesterday\n" || res["previous"] != true {
		t.Fatalf("previous: %v", res)
	}
}

func TestSiteLogRedactsBeforeReturning(t *testing.T) {
	env := siteLogEnv(t, "1")
	writeLog(t, env, "error.log", "mail to jane@example.com failed; PGPASSWORD=hunter2; from 203.0.113.9\n")
	res, err := runSiteLog(context.Background(), env, mustValidate(t, "site_log", map[string]interface{}{"file": "error"}))
	if err != nil {
		t.Fatal(err)
	}
	text := res["text"].(string)
	for _, leaked := range []string{"jane@", "hunter2", "203.0.113.9"} {
		if strings.Contains(text, leaked) {
			t.Errorf("%q left the node: %q", leaked, text)
		}
	}
	if !strings.Contains(text, "<email>@example.com") {
		t.Errorf("the domain should survive: %q", text)
	}
}

// helpers shared by the log word tests

var errDown = errDownType{}

type errDownType struct{}

func (errDownType) Error() string { return "connection refused" }

func mustValidate(t *testing.T, word string, raw map[string]interface{}) Params {
	t.Helper()
	p, ok := Lookup(word)
	if !ok {
		t.Fatalf("%s should be registered", word)
	}
	params, err := Validate(p.Params, raw)
	if err != nil {
		t.Fatalf("validate %v: %v", raw, err)
	}
	return params
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var digits []byte
	for i > 0 {
		digits = append([]byte{byte('0' + i%10)}, digits...)
		i /= 10
	}
	return string(digits)
}
