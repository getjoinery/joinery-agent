package primitives

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// quiet_check (specs/automatic_reboot_when_quiet.md WP1) takes nothing from
// the wire and passes only the node's own site root, when it is a plain
// absolute path.
func TestQuietCheckAsksForNothing(t *testing.T) {
	p, ok := Lookup("quiet_check")
	if !ok {
		t.Fatal("quiet_check should be registered")
	}
	if p.Class != ClassObserve || !p.Machine {
		t.Fatalf("quiet_check is an observe word every machine answers")
	}
	if len(p.Params) != 0 {
		t.Fatalf("quiet_check declares %d parameter(s); it must declare none", len(p.Params))
	}
	for _, key := range []string{"site", "root", "path", "window", "minutes"} {
		if _, err := Validate(p.Params, map[string]interface{}{key: "anything"}); err == nil {
			t.Errorf("a job carrying %q must be refused", key)
		}
	}
	if p.Script == nil || p.Run != nil || p.Script.ScriptPath != quietCheckScript || p.Script.Interpreter != "/bin/bash" || p.Script.Redact {
		t.Fatal("quiet_check runs the one script it names")
	}
	for root, want := range map[string][]string{
		"/var/www/html/demo":      {"/var/www/html/demo", "unknown"},
		"":                        {},
		"relative/site":           {},
		"/var/www/html/../../etc": {},
		"/var/www/html/a b":       {},
		"/var/www/html/$(id)":     {},
	} {
		got, err := quietCheckArgs(context.Background(), &ExecEnv{SiteRoot: root}, Params{})
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("site root %q: args %v (err %v), want %v", root, got, err, want)
		}
	}
	if got, _ := quietCheckArgs(context.Background(), nil, Params{}); len(got) != 0 {
		t.Errorf("no environment: args %v, want none", got)
	}
	// A database that cannot be asked is unknown, which the script counts as busy.
	failing := &ExecEnv{SiteRoot: "/var/www/html/demo", DB: func() (*sql.DB, error) { return nil, errors.New("down") }}
	if got, _ := quietCheckArgs(context.Background(), failing, Params{}); !reflect.DeepEqual(got, []string{"/var/www/html/demo", "unknown"}) {
		t.Errorf("database down: args %v, want the root and unknown", got)
	}
	if !strings.Contains(quietCheckLongQueries, "pg_stat_activity") || strings.Contains(quietCheckLongQueries, "query,") {
		t.Error("the long-query statement counts rows of pg_stat_activity and reads no query text")
	}
}
