package primitives

import (
	"context"
	"database/sql/driver"
	"strings"
	"testing"
	"time"
)

// log_table_tail: the closed table list, the compiled columns, the caps, the
// switch. The load-bearing test is the one that proves an excluded column can
// never appear in any query this word builds.

func TestLogTableTailTakesOnlyTheClosedList(t *testing.T) {
	p, ok := Lookup("log_table_tail")
	if !ok {
		t.Fatal("log_table_tail should be registered")
	}
	if p.Class != ClassObserve {
		t.Fatalf("log_table_tail is %s; it reads and must be observe", p.Class)
	}
	for _, bad := range []interface{}{"users", "stg_settings", "log_logins", "logins; DROP TABLE x", ""} {
		if _, err := Validate(p.Params, map[string]interface{}{"table": bad}); err == nil {
			t.Errorf("table=%v must be refused by the enum", bad)
		}
	}
	for _, key := range []string{"columns", "where", "order", "sql", "since"} {
		if _, err := Validate(p.Params, map[string]interface{}{"table": "logins", key: "x"}); err == nil {
			t.Errorf("a job carrying %q must be refused; there is no pass-through", key)
		}
	}
	if _, err := Validate(p.Params, map[string]interface{}{"table": "logins", "rows": 201}); err == nil {
		t.Error("rows above the cap must be refused")
	}
	if _, err := Validate(p.Params, nil); err == nil {
		t.Error("table is required")
	}
}

func TestLogTableQueriesAreCompiledAndExcludeWhatTheSpecLeavesOut(t *testing.T) {
	if len(logTableNames) != len(logTables) {
		t.Fatalf("enum has %d words, table map has %d", len(logTableNames), len(logTables))
	}
	want := map[string][]string{
		"logins":      {"log_login_id", "log_usr_user_id", "log_login_time", "log_login_type"},
		"requests":    {"rql_request_log_id", "rql_feature", "rql_action", "rql_usr_user_id", "rql_was_success", "rql_status_code", "rql_error_type", "rql_note", "rql_api_key_type", "rql_response_ms", "rql_create_time"},
		"events":      {"evl_event_log_id", "evl_event", "evl_usr_user_id", "evl_create_time", "evl_was_success", "evl_note"},
		"form_errors": {"lfe_log_form_error_id", "lfe_error", "lfe_usr_user_id", "lfe_log_time", "lfe_page", "lfe_url", "lfe_context"},
		"webhooks":    {"wbh_webhook_log_id", "wbh_provider", "wbh_event_type", "wbh_event_id", "wbh_processed", "wbh_error_message", "wbh_create_time"},
	}
	for _, word := range logTableNames {
		query, spec, ok := logTableQuery(word)
		if !ok {
			t.Fatalf("no query for %s", word)
		}
		if strings.Join(spec.columns, ",") != strings.Join(want[word], ",") {
			t.Errorf("%s columns %v, want %v", word, spec.columns, want[word])
		}
		if strings.Contains(query, "*") {
			t.Errorf("%s selects *: %s", word, query)
		}
		if strings.Count(query, "$") != 1 || !strings.HasSuffix(query, "LIMIT $1") {
			t.Errorf("%s must carry exactly one placeholder, the limit: %s", word, query)
		}
		if !strings.Contains(query, "ORDER BY "+spec.timeColumn+" DESC") {
			t.Errorf("%s must order by its time column: %s", word, query)
		}
		for _, excluded := range logTableExcludedColumns {
			if strings.Contains(query, excluded) {
				t.Errorf("%s query names excluded column %s: %s", word, excluded, query)
			}
		}
	}
}

func logTableEnv(t *testing.T, setting string, answers map[string]fakeRows) *ExecEnv {
	t.Helper()
	t.Setenv("AGENT_STATE_DIR", t.TempDir())
	all := settingAnswer(setting)
	for k, v := range answers {
		all[k] = v
	}
	return &ExecEnv{SiteRoot: t.TempDir(), DB: fakeDB(all, nil)}
}

func TestLogTableTailRefusesWhenTheOwnerSaysNo(t *testing.T) {
	env := logTableEnv(t, "", nil)
	// Through Execute: the switch is the dispatcher's check
	// (Primitive.RequiresLogAccess), not this word's first line.
	_, err := Execute(context.Background(), env, ShippedPolicy(),
		Request{Primitive: "log_table_tail", Params: map[string]interface{}{"table": "logins"}})
	if err == nil || !Refused(err) || err.Error() != LogAccessRefusal {
		t.Fatalf("expected the owner's refusal, got %v", err)
	}
	// A marker saying on does not help this word: it needs the database, and
	// the database said off.
	if err := ProjectLogAccess(true); err != nil {
		t.Fatal(err)
	}
	_, err = Execute(context.Background(), env, ShippedPolicy(),
		Request{Primitive: "log_table_tail", Params: map[string]interface{}{"table": "logins"}})
	if err == nil || !Refused(err) {
		t.Fatalf("setting off must win over a marker, got %v", err)
	}
}

func TestLogTableTailShapesRedactsAndCaps(t *testing.T) {
	when := time.Date(2026, 9, 17, 23, 10, 0, 0, time.UTC)
	rows := make([][]driver.Value, 0, 120)
	for i := 0; i < 120; i++ {
		rows = append(rows, []driver.Value{int64(1000 - i), "mail", "send", int64(7), true, int64(200),
			nil, []byte("sent to jane@example.com from 203.0.113.9"), "browser", int64(12), when})
	}
	env := logTableEnv(t, "1", map[string]fakeRows{
		"FROM rql_request_logs": {columns: logTables["requests"].columns, rows: rows},
	})

	res, err := runLogTableTail(context.Background(), env, mustValidate(t, "log_table_tail", map[string]interface{}{"table": "requests"}))
	if err != nil {
		t.Fatal(err)
	}
	if res["rows_returned"] != logTableDefaultRows {
		t.Fatalf("absent rows must mean %d, got %v", logTableDefaultRows, res["rows_returned"])
	}
	if res["table"] != "requests" || res["truncated"] != false {
		t.Errorf("envelope: %v", res)
	}
	cols := res["columns"].([]interface{})
	if len(cols) != 11 || cols[0] != "rql_request_log_id" {
		t.Errorf("columns: %v", cols)
	}
	first := res["rows"].([]interface{})[0].(map[string]interface{})
	if first["rql_create_time"] != "2026-09-17T23:10:00Z" {
		t.Errorf("timestamps must be RFC3339 strings, got %v", first["rql_create_time"])
	}
	if first["rql_note"] != "sent to <email>@example.com from <ip>" {
		t.Errorf("text must be redacted, got %v", first["rql_note"])
	}
	if first["rql_error_type"] != nil || first["rql_was_success"] != true || first["rql_request_log_id"] != int64(1000) {
		t.Errorf("typed values: %v", first)
	}
	for _, excluded := range logTableExcludedColumns {
		if _, present := first[excluded]; present {
			t.Errorf("excluded column %s in the result", excluded)
		}
	}

	res, _ = runLogTableTail(context.Background(), env, mustValidate(t, "log_table_tail", map[string]interface{}{"table": "requests", "rows": 3}))
	if res["rows_returned"] != 3 {
		t.Fatalf("rows=3 returned %v", res["rows_returned"])
	}
}

func TestLogTableTailByteCap(t *testing.T) {
	big := strings.Repeat("z", 1000)
	rows := make([][]driver.Value, 0, 200)
	for i := 0; i < 200; i++ {
		rows = append(rows, []driver.Value{int64(i), big, int64(1), time.Now(), true, big})
	}
	env := logTableEnv(t, "1", map[string]fakeRows{
		"FROM evl_event_logs": {columns: logTables["events"].columns, rows: rows},
	})
	res, err := runLogTableTail(context.Background(), env, mustValidate(t, "log_table_tail", map[string]interface{}{"table": "events", "rows": 200}))
	if err != nil {
		t.Fatal(err)
	}
	n := res["rows_returned"].(int)
	if n >= 200 || n < 20 {
		t.Fatalf("2 KiB rows under a 48 KiB cap should stop near 23, got %d", n)
	}
	if res["truncated"] != true {
		t.Error("a byte-capped read must say truncated")
	}
}

func TestLogTableTailNeedsTheDatabase(t *testing.T) {
	t.Setenv("AGENT_STATE_DIR", t.TempDir())
	if err := ProjectLogAccess(true); err != nil {
		t.Fatal(err)
	}
	env := &ExecEnv{SiteRoot: t.TempDir(), DB: fakeDB(nil, errDown)}
	_, err := runLogTableTail(context.Background(), env, mustValidate(t, "log_table_tail", map[string]interface{}{"table": "logins"}))
	if err == nil {
		t.Fatal("a down database is a legible failure, not an empty answer")
	}
	if Refused(err) {
		// The switch rule falls back to the marker, which says on; the failure
		// is then the database itself, and it must read as that.
		t.Fatalf("a down database is a failure, not a refusal: %v", err)
	}
}
