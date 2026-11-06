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
	if _, err := Validate(p.Params, map[string]interface{}{"table": "logins", "rows": 1001}); err == nil {
		t.Error("rows above the cap must be refused")
	}
	// 201 to 1000 pass validation and are refused at run time without an
	// event (TestLogTableTailEventRead).
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

// event and hours (specs/agent_event_log_filter.md).

func TestLogTableTailEventAndHoursAreClosed(t *testing.T) {
	p, _ := Lookup("log_table_tail")
	for _, bad := range []interface{}{"login", "vault_window", "vault_windows'; --", ""} {
		if _, err := Validate(p.Params, map[string]interface{}{"table": "events", "event": bad}); err == nil {
			t.Errorf("event=%v must be refused by the enum", bad)
		}
	}
	for _, bad := range []interface{}{0, 169, -1} {
		if _, err := Validate(p.Params, map[string]interface{}{"table": "events", "hours": bad}); err == nil {
			t.Errorf("hours=%v must be refused", bad)
		}
	}
	if _, err := Validate(p.Params, map[string]interface{}{"table": "events", "event": "vault_windows", "rows": 1001}); err == nil {
		t.Error("rows above the event ceiling must be refused")
	}
	if len(logEventNames) != len(logEvents) {
		t.Fatalf("event enum has %d words, map has %d", len(logEventNames), len(logEvents))
	}
}

func TestLogTableTailEventQueries(t *testing.T) {
	for _, event := range logEventNames {
		for _, hours := range []bool{false, true} {
			query, _, ok := logTableQueryFor("events", event, hours)
			if !ok {
				t.Fatalf("no query for event %s", event)
			}
			for _, name := range logEvents[event] {
				if !strings.Contains(query, "'"+name+"'") {
					t.Errorf("%s query does not select %s: %s", event, name, query)
				}
			}
			want := 1
			if hours {
				want = 2
				if !strings.Contains(query, "evl_create_time >= now() - make_interval(hours => $2::int)") {
					t.Errorf("hours must bound the time column with $2: %s", query)
				}
			}
			if strings.Count(query, "$") != want || !strings.HasSuffix(query, "LIMIT $1") {
				t.Errorf("%s (hours %v) must carry %d placeholders, the limit last: %s", event, hours, want, query)
			}
			for _, excluded := range logTableExcludedColumns {
				if strings.Contains(query, excluded) {
					t.Errorf("%s query names excluded column %s", event, excluded)
				}
			}
		}
	}
	if _, _, ok := logTableQueryFor("logins", "vault_windows", false); ok {
		t.Error("an event narrows table=events only")
	}
	if q, _, ok := logTableQueryFor("logins", "", true); !ok || !strings.Contains(q, "log_login_time >= now()") {
		t.Errorf("hours bounds any table by its own time column: %s", q)
	}
}

func TestLogTableTailEventRead(t *testing.T) {
	when := time.Date(2026, 11, 6, 9, 14, 0, 0, time.UTC)
	rows := make([][]driver.Value, 0, 600)
	for i := 0; i < 600; i++ {
		rows = append(rows, []driver.Value{int64(5000 - i), "vault_window_closed", int64(7), when, true,
			"scope=user reason=explicit_lock session=3f9a1c0b7d2e open_seconds=120 unwraps=14"})
	}
	env := logTableEnv(t, "1", map[string]fakeRows{
		"evl_event IN ('vault_window_opened', 'vault_window_closed')": {columns: logTables["events"].columns, rows: rows},
	})
	res, err := runLogTableTail(context.Background(), env, mustValidate(t, "log_table_tail",
		map[string]interface{}{"table": "events", "event": "vault_windows", "hours": 24, "rows": 600}))
	if err != nil {
		t.Fatal(err)
	}
	if res["rows_returned"] != 600 || res["truncated"] != false {
		t.Fatalf("600 vault rows fit an event read: %v rows, truncated %v", res["rows_returned"], res["truncated"])
	}
	if res["event"] != "vault_windows" || res["hours"] != int64(24) {
		t.Errorf("event and hours are echoed: %v %v", res["event"], res["hours"])
	}
	first := res["rows"].([]interface{})[0].(map[string]interface{})
	if !strings.Contains(first["evl_note"].(string), "session=3f9a1c0b7d2e") {
		t.Errorf("the session handle must survive redaction, for pairing: %v", first["evl_note"])
	}

	// Without an event, the ceiling stays 200; an event off table=events is refused.
	if _, err := runLogTableTail(context.Background(), env, mustValidate(t, "log_table_tail",
		map[string]interface{}{"table": "events", "rows": 201})); err == nil || !Refused(err) {
		t.Errorf("rows above 200 without an event must be refused, got %v", err)
	}
	if _, err := runLogTableTail(context.Background(), env, mustValidate(t, "log_table_tail",
		map[string]interface{}{"table": "logins", "event": "vault_windows"})); err == nil || !Refused(err) {
		t.Errorf("an event on another table must be refused, got %v", err)
	}
}
