package primitives

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"joinery-agent/redact"
)

// log_table_tail: the newest rows of one of the site's own log tables, from a
// compiled list with a compiled column list per table, redacted on this
// machine before they leave it (specs/agent_log_access.md §2.2).
//
// HOSTILE-CALLER REVIEW (rule 5 of specs/agent_recipes_and_vocabulary.md).
//
// What is the worst a compromised management node can do with this word? Read,
// on a node whose owner has left the switch on, the newest 200 rows of one of
// five log tables — with the members' addresses, the webhook payloads and the
// submitted forms never selected, and every text column masked. That is the
// "redacted log excerpts" cell of the accepted-limits table, no wider.
//
// What it cannot do:
//
//   - Name a table, a column, or a query. `table` is an ENUM of five words
//     compiled here, each bound to ONE query string in this file with ONE
//     placeholder, the row limit. No SQL, no fragment, no column name, no
//     ORDER BY travels from the plane; a job carrying any other field is
//     refused before this code runs.
//   - See what the column lists leave out: log_ip, rql_ip_address,
//     lfe_user_agent, lfe_form, wbh_payload. Not masked — never selected. A
//     test pins that none of those names appears in any query here.
//   - Read without the owner's leave. The switch is checked FIRST; this word
//     needs the database, so it reads the setting and nothing else.
//   - Flood the plane. At most 200 rows and 48 KiB of encoded rows.
//   - Change anything. One SELECT; observe, and a policy that accepts only
//     observe words can trust that.
func init() {
	Register(Primitive{
		Name:        "log_table_tail",
		Class:       ClassObserve,
		Description: "The newest rows of one of the site's own log tables (logins, requests, events, form_errors, webhooks) from a compiled column list, redacted on the node; refused unless the site's owner allows log access.",
		Params: []ParamSpec{
			{Name: "table", Type: ParamEnum, Required: true, Values: logTableNames},
			{Name: "rows", Type: ParamInt, Min: 1, Max: logTableMaxRows},
		},
		Run:     runLogTableTail,
		Timeout: 1 * time.Minute,
	})
}

const (
	logTableMaxRows     = 200
	logTableDefaultRows = 50
	// logTableMaxBytes bounds the encoded rows. Under the framework's 64 KiB
	// cap with room for the envelope.
	logTableMaxBytes = 48 * 1024
)

// logTable is one entry of the compiled list: the enum word, the columns
// returned in order, and the time column the tail is ordered by.
type logTable struct {
	table      string
	columns    []string
	timeColumn string
}

// logTables is the closed list. The "left out" columns of the spec's table are
// simply not here; logTableExcludedColumns names them so a test can prove it.
var logTables = map[string]logTable{
	"logins": {
		table:      "log_logins",
		columns:    []string{"log_login_id", "log_usr_user_id", "log_login_time", "log_login_type"},
		timeColumn: "log_login_time",
	},
	"requests": {
		table: "rql_request_logs",
		columns: []string{"rql_request_log_id", "rql_feature", "rql_action", "rql_usr_user_id",
			"rql_was_success", "rql_status_code", "rql_error_type", "rql_note", "rql_api_key_type",
			"rql_response_ms", "rql_create_time"},
		timeColumn: "rql_create_time",
	},
	"events": {
		table:      "evl_event_logs",
		columns:    []string{"evl_event_log_id", "evl_event", "evl_usr_user_id", "evl_create_time", "evl_was_success", "evl_note"},
		timeColumn: "evl_create_time",
	},
	"form_errors": {
		table:      "lfe_log_form_errors",
		columns:    []string{"lfe_log_form_error_id", "lfe_error", "lfe_usr_user_id", "lfe_log_time", "lfe_page", "lfe_url", "lfe_context"},
		timeColumn: "lfe_log_time",
	},
	"webhooks": {
		table:      "wbh_webhook_logs",
		columns:    []string{"wbh_webhook_log_id", "wbh_provider", "wbh_event_type", "wbh_event_id", "wbh_processed", "wbh_error_message", "wbh_create_time"},
		timeColumn: "wbh_create_time",
	},
}

// logTableNames is the enum, in a fixed order.
var logTableNames = []string{"logins", "requests", "events", "form_errors", "webhooks"}

// logTableExcludedColumns are the columns the spec leaves out and why; the
// gate is that none appears in any query this file builds.
var logTableExcludedColumns = []string{
	"log_ip",         // a member's address is not needed to see that logins stopped
	"rql_ip_address", // likewise
	"lfe_user_agent", // the member's browser
	"lfe_form",       // the member's submitted data
	"wbh_payload",    // the provider's raw body: card and customer detail
}

// logTableQuery is the one query string per enum word. The only placeholder is
// the limit.
func logTableQuery(word string) (string, logTable, bool) {
	t, ok := logTables[word]
	if !ok {
		return "", logTable{}, false
	}
	return fmt.Sprintf("SELECT %s FROM %s ORDER BY %s DESC LIMIT $1",
		strings.Join(t.columns, ", "), t.table, t.timeColumn), t, true
}

func runLogTableTail(ctx context.Context, env *ExecEnv, p Params) (map[string]interface{}, error) {
	if err := requireLogAccess(ctx, env); err != nil {
		return nil, err
	}
	word := p.String("table")
	limit := p.Int("rows")
	if !p.Has("rows") {
		limit = logTableDefaultRows
	}
	query, spec, ok := logTableQuery(word)
	if !ok {
		// Validate already refused anything outside the enum; this is a
		// build mistake, not a bad job.
		return nil, fmt.Errorf("log_table_tail has no query for %q", word)
	}
	if env == nil || env.DB == nil {
		return nil, fmt.Errorf("this machine has no site database to read %s from", spec.table)
	}
	db, err := env.DB()
	if err != nil {
		return nil, fmt.Errorf("the site database is not answering: %v", err)
	}
	rows, err := db.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %v", spec.table, err)
	}
	defer rows.Close()

	shaped, truncated, err := shapeRows(rows, spec.columns, logTableMaxBytes)
	if err != nil {
		return nil, err
	}
	result := map[string]interface{}{
		"table":         word,
		"rows_returned": len(shaped),
		"columns":       stringsAsInterfaces(spec.columns),
		"rows":          shaped,
		"truncated":     truncated,
	}
	redact.Fields(result)
	return result, nil
}

// shapeRows turns the scanned rows into JSON-shaped maps keyed by column,
// stopping when the encoded size would pass maxBytes. Timestamps become
// RFC3339 strings, byte slices become strings, numbers and bools pass.
func shapeRows(rows *sql.Rows, columns []string, maxBytes int) ([]interface{}, bool, error) {
	out := make([]interface{}, 0)
	total := 0
	for rows.Next() {
		values := make([]interface{}, len(columns))
		ptrs := make([]interface{}, len(columns))
		for i := range values {
			ptrs[i] = &values[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, false, err
		}
		row := make(map[string]interface{}, len(columns))
		for i, col := range columns {
			row[col] = jsonValue(values[i])
		}
		encoded, err := json.Marshal(row)
		if err != nil {
			return nil, false, err
		}
		if total+len(encoded) > maxBytes {
			return out, true, rows.Err()
		}
		total += len(encoded)
		out = append(out, row)
	}
	return out, false, rows.Err()
}

func jsonValue(v interface{}) interface{} {
	switch t := v.(type) {
	case nil:
		return nil
	case []byte:
		return string(t)
	case time.Time:
		return t.UTC().Format(time.RFC3339)
	case int64, float64, bool, string:
		return t
	default:
		return fmt.Sprint(t)
	}
}

func stringsAsInterfaces(in []string) []interface{} {
	out := make([]interface{}, len(in))
	for i, s := range in {
		out[i] = s
	}
	return out
}
