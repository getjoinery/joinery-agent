package primitives

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// schema_probe {table}: one table of the site's own database as the database
// describes it — whether it exists, its columns with type and nullability, its
// indexes, and how many rows it holds.
//
// specs/agent_recipes_and_vocabulary.md, the running list (2026-09-17, the
// 0.8.408 apply on joinerydemo): after a migration that renamed a table, the
// operator could only trust the transcript's own lines for "the old table is
// gone, the new column is NOT NULL". This is the node's own answer.
//
// HOSTILE-CALLER REVIEW (rule 5).
//
// What is the worst a compromised management node can do with this word?
// Learn the shape of the site's schema — which is the release's own schema,
// public in the source — and a row count per table. The count is an
// aggregate (how many members, how many messages), accepted by the owner as
// page_probe's size is. No row crosses.
//
// What it cannot do:
//
//   - Send SQL. The plane sends a name; every query below is compiled, and
//     the name reaches them as a bound parameter, except the one COUNT, which
//     takes it as an identifier ONLY after it matched the compiled pattern AND
//     the database itself answered that a table of exactly that name exists
//     in the site's schema. A name the database does not list is refused
//     before any identifier is built.
//   - Read a value. Column names, types, nullability, index definitions and a
//     count: nothing a row holds.
//   - Hold the database. The count runs under its own deadline; a table too
//     big to count in time is reported with the planner's estimate, and says
//     so.
func init() {
	Register(Primitive{
		Name:        "schema_probe",
		Class:       ClassObserve,
		Description: "One table of the site's own database: whether it exists, its columns (type, nullability), its indexes and its row count. No row is read.",
		Params: []ParamSpec{
			{Name: "table", Type: ParamString, Required: true, MaxLen: 63, Pattern: schemaProbeTable},
		},
		Run:     runSchemaProbe,
		Timeout: 1 * time.Minute,
	})
}

// schemaProbeTable is an unquoted PostgreSQL identifier as this platform names
// tables: lower case, digits and underscores, starting with a letter.
var schemaProbeTable = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)

const (
	schemaProbeMaxColumns = 200
	schemaProbeMaxIndexes = 50
	schemaProbeCountLimit = 20 * time.Second
)

const (
	schemaProbeExistsQuery  = "SELECT count(*) FROM information_schema.tables WHERE table_schema = current_schema() AND table_name = $1"
	schemaProbeColumnsQuery = "SELECT column_name, data_type, is_nullable, coalesce(character_maximum_length, 0), coalesce(column_default, '') FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = $1 ORDER BY ordinal_position LIMIT 200"
	schemaProbeIndexesQuery = "SELECT indexname, indexdef FROM pg_indexes WHERE schemaname = current_schema() AND tablename = $1 ORDER BY indexname LIMIT 50"
	schemaProbeEstimate     = "SELECT coalesce(c.reltuples, -1)::bigint FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = current_schema() AND c.relname = $1"
)

func runSchemaProbe(ctx context.Context, env *ExecEnv, p Params) (map[string]interface{}, error) {
	table := p.String("table")
	if env == nil || env.DB == nil {
		return nil, fmt.Errorf("this machine has no site database")
	}
	db, err := env.DB()
	if err != nil {
		return nil, fmt.Errorf("the site database is not answering: %v", err)
	}
	result := map[string]interface{}{
		"table":           table,
		"exists":          false,
		"columns":         []interface{}{},
		"indexes":         []interface{}{},
		"row_count":       int64(0),
		"row_count_exact": false,
	}

	var n int64
	if err := db.QueryRowContext(ctx, schemaProbeExistsQuery, table).Scan(&n); err != nil {
		return nil, fmt.Errorf("reading information_schema: %v", err)
	}
	if n != 1 {
		// Not an error: "the old table is gone" is an answer this word exists
		// to give. Nothing below runs for a name the database does not list.
		return result, nil
	}
	result["exists"] = true

	columns, err := schemaProbeRows(ctx, db, schemaProbeColumnsQuery, table, schemaProbeMaxColumns, func(r *sql.Rows) (interface{}, error) {
		var name, typ, nullable, def string
		var length int64
		if err := r.Scan(&name, &typ, &nullable, &length, &def); err != nil {
			return nil, err
		}
		col := map[string]interface{}{"name": name, "type": typ, "nullable": nullable == "YES"}
		if length > 0 {
			col["max_length"] = length
		}
		// A default is schema, not data; a sequence default names a sequence.
		if def != "" {
			if len(def) > 128 {
				def = def[:128]
			}
			col["default"] = def
		}
		return col, nil
	})
	if err != nil {
		return nil, err
	}
	result["columns"] = columns

	indexes, err := schemaProbeRows(ctx, db, schemaProbeIndexesQuery, table, schemaProbeMaxIndexes, func(r *sql.Rows) (interface{}, error) {
		var name, def string
		if err := r.Scan(&name, &def); err != nil {
			return nil, err
		}
		if len(def) > 512 {
			def = def[:512]
		}
		return map[string]interface{}{"name": name, "definition": def}, nil
	})
	if err != nil {
		return nil, err
	}
	result["indexes"] = indexes

	// The identifier is built only here, only from a name that matched the
	// compiled pattern and that the database just listed.
	countCtx, cancel := context.WithTimeout(ctx, schemaProbeCountLimit)
	defer cancel()
	var count int64
	if err := db.QueryRowContext(countCtx, "SELECT count(*) FROM "+quoteIdent(table)).Scan(&count); err == nil {
		result["row_count"] = count
		result["row_count_exact"] = true
	} else {
		var est int64
		if err := db.QueryRowContext(ctx, schemaProbeEstimate, table).Scan(&est); err == nil {
			result["row_count"] = est
		} else {
			result["row_count"] = int64(-1)
		}
	}
	return result, nil
}

func schemaProbeRows(ctx context.Context, db *sql.DB, query, table string, limit int, scan func(*sql.Rows) (interface{}, error)) ([]interface{}, error) {
	rows, err := db.QueryContext(ctx, query, table)
	if err != nil {
		return nil, fmt.Errorf("reading the schema of %s: %v", table, err)
	}
	defer rows.Close()
	out := make([]interface{}, 0)
	for rows.Next() && len(out) < limit {
		v, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// quoteIdent double-quotes an identifier. The pattern already excludes every
// character that would need escaping; the quoting is a second fence.
func quoteIdent(name string) string {
	return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
}
