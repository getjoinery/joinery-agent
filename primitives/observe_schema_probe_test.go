package primitives

import (
	"context"
	"database/sql/driver"
	"testing"
)

func TestSchemaProbeTakesOnlyAnIdentifier(t *testing.T) {
	p, ok := Lookup("schema_probe")
	if !ok {
		t.Fatal("schema_probe should be registered")
	}
	for _, bad := range []string{"", "Users", "usr_users; drop table x", "pg_catalog.pg_authid", `"x"`, "1abc", "a b", "usr_users--"} {
		if _, err := Validate(p.Params, map[string]interface{}{"table": bad}); err == nil {
			t.Errorf("table %q must be refused", bad)
		}
	}
	if _, err := Validate(p.Params, map[string]interface{}{"table": "usr_users", "sql": "select 1"}); err == nil {
		t.Error("an undeclared key must be refused")
	}
	if p.Class != ClassObserve || p.Run == nil || p.RequiresLogAccess || p.Machine {
		t.Error("schema_probe is an embedded observe site word; it reads no log")
	}
}

func TestSchemaProbeAbsentTableRunsNothingElse(t *testing.T) {
	env := &ExecEnv{DB: fakeDB(map[string]fakeRows{
		"information_schema.tables": {columns: []string{"count"}, rows: [][]driver.Value{{int64(0)}}},
	}, nil)}
	p, _ := Lookup("schema_probe")
	params, _ := Validate(p.Params, map[string]interface{}{"table": "old_table"})
	res, err := p.Run(context.Background(), env, params)
	if err != nil {
		t.Fatalf("an absent table is an answer, not an error: %v", err)
	}
	if res["exists"] != false {
		t.Errorf("exists should be false, got %v", res["exists"])
	}
}

func TestSchemaProbeDescribesAnExistingTable(t *testing.T) {
	env := &ExecEnv{DB: fakeDB(map[string]fakeRows{
		"information_schema.tables": {columns: []string{"count"}, rows: [][]driver.Value{{int64(1)}}},
		"information_schema.columns": {columns: []string{"a", "b", "c", "d", "e"}, rows: [][]driver.Value{
			{"usr_user_id", "integer", "NO", int64(0), "nextval('usr_users_usr_user_id_seq'::regclass)"},
			{"usr_email", "character varying", "YES", int64(255), ""},
		}},
		"pg_indexes":       {columns: []string{"a", "b"}, rows: [][]driver.Value{{"usr_users_pkey", "CREATE UNIQUE INDEX usr_users_pkey ON public.usr_users USING btree (usr_user_id)"}}},
		`FROM "usr_users"`: {columns: []string{"count"}, rows: [][]driver.Value{{int64(42)}}},
	}, nil)}
	p, _ := Lookup("schema_probe")
	params, _ := Validate(p.Params, map[string]interface{}{"table": "usr_users"})
	res, err := p.Run(context.Background(), env, params)
	if err != nil {
		t.Fatal(err)
	}
	cols := res["columns"].([]interface{})
	if len(cols) != 2 || cols[0].(map[string]interface{})["nullable"] != false || cols[1].(map[string]interface{})["max_length"] != int64(255) {
		t.Errorf("columns wrong: %v", cols)
	}
	if res["row_count"] != int64(42) || res["row_count_exact"] != true {
		t.Errorf("count wrong: %v %v", res["row_count"], res["row_count_exact"])
	}
	if len(res["indexes"].([]interface{})) != 1 {
		t.Errorf("indexes wrong: %v", res["indexes"])
	}
}
