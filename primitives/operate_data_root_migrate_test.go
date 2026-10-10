package primitives

import "testing"

func TestDataRootMigrateTakesNothingAndRunsTheShippedScript(t *testing.T) {
	p, ok := Lookup("data_root_migrate")
	if !ok {
		t.Fatal("data_root_migrate should be registered")
	}
	if _, err := Validate(p.Params, map[string]interface{}{}); err != nil {
		t.Errorf("no params must validate: %v", err)
	}
	for _, bad := range []map[string]interface{}{
		{"size": "32G"},
		{"device": "/dev/sdb"},
	} {
		if _, err := Validate(p.Params, bad); err == nil {
			t.Errorf("params %v must be refused: the script sizes the data root itself", bad)
		}
	}
	if p.Class != ClassOperate || !p.Machine || p.Script == nil || p.Script.ScriptPath != dataRootMigrateScript {
		t.Error("data_root_migrate is an operate machine script word running the shipped script")
	}
	if len(p.Script.Args) != 1 || p.Script.Args[0] != "migrate" || p.Script.StdinFrom != nil || p.Script.ArgsFrom != nil {
		t.Errorf("argv should be the one fixed word migrate, got %v", p.Script.Args)
	}
	if p.Timeout > MaxTimeout {
		t.Errorf("data_root_migrate declares %v, above the %v ceiling", p.Timeout, MaxTimeout)
	}
}
