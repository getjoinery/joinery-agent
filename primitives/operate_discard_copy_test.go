package primitives

import "testing"

func TestDiscardCopyTakesASiteName(t *testing.T) {
	p, ok := Lookup("discard_copy")
	if !ok {
		t.Fatal("discard_copy should be registered")
	}
	if p.Class != ClassOperate || !p.Machine || p.Script == nil || p.Script.ScriptPath != discardCopyScript ||
		len(p.Script.Args) != 1 || p.Script.Args[0] != "{name}" || p.Script.ArgsFrom != nil || p.Script.StdinFrom != nil {
		t.Fatal("discard_copy is an operate machine script word with the site name as its one argument")
	}
	if _, err := Validate(p.Params, map[string]interface{}{"name": "getjoinery_orgs"}); err != nil {
		t.Fatalf("a site name validates: %v", err)
	}
	for _, bad := range []map[string]interface{}{
		{}, {"name": "a"}, {"name": "Sa"}, {"name": "../etc"}, {"name": "-y"}, {"name": "a b"}, {"name": "sa", "force": true},
	} {
		if _, err := Validate(p.Params, bad); err == nil {
			t.Errorf("params %v must be refused", bad)
		}
	}
}
