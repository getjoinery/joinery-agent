package primitives

import "testing"

func TestRecreateSiteTakesASiteName(t *testing.T) {
	p, ok := Lookup("recreate_site")
	if !ok {
		t.Fatal("recreate_site should be registered")
	}
	for _, name := range []string{"getjoinery", "demo_site", "a-1", "wd5"} {
		if _, err := Validate(p.Params, map[string]interface{}{"name": name}); err != nil {
			t.Errorf("%q must validate: %v", name, err)
		}
	}
	for _, bad := range []map[string]interface{}{
		{},
		{"name": ""},
		{"name": "Getjoinery"},
		{"name": "../etc"},
		{"name": "x;reboot"},
		{"name": "-x"},
		{"name": "a b"},
		{"name": "getjoinery", "image": "evil:latest"},
	} {
		if _, err := Validate(p.Params, bad); err == nil {
			t.Errorf("params %v must be refused", bad)
		}
	}
	if p.Class != ClassOperate || !p.Machine || p.Script == nil || p.Script.ScriptPath != recreateSiteScript {
		t.Error("recreate_site is an operate machine script word running the shipped script")
	}
	if len(p.Script.Args) != 1 || p.Script.Args[0] != "{name}" || p.Script.StdinFrom != nil || p.Script.ArgsFrom != nil {
		t.Errorf("argv should be the one validated slot, got %v", p.Script.Args)
	}
}
