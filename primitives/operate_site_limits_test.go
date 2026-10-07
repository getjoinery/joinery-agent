package primitives

import "testing"

func TestSiteLimitsTakesASiteAndThreeFigures(t *testing.T) {
	p, ok := Lookup("site_limits")
	if !ok {
		t.Fatal("site_limits should be registered")
	}
	for _, good := range []map[string]interface{}{
		{"name": "starter7", "memory": "512m", "cpus": "0.5", "disk": "4g"},
		{"name": "demo_site", "memory": "keep", "cpus": "keep", "disk": "none"},
		{"name": "a-1", "memory": "1g", "cpus": "1", "disk": "500m"},
		{"name": "a-1", "memory": "keep", "cpus": ".25", "disk": "1t"},
	} {
		if _, err := Validate(p.Params, good); err != nil {
			t.Errorf("%v must validate: %v", good, err)
		}
	}
	for _, bad := range []map[string]interface{}{
		{"name": "starter7", "memory": "512m", "cpus": "0.5"},
		{"name": "Starter7", "memory": "keep", "cpus": "keep", "disk": "keep"},
		{"name": "../etc", "memory": "keep", "cpus": "keep", "disk": "keep"},
		{"name": "starter7", "memory": "512 m", "cpus": "keep", "disk": "keep"},
		{"name": "starter7", "memory": "keep", "cpus": "1;reboot", "disk": "keep"},
		{"name": "starter7", "memory": "keep", "cpus": "keep", "disk": "4"},
		{"name": "starter7", "memory": "keep", "cpus": "keep", "disk": "-1g"},
		{"name": "starter7", "memory": "", "cpus": "keep", "disk": "keep"},
	} {
		if _, err := Validate(p.Params, bad); err == nil {
			t.Errorf("params %v must be refused", bad)
		}
	}
	if p.Class != ClassOperate || !p.Machine || p.Script == nil || p.Script.ScriptPath != siteLimitsScript {
		t.Error("site_limits is an operate machine script word running the shipped script")
	}
	if len(p.Script.Args) != 4 || p.Script.Args[0] != "{name}" || p.Script.Args[3] != "{disk}" ||
		p.Script.StdinFrom != nil || p.Script.ArgsFrom != nil {
		t.Errorf("argv should be the four validated slots, got %v", p.Script.Args)
	}
}
