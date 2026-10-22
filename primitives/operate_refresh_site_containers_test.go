package primitives

import "testing"

func TestRefreshSiteContainersTakesNothing(t *testing.T) {
	p, ok := Lookup("refresh_site_containers")
	if !ok {
		t.Fatal("refresh_site_containers should be registered")
	}
	if _, err := Validate(p.Params, map[string]interface{}{}); err != nil {
		t.Errorf("no params must validate: %v", err)
	}
	for _, bad := range []map[string]interface{}{
		{"name": "getjoinery"},
		{"args": "run"},
	} {
		if _, err := Validate(p.Params, bad); err == nil {
			t.Errorf("params %v must be refused", bad)
		}
	}
	if p.Class != ClassOperate || !p.Machine || p.Script == nil || p.Script.ScriptPath != refreshSiteContainersScript {
		t.Error("refresh_site_containers is an operate machine script word running the shipped script")
	}
	if len(p.Script.Args) != 1 || p.Script.Args[0] != "start" || p.Script.StdinFrom != nil || p.Script.ArgsFrom != nil {
		t.Errorf("argv should be the one fixed word start, got %v", p.Script.Args)
	}
}
