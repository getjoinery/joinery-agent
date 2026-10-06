package primitives

import "testing"

func TestSuspendedPageTakesAnActionAndASiteName(t *testing.T) {
	p, ok := Lookup("suspended_page")
	if !ok {
		t.Fatal("suspended_page should be registered")
	}
	for _, action := range []string{"show", "clear"} {
		for _, name := range []string{"getjoinery", "demo_site", "a-1"} {
			if _, err := Validate(p.Params, map[string]interface{}{"action": action, "name": name}); err != nil {
				t.Errorf("%s %q must validate: %v", action, name, err)
			}
		}
	}
	for _, bad := range []map[string]interface{}{
		{"action": "hide", "name": "getjoinery"},
		{"action": "suspend", "name": "getjoinery"},
		{"action": "", "name": "getjoinery"},
		{"name": "getjoinery"},
		{"action": "show"},
		{"action": "show", "name": "Getjoinery"},
		{"action": "show", "name": "../etc"},
		{"action": "show", "name": "x;reboot"},
		{"action": "show", "name": "-x"},
		{"action": "show", "name": "a b"},
	} {
		if _, err := Validate(p.Params, bad); err == nil {
			t.Errorf("params %v must be refused", bad)
		}
	}
	if p.Class != ClassOperate || !p.Machine || p.Script == nil || p.Script.ScriptPath != suspendedPageScript {
		t.Error("suspended_page is an operate machine script word running the shipped script")
	}
	if len(p.Script.Args) != 2 || p.Script.Args[0] != "{action}" || p.Script.Args[1] != "{name}" ||
		p.Script.StdinFrom != nil || p.Script.ArgsFrom != nil {
		t.Errorf("argv should be the two validated slots, got %v", p.Script.Args)
	}
}
