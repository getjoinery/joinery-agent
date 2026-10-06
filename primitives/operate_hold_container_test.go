package primitives

import "testing"

func TestHoldContainerTakesAnActionAndASiteName(t *testing.T) {
	p, ok := Lookup("hold_container")
	if !ok {
		t.Fatal("hold_container should be registered")
	}
	for _, action := range []string{"stop", "start"} {
		for _, name := range []string{"getjoinery", "demo_site", "a-1"} {
			if _, err := Validate(p.Params, map[string]interface{}{"action": action, "name": name}); err != nil {
				t.Errorf("%s %q must validate: %v", action, name, err)
			}
		}
	}
	for _, bad := range []map[string]interface{}{
		{"action": "restart", "name": "getjoinery"},
		{"action": "rm", "name": "getjoinery"},
		{"action": "", "name": "getjoinery"},
		{"name": "getjoinery"},
		{"action": "stop"},
		{"action": "stop", "name": "Getjoinery"},
		{"action": "stop", "name": "../etc"},
		{"action": "stop", "name": "x;reboot"},
		{"action": "stop", "name": "-x"},
		{"action": "stop", "name": "a b"},
	} {
		if _, err := Validate(p.Params, bad); err == nil {
			t.Errorf("params %v must be refused", bad)
		}
	}
	if p.Class != ClassOperate || !p.Machine || p.Script == nil || p.Script.ScriptPath != holdContainerScript {
		t.Error("hold_container is an operate machine script word running the shipped script")
	}
	if len(p.Script.Args) != 2 || p.Script.Args[0] != "{action}" || p.Script.Args[1] != "{name}" ||
		p.Script.StdinFrom != nil || p.Script.ArgsFrom != nil {
		t.Errorf("argv should be the two validated slots, got %v", p.Script.Args)
	}
}
