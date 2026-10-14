package primitives

import (
	"context"
	"reflect"
	"testing"
)

func TestSiteQuietHostTakesAnActionASiteAndAReason(t *testing.T) {
	p, ok := Lookup("site_quiet_host")
	if !ok {
		t.Fatal("site_quiet_host should be registered")
	}
	if p.Class != ClassOperate || !p.Machine || p.Script == nil || p.Script.ScriptPath != siteQuietHostScript ||
		p.Script.Args != nil || p.Script.StdinFrom != nil {
		t.Fatal("site_quiet_host is an operate machine script word running the shipped script, argv composed")
	}
	argv := func(params map[string]interface{}) ([]string, error) {
		v, err := Validate(p.Params, params)
		if err != nil {
			return nil, err
		}
		return p.Script.ArgsFrom(context.Background(), nil, v)
	}
	for _, c := range []struct {
		params map[string]interface{}
		want   []string
	}{
		{map[string]interface{}{"action": "on", "name": "getjoinery", "reason": "switchover"}, []string{"on", "getjoinery", "switchover"}},
		{map[string]interface{}{"action": "off", "name": "demo_site"}, []string{"off", "demo_site"}},
	} {
		got, err := argv(c.params)
		if err != nil || !reflect.DeepEqual(got, c.want) {
			t.Errorf("%v: argv %v %v, want %v", c.params, got, err, c.want)
		}
	}
	for _, bad := range []map[string]interface{}{
		{"action": "on", "name": "sq"},
		{"action": "on", "name": "sq", "reason": "copy"},
		{"action": "off", "name": "sq", "reason": "copy"},
		{"action": "on", "name": "sq", "reason": "live"},
		{"action": "clear", "name": "sq"},
		{"action": "on", "name": "Sq", "reason": "copy"},
		{"action": "on", "name": "../etc", "reason": "copy"},
		{"action": "on", "name": "x;reboot", "reason": "copy"},
		{"action": "on", "name": "-x", "reason": "copy"},
		{"action": "on", "reason": "copy"},
	} {
		if _, err := argv(bad); err == nil {
			t.Errorf("params %v must be refused", bad)
		}
	}
}
