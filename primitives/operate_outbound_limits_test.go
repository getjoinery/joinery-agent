package primitives

import (
	"context"
	"reflect"
	"testing"
)

func TestOutboundLimitsValidatesItsFigures(t *testing.T) {
	p, ok := Lookup("outbound_limits")
	if !ok {
		t.Fatal("outbound_limits should be registered")
	}
	for _, good := range []map[string]interface{}{
		{"action": "on"},
		{"action": "off"},
		{"action": "set", "ceiling": "200"},
		{"action": "set", "ceiling": "off"},
		{"action": "set", "ceiling": "default", "conn_rate": "20", "conn_burst": "100", "open_conns": "256"},
		{"action": "set", "conn_rate": "default", "site": "getjoinery"},
		{"action": "set", "ceiling": "999999", "open_conns": "9999999"},
	} {
		if _, err := Validate(p.Params, good); err != nil {
			t.Errorf("params %v must validate: %v", good, err)
		}
	}
	for _, bad := range []map[string]interface{}{
		{"action": "toggle"},
		{"ceiling": "200"},
		{"action": "set", "ceiling": "0"},
		{"action": "set", "ceiling": "1000000"},
		{"action": "set", "ceiling": "200mbit"},
		{"action": "set", "ceiling": "-1"},
		{"action": "set", "ceiling": "200 --off"},
		{"action": "set", "conn_rate": "off"},
		{"action": "set", "conn_rate": "10000000"},
		{"action": "set", "open_conns": "1;reboot"},
		{"action": "set", "ceiling": "200", "site": "../etc"},
		{"action": "set", "ceiling": "200", "site": "-x"},
		{"action": "set", "ceiling": "200", "site": "a b"},
	} {
		if _, err := Validate(p.Params, bad); err == nil {
			t.Errorf("params %v must be refused", bad)
		}
	}
	if p.Class != ClassOperate || !p.Machine || p.Script == nil || p.Script.ScriptPath != outboundLimitsScript ||
		p.Script.ArgsFrom == nil || p.Script.Args != nil || p.Script.StdinFrom != nil {
		t.Error("outbound_limits is an operate machine script word whose argv is composed from its params")
	}
}

func TestOutboundLimitsArgv(t *testing.T) {
	p, _ := Lookup("outbound_limits")
	argv := func(in map[string]interface{}) ([]string, error) {
		params, err := Validate(p.Params, in)
		if err != nil {
			t.Fatalf("params %v: %v", in, err)
		}
		return outboundLimitsArgv(context.Background(), nil, params)
	}
	for _, c := range []struct {
		in   map[string]interface{}
		want []string
	}{
		{map[string]interface{}{"action": "on"}, []string{"on"}},
		{map[string]interface{}{"action": "off"}, []string{"off"}},
		{map[string]interface{}{"action": "set", "ceiling": "500"}, []string{"set", "--ceiling=500", "--by=plane"}},
		{map[string]interface{}{"action": "set", "ceiling": "off", "conn_rate": "40", "conn_burst": "200", "open_conns": "512", "site": "demo"},
			[]string{"set", "--ceiling=off", "--conn-rate=40", "--conn-burst=200", "--open-conns=512", "--site=demo", "--by=plane"}},
		{map[string]interface{}{"action": "set", "conn_rate": "default"}, []string{"set", "--conn-rate=default", "--by=plane"}},
	} {
		got, err := argv(c.in)
		if err != nil || !reflect.DeepEqual(got, c.want) {
			t.Errorf("%v: got %v, %v; want %v", c.in, got, err, c.want)
		}
	}
	for _, refused := range []map[string]interface{}{
		{"action": "set"},
		{"action": "set", "site": "demo"},
		{"action": "on", "ceiling": "200"},
		{"action": "off", "site": "demo"},
	} {
		if _, err := argv(refused); err == nil {
			t.Errorf("%v must be refused", refused)
		}
	}
}
