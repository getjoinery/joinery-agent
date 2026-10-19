package primitives

import (
	"context"
	"reflect"
	"testing"
)

func TestCopyProbesTakesASiteANeighbourAndAPublicAddress(t *testing.T) {
	p, ok := Lookup("copy_probes")
	if !ok {
		t.Fatal("copy_probes should be registered")
	}
	if p.Class != ClassOperate || !p.Machine || p.Script == nil || p.Script.ScriptPath != copyProbesScript || p.Script.Args != nil || p.Quiet != QuietAny {
		t.Fatal("copy_probes is an operate machine script word running the shipped script, argv composed, under any quiet reason")
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
		{map[string]interface{}{"site": "src1"}, []string{"src1"}},
		{map[string]interface{}{"site": "src1", "neighbour": "other_site"}, []string{"src1", "--neighbour", "other_site"}},
		{map[string]interface{}{"site": "src1", "old_address": "2606:4700:0:0::1"}, []string{"src1", "--old-address", "2606:4700::1"}},
		{map[string]interface{}{"site": "a", "neighbour": "b", "old_address": "198.51.100.7"},
			[]string{"a", "--neighbour", "b", "--old-address", "198.51.100.7"}},
	} {
		got, err := argv(c.params)
		if err != nil || !reflect.DeepEqual(got, c.want) {
			t.Errorf("%v: argv %v %v, want %v", c.params, got, err, c.want)
		}
	}
	for _, bad := range []map[string]interface{}{
		{},
		{"site": "-x"},
		{"site": "--loosen"},
		{"site": "../etc"},
		{"site": "Src1"},
		{"site": "a b"},
		{"site": "src1", "neighbour": "src1"},
		{"site": "src1", "neighbour": "-y"},
		{"site": "src1", "old_address": "10.0.0.5"},
		{"site": "src1", "old_address": "127.0.0.1"},
		{"site": "src1", "old_address": "203.0.113.0/24"},
		{"site": "src1", "old_address": "1.2.3.4;reboot"},
		{"site": "src1", "loosen": true},
	} {
		if _, err := argv(bad); err == nil {
			t.Errorf("params %v must be refused", bad)
		}
	}
}
