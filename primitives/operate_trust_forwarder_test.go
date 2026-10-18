package primitives

import (
	"context"
	"reflect"
	"testing"
)

func TestTrustForwarderTakesOnePublicAddressForBoundedHours(t *testing.T) {
	p, ok := Lookup("trust_forwarder")
	if !ok {
		t.Fatal("trust_forwarder should be registered")
	}
	if p.Class != ClassOperate || !p.Machine || p.Script == nil || p.Script.ScriptPath != trustForwarderScript || p.Script.Args != nil {
		t.Fatal("trust_forwarder is an operate machine script word running the shipped script, argv composed")
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
		{map[string]interface{}{"action": "trust", "address": "198.51.100.7", "hours": 48}, []string{"trust", "198.51.100.7", "48"}},
		{map[string]interface{}{"action": "trust", "address": "2606:4700:0:0::1", "hours": 1}, []string{"trust", "2606:4700::1", "1"}},
		{map[string]interface{}{"action": "untrust", "address": "198.51.100.7"}, []string{"untrust", "198.51.100.7"}},
	} {
		got, err := argv(c.params)
		if err != nil || !reflect.DeepEqual(got, c.want) {
			t.Errorf("%v: argv %v %v, want %v", c.params, got, err, c.want)
		}
	}
	for _, bad := range []map[string]interface{}{
		{"action": "trust", "address": "198.51.100.7"},
		{"action": "trust", "address": "198.51.100.7", "hours": 169},
		{"action": "trust", "address": "198.51.100.7", "hours": 0},
		{"action": "untrust", "address": "198.51.100.7", "hours": 2},
		{"action": "trust", "address": "10.0.0.5", "hours": 2},
		{"action": "trust", "address": "127.0.0.1", "hours": 2},
		{"action": "trust", "address": "192.168.1.1", "hours": 2},
		{"action": "trust", "address": "fe80::1", "hours": 2},
		{"action": "trust", "address": "::1", "hours": 2},
		{"action": "trust", "address": "0.0.0.0", "hours": 2},
		{"action": "trust", "address": "203.0.113.0/24", "hours": 2},
		{"action": "trust", "address": "1.2.3.4;reboot", "hours": 2},
		{"action": "trust", "address": "999.1.1.1", "hours": 2},
		{"action": "allow", "address": "198.51.100.7", "hours": 2},
	} {
		if _, err := argv(bad); err == nil {
			t.Errorf("params %v must be refused", bad)
		}
	}
}

func TestSiteQuietForwardsOnlyToAPublicAddress(t *testing.T) {
	p, _ := Lookup("site_quiet")
	argv := func(params map[string]interface{}) ([]string, error) {
		v, err := Validate(p.Params, params)
		if err != nil {
			return nil, err
		}
		return p.Script.ArgsFrom(context.Background(), &ExecEnv{SiteRoot: "/var/www/html/x"}, v)
	}
	got, err := argv(map[string]interface{}{"action": "forward", "to": "198.51.100.70"})
	if err != nil || !reflect.DeepEqual(got, []string{"forward", "198.51.100.70"}) {
		t.Errorf("forward: argv %v %v", got, err)
	}
	got, err = argv(map[string]interface{}{"action": "on"})
	if err != nil || !reflect.DeepEqual(got, []string{"on"}) {
		t.Errorf("on: argv %v %v", got, err)
	}
	for _, bad := range []map[string]interface{}{
		{"action": "forward"},
		{"action": "forward", "to": "10.1.2.3"},
		{"action": "forward", "to": "localhost"},
		{"action": "on", "to": "198.51.100.70"},
		{"action": "off", "to": "198.51.100.70"},
	} {
		if _, err := argv(bad); err == nil {
			t.Errorf("params %v must be refused", bad)
		}
	}
}

func TestSiteQuietHostForwardsOnlyToAPublicAddress(t *testing.T) {
	p, _ := Lookup("site_quiet_host")
	argv := func(params map[string]interface{}) ([]string, error) {
		v, err := Validate(p.Params, params)
		if err != nil {
			return nil, err
		}
		return p.Script.ArgsFrom(context.Background(), nil, v)
	}
	got, err := argv(map[string]interface{}{"action": "forward", "name": "demo", "to": "2001:4860::8888"})
	if err != nil || !reflect.DeepEqual(got, []string{"forward", "demo", "2001:4860::8888"}) {
		t.Errorf("forward: argv %v %v", got, err)
	}
	for _, bad := range []map[string]interface{}{
		{"action": "forward", "name": "demo"},
		{"action": "forward", "name": "demo", "to": "172.17.0.1"},
		{"action": "forward", "name": "demo", "to": "198.51.100.70", "reason": "switchover"},
		{"action": "on", "name": "demo", "reason": "switchover", "to": "198.51.100.70"},
	} {
		if _, err := argv(bad); err == nil {
			t.Errorf("params %v must be refused", bad)
		}
	}
}
