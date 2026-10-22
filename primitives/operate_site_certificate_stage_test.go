package primitives

import (
	"context"
	"reflect"
	"testing"
)

func TestSiteCertificateStageStagesOrClearsOneSite(t *testing.T) {
	p, ok := Lookup("site_certificate_stage")
	if !ok {
		t.Fatal("site_certificate_stage should be registered")
	}
	if p.Class != ClassOperate || !p.Machine || p.Script == nil || p.Script.ScriptPath != siteCertificateStageScript ||
		p.Script.Args != nil || p.Script.StdinFrom != nil {
		t.Fatal("site_certificate_stage is an operate machine script word running the shipped script, argv composed")
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
		{map[string]interface{}{"action": "stage", "name": "src7", "domain": "src7.joinerytest.com"}, []string{"stage", "src7", "src7.joinerytest.com"}},
		{map[string]interface{}{"action": "stage", "name": "demo_site", "domain": "Shop.Example.ORG"}, []string{"stage", "demo_site", "shop.example.org"}},
		{map[string]interface{}{"action": "clear", "name": "src7"}, []string{"clear", "src7"}},
	} {
		got, err := argv(c.params)
		if err != nil || !reflect.DeepEqual(got, c.want) {
			t.Errorf("%v: argv %v %v, want %v", c.params, got, err, c.want)
		}
	}
	for _, bad := range []map[string]interface{}{
		{"action": "stage", "name": "src7"},
		{"action": "clear", "name": "src7", "domain": "src7.joinerytest.com"},
		{"action": "stage", "name": "../etc", "domain": "src7.joinerytest.com"},
		{"action": "stage", "name": "src7", "domain": "x;reboot"},
		{"action": "collect", "name": "src7", "domain": "src7.joinerytest.com"},
	} {
		if got, err := argv(bad); err == nil {
			t.Errorf("%v: refused, got argv %v", bad, got)
		}
	}
}
