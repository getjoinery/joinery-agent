package primitives

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func siteInstallParams(over map[string]interface{}) map[string]interface{} {
	p := map[string]interface{}{
		"name": "getjoinery_orgs", "domain": "orgs.getjoinery.com", "port": float64(9083),
		"release": "0.8.496", "copy_of": float64(417), "copy_of_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
	}
	for k, v := range over {
		if v == nil {
			delete(p, k)
		} else {
			p[k] = v
		}
	}
	return p
}

func TestSiteInstallIsADormantCopyFromAVerifiedRelease(t *testing.T) {
	p, ok := Lookup("site_install")
	if !ok {
		t.Fatal("site_install should be registered")
	}
	if p.Class != ClassOperate || !p.Machine || p.Script == nil || p.Script.ScriptPath != siteInstallScript ||
		p.Script.Release == nil || p.Script.ArgsFrom == nil || p.Script.Args != nil || p.Script.StdinFrom != nil {
		t.Fatal("site_install is an operate machine script word, run from a release, argv composed")
	}
	env := &ExecEnv{PlaneURL: func() (string, error) { return "https://getjoinery.com/", nil }}
	v, err := Validate(p.Params, siteInstallParams(map[string]interface{}{"memory": "384m"}))
	if err != nil {
		t.Fatal(err)
	}
	if r, _ := p.Script.Release(context.Background(), env, v); r != "0.8.496" {
		t.Fatalf("the tree is the release named: %q", r)
	}
	got, err := p.Script.ArgsFrom(context.Background(), env, v)
	want := []string{"-y", "-q", "site", "--docker", "getjoinery_orgs", "-", "orgs.getjoinery.com", "9083",
		"--enable-agent", "--management-node=https://getjoinery.com", "--upgrade-server=https://getjoinery.com",
		"--dormant", "--copy-of=417", "--copy-of-key=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "--release-tree-only", "--memory=384m"}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("argv\n got  %v %v\n want %v", got, err, want)
	}

	for _, refuse := range []struct {
		why string
		env *ExecEnv
	}{
		{"a machine that is a site", &ExecEnv{SiteRoot: "/var/www/html/x", PlaneURL: env.PlaneURL}},
		{"no plane to read", &ExecEnv{}},
		{"not enrolled", &ExecEnv{PlaneURL: func() (string, error) { return "", errors.New("not enrolled") }}},
		{"a plane that is not https", &ExecEnv{PlaneURL: func() (string, error) { return "http://plane.example", nil }}},
		{"a plane address with a path", &ExecEnv{PlaneURL: func() (string, error) { return "https://plane.example/x?y", nil }}},
	} {
		if _, err := p.Script.ArgsFrom(context.Background(), refuse.env, v); err == nil {
			t.Errorf("%s: refused", refuse.why)
		}
	}

	for _, bad := range []map[string]interface{}{
		siteInstallParams(map[string]interface{}{"name": "Getjoinery"}),
		siteInstallParams(map[string]interface{}{"name": "a"}),
		siteInstallParams(map[string]interface{}{"name": "../etc"}),
		siteInstallParams(map[string]interface{}{"name": "-x"}),
		siteInstallParams(map[string]interface{}{"domain": "orgs.getjoinery.com --wipe-data"}),
		siteInstallParams(map[string]interface{}{"domain": "localhost"}),
		siteInstallParams(map[string]interface{}{"port": float64(80)}),
		siteInstallParams(map[string]interface{}{"release": "latest"}),
		siteInstallParams(map[string]interface{}{"copy_of": float64(0)}),
		siteInstallParams(map[string]interface{}{"copy_of_key": "not-a-key"}),
		siteInstallParams(map[string]interface{}{"memory": "1t"}),
		siteInstallParams(map[string]interface{}{"copy_of": nil}),
		siteInstallParams(map[string]interface{}{"copy_of_key": nil}),
		siteInstallParams(map[string]interface{}{"release": nil}),
		siteInstallParams(map[string]interface{}{"management_node": "https://evil.example"}),
	} {
		if _, err := Validate(p.Params, bad); err == nil {
			t.Errorf("params %v must be refused", bad)
		}
	}
}
