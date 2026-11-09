package primitives

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

func siteCreateParams(over map[string]interface{}) map[string]interface{} {
	p := map[string]interface{}{
		"name": "starter_example", "domain": "example-starter.com", "port": float64(9101),
		"release": "0.8.599", "admin_email": "owner@example.com", "admin_password": "Aa1!bcdefghijkl",
		"memory": "256m", "cpus": "1", "disk": "5G",
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

func TestSiteCreateIsALiveSiteFromAVerifiedRelease(t *testing.T) {
	p, ok := Lookup("site_create")
	if !ok {
		t.Fatal("site_create should be registered")
	}
	if p.Class != ClassOperate || !p.Machine || p.Script == nil || p.Script.ScriptPath != siteInstallScript ||
		p.Script.Release == nil || p.Script.ArgsFrom == nil || p.Script.Args != nil || p.Script.StdinFrom == nil {
		t.Fatal("site_create is an operate machine script word, run from a release, argv composed, password on stdin")
	}
	env := &ExecEnv{PlaneURL: func() (string, error) { return "https://getjoinery.com/", nil }}
	v, err := Validate(p.Params, siteCreateParams(nil))
	if err != nil {
		t.Fatal(err)
	}
	if r, _ := p.Script.Release(context.Background(), env, v); r != "0.8.599" {
		t.Fatalf("the tree is the release named: %q", r)
	}
	got, err := p.Script.ArgsFrom(context.Background(), env, v)
	want := []string{"-y", "-q", "site", "--docker", "starter_example", "-", "example-starter.com", "9101",
		"--enable-agent", "--management-node=https://getjoinery.com", "--upgrade-server=https://getjoinery.com",
		"--admin-email=owner@example.com", "--admin-password-stdin", "--new-site-only", "--memory=256m", "--cpus=1", "--disk=5G"}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("argv\n got  %v %v\n want %v", got, err, want)
	}
	for _, a := range got {
		if strings.Contains(a, "Aa1!bcdefghijkl") {
			t.Fatal("the admin password must never be in argv, where every process on the box can read it")
		}
		if a == "--dormant" || strings.HasPrefix(a, "--copy-of") {
			t.Fatalf("a created site is live, never a dormant copy: %q", a)
		}
	}
	in, err := p.Script.StdinFrom(v)
	if err != nil || in != "Aa1!bcdefghijkl\n" {
		t.Fatalf("stdin is the password and one newline: %q %v", in, err)
	}

	for _, refuse := range []*ExecEnv{
		{SiteRoot: "/var/www/html/x", PlaneURL: env.PlaneURL},
		{},
		{PlaneURL: func() (string, error) { return "http://plane.example", nil }},
	} {
		if _, err := p.Script.ArgsFrom(context.Background(), refuse, v); err == nil {
			t.Errorf("refused: %+v", refuse)
		}
	}

	for _, bad := range []map[string]interface{}{
		siteCreateParams(map[string]interface{}{"name": "Starter"}),
		siteCreateParams(map[string]interface{}{"domain": "example.com --wipe-data"}),
		siteCreateParams(map[string]interface{}{"port": float64(80)}),
		siteCreateParams(map[string]interface{}{"release": "latest"}),
		siteCreateParams(map[string]interface{}{"admin_email": "a@b.com --wipe-data"}),
		siteCreateParams(map[string]interface{}{"admin_email": "a@b.com\nBcc: c@d.com"}),
		siteCreateParams(map[string]interface{}{"admin_email": nil}),
		siteCreateParams(map[string]interface{}{"admin_password": "short"}),
		siteCreateParams(map[string]interface{}{"admin_password": "has a space in it"}),
		siteCreateParams(map[string]interface{}{"admin_password": "two\nlinespassword"}),
		siteCreateParams(map[string]interface{}{"admin_password": nil}),
		siteCreateParams(map[string]interface{}{"memory": "1t"}),
		siteCreateParams(map[string]interface{}{"cpus": "all"}),
		siteCreateParams(map[string]interface{}{"disk": "none"}),
		siteCreateParams(map[string]interface{}{"memory": nil}),
		siteCreateParams(map[string]interface{}{"cpus": nil}),
		siteCreateParams(map[string]interface{}{"disk": nil}),
		siteCreateParams(map[string]interface{}{"copy_of": float64(4)}),
		siteCreateParams(map[string]interface{}{"management_node": "https://evil.example"}),
	} {
		if _, err := Validate(p.Params, bad); err == nil {
			t.Errorf("refused: %v", bad)
		}
	}
}
