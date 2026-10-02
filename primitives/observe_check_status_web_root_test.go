package primitives

import (
	"context"
	"testing"
)

// check_status names the site's web root, so the plane can fill a node record
// made without one. A machine with no site names none.
func TestCheckStatusReportsTheWebRoot(t *testing.T) {
	root := t.TempDir()
	result, err := runCheckStatus(context.Background(), &ExecEnv{WebRoot: root}, Params{})
	if err != nil {
		t.Fatal(err)
	}
	if result["web_root"] != root {
		t.Fatalf("web_root = %v, want %s", result["web_root"], root)
	}

	siteless, err := runCheckStatus(context.Background(), &ExecEnv{}, Params{})
	if err != nil {
		t.Fatal(err)
	}
	if _, has := siteless["web_root"]; has {
		t.Fatalf("a siteless machine reported a web root: %v", siteless["web_root"])
	}
}

// check_status names the site's domain, so the plane can fill a node record
// made without a site address. A machine with no domain names none.
func TestCheckStatusReportsTheSiteDomain(t *testing.T) {
	result, err := runCheckStatus(context.Background(), &ExecEnv{WebRoot: t.TempDir(), SiteDomain: "copytest.example.com"}, Params{})
	if err != nil {
		t.Fatal(err)
	}
	if result["site_domain"] != "copytest.example.com" {
		t.Fatalf("site_domain = %v, want copytest.example.com", result["site_domain"])
	}

	none, err := runCheckStatus(context.Background(), &ExecEnv{WebRoot: t.TempDir()}, Params{})
	if err != nil {
		t.Fatal(err)
	}
	if _, has := none["site_domain"]; has {
		t.Fatalf("a site with no domain reported one: %v", none["site_domain"])
	}
}
