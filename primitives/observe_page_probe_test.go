package primitives

import "testing"

func TestPageProbeTakesAPathAndAViewer(t *testing.T) {
	p, ok := Lookup("page_probe")
	if !ok {
		t.Fatal("page_probe should be registered")
	}
	for _, good := range []string{"/", "/admin/admin_users", "/profile/account_edit", "/plugins/store/admin/admin_orders"} {
		if _, err := Validate(p.Params, map[string]interface{}{"page": good, "viewer": "admin"}); err != nil {
			t.Errorf("%q must validate: %v", good, err)
		}
	}
	for _, bad := range []string{"", "admin", "/x?y=1", "/x#y", "https://evil/", "/X", "/a b", "//evil.example/x"} {
		if _, err := Validate(p.Params, map[string]interface{}{"page": bad, "viewer": "admin"}); err == nil {
			t.Errorf("page %q must be refused", bad)
		}
	}
	for _, bad := range []string{"root", "superadmin", "", "Admin"} {
		if _, err := Validate(p.Params, map[string]interface{}{"page": "/", "viewer": bad}); err == nil {
			t.Errorf("viewer %q must be refused", bad)
		}
	}
	if p.Class != ClassObserve || p.Script == nil || p.Script.ScriptPath != pageProbeScript || p.Machine || p.RequiresLogAccess || p.Script.Redact {
		t.Error("page_probe is a site observe script word printing compiled facts")
	}
	if len(p.Script.Args) != 2 || p.Script.Args[0] != "{page}" || p.Script.Args[1] != "{viewer}" {
		t.Errorf("argv should be the two validated slots, got %v", p.Script.Args)
	}
}
