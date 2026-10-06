package primitives

import "testing"

func TestRemoveSiteCertificateTakesOnlyACertificateName(t *testing.T) {
	p, ok := Lookup("remove_site_certificate")
	if !ok {
		t.Fatal("remove_site_certificate should be registered")
	}
	for _, good := range []string{"demo.getjoinery.com", "getjoinery.com", "a-b.example.org", "demo.getjoinery.com-0001"} {
		if _, err := Validate(p.Params, map[string]interface{}{"name": good}); err != nil {
			t.Errorf("%q is a certificate name and must validate: %v", good, err)
		}
	}
	for _, bad := range []string{"", "localhost", "Demo.getjoinery.com", "../etc", "demo.getjoinery.com/x",
		"-demo.example.com", "*.example.com", "a b.com", "x.com;reboot", "--all"} {
		if _, err := Validate(p.Params, map[string]interface{}{"name": bad}); err == nil {
			t.Errorf("name %q must be refused", bad)
		}
	}
	if p.Class != ClassOperate || !p.Machine || p.Script == nil || p.Script.ScriptPath != removeSiteCertificateScript {
		t.Error("remove_site_certificate is an operate machine script word running the shipped script")
	}
	if len(p.Script.Args) != 1 || p.Script.Args[0] != "{name}" || p.Script.StdinFrom != nil || p.Script.ArgsFrom != nil {
		t.Errorf("argv should be the one validated slot, got %v", p.Script.Args)
	}
}
