package primitives

import "testing"

func TestReclaimManagedFileTakesOnlyAResettableName(t *testing.T) {
	p, ok := Lookup("reclaim_managed_file")
	if !ok {
		t.Fatal("reclaim_managed_file should be registered")
	}
	for _, f := range reclaimFiles {
		if _, err := Validate(p.Params, map[string]interface{}{"file": f}); err != nil {
			t.Errorf("%q must validate: %v", f, err)
		}
		// Every resettable file is also a readable one: the driver reads a
		// file before it resets it.
		if _, readable := fileHeadFiles[f]; !readable {
			t.Errorf("%q is resettable but not on file_head's readable list", f)
		}
	}
	for _, bad := range []string{"apache2_conf", "apache_site_ssl", "postfix_main", "sysctl_security", "apt_auto_upgrades", "docker_daemon", "/etc/passwd", ""} {
		if _, err := Validate(p.Params, map[string]interface{}{"file": bad}); err == nil {
			t.Errorf("%q must never be resettable", bad)
		}
	}
	if p.Class != ClassOperate || p.Script == nil || p.Script.ScriptPath != reclaimManagedFileScript || len(p.Script.Args) != 1 {
		t.Error("reclaim_managed_file is an operate script word with one validated slot")
	}
}
