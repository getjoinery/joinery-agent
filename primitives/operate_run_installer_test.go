package primitives

import (
	"context"
	"testing"
)

func TestRunInstallerAcceptsOnlyAnInstallerName(t *testing.T) {
	p, ok := Lookup("run_installer")
	if !ok {
		t.Fatal("run_installer should be registered")
	}
	good := append([]string{"plugin:mailbox", "plugin:persona_browser"}, runInstallerCore...)
	for _, name := range good {
		if _, err := Validate(p.Params, map[string]interface{}{"name": name}); err != nil {
			t.Errorf("%q must validate: %v", name, err)
		}
	}
	for _, bad := range []string{
		"", "install.sh", "_site_init.sh", "../install_agent.sh", "/bin/sh",
		"host_housekeeping.sh --when-changed", "plugin:", "plugin:../x", "plugin:Mailbox",
		"plugin:mailbox/../../x", "--only=render_vhost.sh", "fix_permissions.sh",
	} {
		if _, err := Validate(p.Params, map[string]interface{}{"name": bad}); err == nil {
			t.Errorf("%q must be refused", bad)
		}
	}
	if p.Class != ClassOperate || p.Script == nil || p.Script.ScriptPath != pluginInstallersRunner {
		t.Error("run_installer is an operate word over the host runner")
	}
	if p.Script.Args != nil || p.Script.ArgsFrom == nil {
		t.Error("argv is composed from the name and the posture, never a template")
	}
}

// The core half of the pattern is exactly the runner's list.
func TestRunInstallerCoreListIsThePattern(t *testing.T) {
	for _, n := range runInstallerCore {
		if !runInstallerName.MatchString(n) {
			t.Errorf("%q is a core installer and the pattern must accept it", n)
		}
	}
	for _, h := range runInstallerHost {
		found := false
		for _, c := range runInstallerCore {
			found = found || c == h
		}
		if !found {
			t.Errorf("host installer %q must also be a core installer", h)
		}
	}
}

func TestRunInstallerArgv(t *testing.T) {
	p, _ := Lookup("run_installer")
	site := &ExecEnv{SiteRoot: "/var/www/html/x"}
	machine := &ExecEnv{SiteRoot: ""}
	cases := []struct {
		env  *ExecEnv
		name string
		want []string
		err  bool
	}{
		{site, "render_vhost.sh", []string{"--only=render_vhost.sh"}, false},
		{site, "plugin:mailbox", []string{"--only-plugin=mailbox"}, false},
		{machine, "host_housekeeping.sh", []string{"--machine", "--only=host_housekeeping.sh"}, false},
		{machine, "render_vhost.sh", nil, true},
		{machine, "plugin:mailbox", nil, true},
	}
	for _, c := range cases {
		params, err := Validate(p.Params, map[string]interface{}{"name": c.name})
		if err != nil {
			t.Fatalf("%q: %v", c.name, err)
		}
		got, err := p.Script.ArgsFrom(context.Background(), c.env, params)
		if c.err {
			if err == nil || !Refused(err) {
				t.Errorf("%q on this posture must refuse, got %v %v", c.name, got, err)
			}
			continue
		}
		if err != nil || len(got) != len(c.want) {
			t.Errorf("%q: got %v %v, want %v", c.name, got, err, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("%q: argv %v, want %v", c.name, got, c.want)
			}
		}
	}
}
