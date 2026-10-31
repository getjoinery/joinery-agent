package primitives

import (
	"testing"
	"time"
)

// site_converger is a gated script word that names one site container. The
// tests are about the shape its hostile-caller review relies on: the site is
// a name of the container shape and nothing else, the line count is bounded,
// nothing else steers it, the switch is declared, what it prints is redacted,
// and it starts the one shipped script.

func TestSiteConvergerTakesOnlyASiteName(t *testing.T) {
	p, ok := Lookup("site_converger")
	if !ok {
		t.Fatal("site_converger should be registered")
	}
	for _, site := range []string{"sa", "wd5", "joinerytest", "a-b_c"} {
		if _, err := Validate(p.Params, map[string]interface{}{"site": site}); err != nil {
			t.Errorf("%q is a site name and must validate: %v", site, err)
		}
	}
	for _, bad := range []string{
		"",
		"../sa",
		"/var/www/html/sa",
		"sa/logs",
		"Sa",
		"-sa",
		"sa;id",
		"sa logs",
		"a23456789012345678901234567890123456789012345678901",
	} {
		if _, err := Validate(p.Params, map[string]interface{}{"site": bad}); err == nil {
			t.Errorf("site %q must be refused", bad)
		}
	}
	if _, err := Validate(p.Params, map[string]interface{}{}); err == nil {
		t.Error("site is required; a missing one must refuse rather than read every site")
	}
}

func TestSiteConvergerBoundsTheLineCountAndTakesNothingElse(t *testing.T) {
	p, _ := Lookup("site_converger")
	if _, err := Validate(p.Params, map[string]interface{}{"site": "sa", "lines": 200}); err != nil {
		t.Errorf("200 lines is the cap and must validate: %v", err)
	}
	for _, bad := range []interface{}{0, -1, 201, 100000} {
		if _, err := Validate(p.Params, map[string]interface{}{"site": "sa", "lines": bad}); err == nil {
			t.Errorf("lines=%v must be refused; the cap is %d", bad, siteConvergerMaxLines)
		}
	}
	for _, key := range []string{"file", "path", "since", "grep", "volume", "container"} {
		if _, err := Validate(p.Params, map[string]interface{}{"site": "sa", key: "anything"}); err == nil {
			t.Errorf("a job carrying %q must be refused; there is no pass-through", key)
		}
	}
}

func TestSiteConvergerIsGatedRedactedAndRunsItsScript(t *testing.T) {
	p, _ := Lookup("site_converger")
	if p.Class != ClassObserve {
		t.Errorf("site_converger is observe, not %q", p.Class)
	}
	if !p.Machine {
		t.Error("site_converger is a machine word: it reads a container site from its host")
	}
	if !p.RequiresLogAccess {
		t.Error("site_converger reads a log: it must ask the owner's switch")
	}
	if p.Run != nil || p.Script == nil {
		t.Fatal("site_converger is a script word with no embedded Run")
	}
	if !p.Script.Redact {
		t.Error("the converger log is text this node did not compose; it is masked here or it leaves unmasked")
	}
	if p.Script.ScriptPath != siteConvergerScript || p.Script.Interpreter != "/bin/bash" {
		t.Errorf("should run %q under /bin/bash, got %q under %q", siteConvergerScript, p.Script.ScriptPath, p.Script.Interpreter)
	}
	if p.Script.StdinFrom != nil || p.Script.ArgsFrom != nil {
		t.Error("argv is the fixed template; nothing composes it from the environment")
	}
	if len(p.Script.Args) != 2 || p.Script.Args[0] != "{site}" || p.Script.Args[1] != "{lines}" {
		t.Errorf("argv should be the two validated slots, got %v", p.Script.Args)
	}
	if p.Timeout > 2*time.Minute {
		t.Errorf("a few local reads; a timeout of %v says otherwise", p.Timeout)
	}
}
