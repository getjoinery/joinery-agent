package primitives

import (
	"context"
	"strings"
	"testing"
)

// mail_log_summary's review rests on these: one parameter, bounded; the one
// script it names, as root; behind the owner's log switch; not a machine word.
func TestMailLogSummaryShape(t *testing.T) {
	p, ok := Lookup("mail_log_summary")
	if !ok {
		t.Fatal("mail_log_summary should be registered")
	}
	if p.Class != ClassObserve {
		t.Errorf("mail_log_summary is %q, want observe", p.Class)
	}
	if !p.RequiresLogAccess {
		t.Error("mail_log_summary reads the journal; it must sit behind the owner's log switch")
	}
	if p.Machine {
		t.Error("mail_log_summary is a site's word: a siteless host must not offer it")
	}
	if p.Script == nil || p.Run != nil {
		t.Fatal("mail_log_summary is a script word and nothing else")
	}
	if p.Script.ScriptPath != mailLogSummaryScript || p.Script.Interpreter != "/usr/bin/php" {
		t.Errorf("runs %s %s", p.Script.Interpreter, p.Script.ScriptPath)
	}
	if !strings.HasPrefix(p.Script.ScriptPath, "maintenance_scripts/sysadmin_tools/") {
		t.Error("a word's script lives in the signed sysadmin_tools")
	}
	if p.Script.AsSiteUser {
		t.Error("the journal is read as root")
	}
	if len(p.Script.Args) != 1 || p.Script.Args[0] != "{hours}" || p.Script.ArgsFrom != nil || p.Script.StdinFrom != nil {
		t.Errorf("argv must be the one {hours} slot and stdin empty: %v", p.Script.Args)
	}
	if p.Script.Redact {
		t.Error("every value is compiled or pattern-checked; the redactor would mangle the domains")
	}
}

func TestMailLogSummaryParams(t *testing.T) {
	p, _ := Lookup("mail_log_summary")
	for _, bad := range []map[string]interface{}{
		{"hours": 0}, {"hours": 169}, {"hours": -1}, {"hours": "24; id"},
		{"hours": 24, "unit": "postfix"}, {"path": "/var/log/mail.log"}, {"pattern": "."},
	} {
		if _, err := Validate(p.Params, bad); err == nil {
			t.Errorf("a job carrying %v must be refused", bad)
		}
	}
	for _, good := range []map[string]interface{}{nil, {"hours": 1}, {"hours": 24}, {"hours": 168}} {
		if _, err := Validate(p.Params, good); err != nil {
			t.Errorf("%v should be accepted: %v", good, err)
		}
	}
	params, _ := Validate(p.Params, map[string]interface{}{"hours": 24})
	argv, err := resolveArgs(p.Script.Args, params)
	if err != nil || len(argv) != 1 || argv[0] != "24" {
		t.Errorf("argv = %v, %v; want [24]", argv, err)
	}
	none, _ := Validate(p.Params, nil)
	argv, _ = resolveArgs(p.Script.Args, none)
	if len(argv) != 0 {
		t.Errorf("no hours gives no argument (the script's default of 24): %v", argv)
	}
}

func TestMailLogSummaryRefusesWhenTheOwnerSaysNo(t *testing.T) {
	env := logTableEnv(t, "", nil)
	_, err := Execute(context.Background(), env, ShippedPolicy(),
		Request{Primitive: "mail_log_summary", Params: map[string]interface{}{"hours": 24}})
	if err == nil || !Refused(err) || err.Error() != LogAccessRefusal {
		t.Fatalf("expected the owner's refusal, got %v", err)
	}
}
