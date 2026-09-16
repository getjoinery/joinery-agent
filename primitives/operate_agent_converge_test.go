package primitives

import (
	"context"
	"strings"
	"testing"
)

// agent_converge is host_converge's twin for the agent installer: one compiled
// argv constant, no parameter that could reach it, and a refusal where there
// is no site tree to run the installer from.

func TestAgentConvergeAsksForNothing(t *testing.T) {
	p, ok := Lookup("agent_converge")
	if !ok {
		t.Fatal("agent_converge should be registered")
	}
	if len(p.Params) != 0 {
		t.Fatalf("agent_converge declares %d parameter(s); it must declare none", len(p.Params))
	}
	if p.Class != ClassOperate {
		t.Errorf("agent_converge is operate, not %q", p.Class)
	}
}

func TestAgentConvergeArgvIsTheCompiledConstantOrARefusal(t *testing.T) {
	p, _ := Lookup("agent_converge")
	if p.Script == nil || p.Script.ScriptPath != pluginInstallersRunner || p.Script.Interpreter != "/bin/bash" {
		t.Fatalf("agent_converge runs the shipped runner under bash; got %+v", p.Script)
	}
	if p.Script.Args != nil || p.Script.ArgsFrom == nil {
		t.Fatal("agent_converge picks its argv in ArgsFrom and carries no template")
	}
	if agentConvergeOnly != "--only=install_agent.sh" {
		t.Errorf("the constant names the agent installer in the runner's single-installer mode, got %q", agentConvergeOnly)
	}
	argv, err := p.Script.ArgsFrom(context.Background(), &ExecEnv{SiteRoot: "/var/www/html/site"}, Params{})
	if err != nil || len(argv) != 1 || argv[0] != agentConvergeOnly {
		t.Fatalf("on a site the argv should be exactly [%q], got %v (%v)", agentConvergeOnly, argv, err)
	}
	// A parameter changes nothing.
	a2, _ := p.Script.ArgsFrom(context.Background(), &ExecEnv{SiteRoot: "/var/www/html/site"}, Params{values: map[string]interface{}{"only": "render_vhost.sh"}})
	if strings.Join(a2, " ") != agentConvergeOnly {
		t.Errorf("a parameter changed the argv to %v", a2)
	}
	// A machine with no site: refused, never guessed.
	for _, env := range []*ExecEnv{nil, {SiteRoot: "", ToolRoot: "/opt/joinery-agent/tree"}} {
		argv, err := p.Script.ArgsFrom(context.Background(), env, Params{})
		if err == nil || !Refused(err) || argv != nil {
			t.Errorf("with no site the word should refuse, got argv %v err %v", argv, err)
		}
	}
}
