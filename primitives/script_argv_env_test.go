package primitives

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The two framework changes the restore family needed, and the reasons they are
// not widenings.

func TestArgvComposedNodeSideReachesTheProcess(t *testing.T) {
	// ArgsFrom exists because a "{param}" slot can only ever emit a value the
	// wire supplied, and the restores must hand a root process an ABSOLUTE PATH
	// the plane could not name. This proves the composed argv is what actually
	// runs, rather than being computed and dropped.
	root := t.TempDir()
	rel := "maintenance_scripts/sysadmin_tools/echo_argv.sh"
	full := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte("#!/bin/bash\nprintf '%s\\n' \"$@\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	p := Primitive{
		Name:  "proof_only_argsfrom",
		Class: ClassOperate,
		Script: &ScriptSpec{
			Interpreter: "/bin/bash",
			ScriptPath:  rel,
			ArgsFrom: func(ctx context.Context, env *ExecEnv, params Params) ([]string, error) {
				return []string{filepath.Join(env.SiteRoot, "backups", "resolved.sql.gz"), "--non-interactive"}, nil
			},
		},
	}
	env := &ExecEnv{SiteRoot: root, Manifest: &recordingVerifier{accept: full}}

	out, err := runScriptPrimitive(context.Background(), env, p, Params{})
	if err != nil {
		t.Fatalf("the script should have run: %v", err)
	}
	text, _ := out["output"].(string)
	want := filepath.Join(root, "backups", "resolved.sql.gz")
	if !strings.Contains(text, want) {
		t.Errorf("the process did not receive the node-composed path; argv was %q", text)
	}
	if !strings.Contains(text, "--non-interactive") {
		t.Errorf("the process did not receive the compiled-in flag; argv was %q", text)
	}
}

func TestARefusalFromArgvCompositionStopsTheRun(t *testing.T) {
	// The restores refuse inside ArgsFrom — a missing archive, an unprepared
	// chain, an unforced project restore. That has to stop the process
	// starting, not merely produce a shorter argv.
	root := t.TempDir()
	rel := "maintenance_scripts/sysadmin_tools/never_runs.sh"
	full := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(root, "it_ran")
	if err := os.WriteFile(full, []byte("#!/bin/bash\ntouch "+marker+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	p := Primitive{
		Name:  "proof_only_argsfrom_refusal",
		Class: ClassOperate,
		Script: &ScriptSpec{
			Interpreter: "/bin/bash",
			ScriptPath:  rel,
			ArgsFrom: func(ctx context.Context, env *ExecEnv, params Params) ([]string, error) {
				return nil, refusedf("this node has no such backup")
			},
		},
	}
	env := &ExecEnv{SiteRoot: root, Manifest: &recordingVerifier{accept: full}}

	if _, err := runScriptPrimitive(context.Background(), env, p, Params{}); err == nil || !Refused(err) {
		t.Fatalf("a composition refusal must be a refusal, got %v", err)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Error("the script ran despite the refusal")
	}
}

func TestAPrimitiveCannotDeclareTwoSourcesOfArgv(t *testing.T) {
	// One answer to "where did this argument come from". A spec setting both
	// would silently ignore one, and the ignored one would read as an active
	// constraint to the next reviewer.
	defer func() {
		if recover() == nil {
			t.Error("registering a primitive with both Args and ArgsFrom should panic at process start")
		}
	}()
	Register(Primitive{
		Name:  "proof_only_two_argv_sources",
		Class: ClassOperate,
		Script: &ScriptSpec{
			Interpreter: "/bin/bash",
			ScriptPath:  "maintenance_scripts/sysadmin_tools/setup_ssl.sh",
			Args:        []string{"--verbose"},
			ArgsFrom: func(ctx context.Context, env *ExecEnv, params Params) ([]string, error) {
				return nil, nil
			},
		},
	})
}

func TestAScriptStartedByThisAgentAlwaysHasAHome(t *testing.T) {
	// systemd sets $HOME only for units with User= set, and joinery-agent.service
	// sets none — it runs as root because it is a system agent. So without this
	// the agent, and every root process it starts, has no HOME at all, and the
	// platform scripts resolve the node's OWN backup key through it:
	// restore_database.sh silently looks for /.joinery_backup_key and reports
	// the node has no key, while restore_project.sh runs under `set -u` and dies
	// on the unbound variable mid-restore.
	got := EnvWithHome([]string{"PATH=/usr/bin", "LANG=C"})
	var home string
	for _, entry := range got {
		if strings.HasPrefix(entry, "HOME=") {
			home = strings.TrimPrefix(entry, "HOME=")
		}
	}
	if home == "" {
		t.Fatal("a child started with no HOME in the environment must be given one")
	}
	if !filepath.IsAbs(home) {
		t.Errorf("HOME is %q, which is not a directory", home)
	}
}

func TestAnExistingHomeIsLeftAlone(t *testing.T) {
	// The value is the account's, not a job's — but where the environment
	// already carries one, that is the operator's answer and this must not
	// second-guess it.
	got := EnvWithHome([]string{"HOME=/home/operator", "PATH=/usr/bin"})
	if len(got) != 2 || got[0] != "HOME=/home/operator" {
		t.Errorf("an existing HOME should survive untouched, got %q", got)
	}

	// An EMPTY one is not an answer, though: "$HOME/.joinery_backup_key" with
	// HOME set to nothing is /.joinery_backup_key, which is the same silent
	// miss as having none.
	got = EnvWithHome([]string{"HOME=", "PATH=/usr/bin"})
	if len(got) != 3 || !strings.HasPrefix(got[2], "HOME=/") {
		t.Errorf("an empty HOME should be overridden, got %q", got)
	}
}
