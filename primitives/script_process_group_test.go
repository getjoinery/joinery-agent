package primitives

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A script primitive's timeout kills everything the script started, not only
// the interpreter the agent forked.
//
// Why it matters: after _plugin_installers_start.sh 2.16 the runner lock is a
// kernel flock on a descriptor every child inherits. Kill bash and leave its
// backgrounded child alive, and that child holds the lock for as long as it
// lives; the next runner then waits its full bound on a process nobody meant
// to keep. The fixture below is that shape exactly — a child that would sleep
// far past the timeout, and a parent waiting on it — and the assertion is that
// the child is gone once the primitive has returned.

func TestATimedOutScriptTakesItsChildrenWithIt(t *testing.T) {
	root := t.TempDir()
	rel := "maintenance_scripts/sysadmin_tools/hang_with_child.sh"
	full := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	pidFile := filepath.Join(root, "child.pid")

	// The child's pid is written by the parent, from the literal argv element
	// below — a proof-only primitive; nothing registered may carry a literal
	// path this way, and this one is never registered.
	script := "#!/bin/bash\n" +
		"sleep 300 &\n" +
		"echo $! > \"$1\"\n" +
		"wait\n"
	if err := os.WriteFile(full, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	p := Primitive{
		Name:  "proof_only_process_group",
		Class: ClassOperate,
		Script: &ScriptSpec{
			Interpreter: "/bin/bash",
			ScriptPath:  rel,
			Args:        []string{pidFile},
		},
	}
	env := &ExecEnv{SiteRoot: root, Manifest: &recordingVerifier{accept: full}}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	started := time.Now()
	_, err := runScriptPrimitive(ctx, env, p, Params{})
	elapsed := time.Since(started)
	if err == nil {
		t.Fatal("a script that outlives its deadline must return an error")
	}
	if elapsed > 15*time.Second {
		t.Fatalf("the primitive took %v to return after a 1s deadline — the timeout did not end the run", elapsed)
	}

	raw, readErr := os.ReadFile(pidFile)
	if readErr != nil {
		t.Fatalf("the fixture never recorded its child's pid: %v", readErr)
	}
	childPid, convErr := strconv.Atoi(strings.TrimSpace(string(raw)))
	if convErr != nil || childPid <= 0 {
		t.Fatalf("unreadable child pid %q", raw)
	}

	// A killed child is reaped by init once bash is gone; give that a moment.
	deadline := time.Now().Add(5 * time.Second)
	for {
		killErr := syscall.Kill(childPid, 0)
		if killErr == syscall.ESRCH {
			return
		}
		if time.Now().After(deadline) {
			syscall.Kill(childPid, syscall.SIGKILL) // clean up after the failure
			t.Fatalf("the script's backgrounded child (pid %d) survived the timeout — "+
				"only the interpreter was killed, and a survivor holds every descriptor it inherited, "+
				"the runner lock included", childPid)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// The script is the leader of its own process group, so the group kill can
// never reach the agent itself: signalling -pid with pid == the agent's own
// group would take the agent down with the script.
func TestAScriptRunsInItsOwnProcessGroup(t *testing.T) {
	root := t.TempDir()
	rel := "maintenance_scripts/sysadmin_tools/report_pgid.sh"
	full := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte("#!/bin/bash\nps -o pgid= -p $$\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	p := Primitive{
		Name:   "proof_only_pgid",
		Class:  ClassOperate,
		Script: &ScriptSpec{Interpreter: "/bin/bash", ScriptPath: rel},
	}
	env := &ExecEnv{SiteRoot: root, Manifest: &recordingVerifier{accept: full}}

	out, err := runScriptPrimitive(context.Background(), env, p, Params{})
	if err != nil {
		t.Fatalf("the script should have run: %v", err)
	}
	text, _ := out["output"].(string)
	pgid, convErr := strconv.Atoi(strings.TrimSpace(text))
	if convErr != nil {
		t.Fatalf("unreadable pgid %q", text)
	}
	if pgid == syscall.Getpgrp() {
		t.Fatalf("the script shares the agent's process group (%d); a group kill would kill the agent", pgid)
	}
}
