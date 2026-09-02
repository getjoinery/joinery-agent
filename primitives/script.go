package primitives

// script.go is the ONLY file in this package permitted to start a process.
// gate_test.go asserts that: it fails the build's tests if any other file here
// imports os/exec, and it fails if the string "-c" ever appears next to a shell
// name anywhere in the package. A future primitive that wants to run something
// therefore cannot quietly grow its own exec call — it has to come through here,
// past the manifest verification below, in a change a reviewer will see.

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

// MaxScriptOutputBytes bounds what one script may hand back. Output beyond it
// is dropped and reported as dropped — the count is what the caller reads, not
// the length of what survived.
//
// Sized to leave room: this output travels inside a result body that also
// carries a log and an envelope, and the whole thing has to fit under the
// plane's inbound cap. A ceiling equal to that cap would guarantee that a
// chatty script's result is refused at the far end and lost.
const MaxScriptOutputBytes = 64 * 1024

// ScriptSpec is a fixed argv template. The interpreter and the script are
// chosen at compile time; the only thing a job supplies is the values for the
// named parameter slots, each of which has already been validated against the
// primitive's declared spec.
//
// There is no shell anywhere in this path. Argv is passed to the kernel as a
// list, so a parameter containing a semicolon is a parameter containing a
// semicolon — there is nothing to parse it.
type ScriptSpec struct {
	// Interpreter is the absolute path to the program that runs the script,
	// e.g. /usr/bin/php or /bin/bash for a platform .sh file. It is not
	// verified against the manifest (it is not ours), but it is compiled in.
	Interpreter string

	// ScriptPath is the tree-relative path of the platform script, resolved
	// against ExecEnv.SiteRoot. This is the file verified against the signed
	// release manifest before anything runs.
	ScriptPath string

	// Args is the fixed argument template. An element of the form "{param}"
	// is replaced by that validated parameter's value; every other element is
	// passed through literally. A "{param}" naming an absent optional
	// parameter drops the element.
	Args []string

	// ArgsFrom composes argv from validated params AND the node's own resolved
	// environment. Set this OR Args, never both; Register refuses a spec that
	// sets both, so there is one answer to "where did this argv come from".
	//
	// It is the exact twin of StdinFrom, and it exists for the exact twin of
	// StdinFrom's reason. Some platform scripts want a composed object on
	// stdin; others want an ABSOLUTE PATH in argv — and a path is the one thing
	// the plane must never be able to express (§ upload_backup, delete_backup).
	// A "{param}" slot can only ever emit a value the wire supplied, so a
	// template alone would leave exactly two ways to give restore_database.sh
	// the file it must read: let the plane send a path, or hardcode a directory
	// that is wrong on every container node (see backupdirs.go, which exists
	// because that hardcoding was the bug). This is the third way: the wire
	// supplies a NAME, and the node — which is the only party that knows where
	// its own backups live — turns it into a path here.
	//
	// It widens nothing that StdinFrom did not already widen. It receives the
	// same validated Params, it cannot see the raw wire object, and every
	// element it returns goes to the kernel as a list element. There is still
	// no shell, and script.go is still the only file that may start a process.
	ArgsFrom func(ctx context.Context, env *ExecEnv, params Params) ([]string, error)

	// StdinFrom builds what the script reads on standard input, from validated
	// params. Nil means the script gets no stdin.
	//
	// A builder rather than a "{param}" template because what these scripts want
	// on stdin is a composed object, not one value — and composing it HERE, from
	// a fixed set of declared parameters, is what stops the plane adding a field
	// by sending one.
	//
	// This exists because some platform scripts take their configuration on
	// stdin deliberately, and say so: run_backup.php's header reads "Stdin
	// rather than an argument on purpose. Anything in argv is visible to every
	// [process on the box]." Its config carries a storage credential, so an
	// argv template would leak it into ps on every node on every run.
	//
	// Stdin is DATA, never a command channel. The interpreter always receives a
	// manifest-verified ScriptPath as its program, so what arrives here is input
	// to that script and cannot become the thing executed. It is also never
	// logged: not in the agent log, not in the posted result, not on failure —
	// the whole reason it is not in argv is that it must not be visible, and a
	// log line is as visible as ps.
	StdinFrom func(params Params) (string, error)
}

// runScriptPrimitive verifies the script against the signed release manifest,
// then runs it with an explicit argv.
func runScriptPrimitive(ctx context.Context, env *ExecEnv, p Primitive, params Params) (map[string]interface{}, error) {
	if env == nil {
		return nil, refusedf("primitive %q has no execution environment", p.Name)
	}

	// Which tree this script lives in, and which manifest speaks for it.
	//
	// A site root wins wherever there is one, so nothing changes for a machine
	// that has a site: same tree, same manifest, same refusals. A machine with
	// no site uses the signed support bundle instead — and a machine with
	// NEITHER refuses exactly as it always did. The script path is the same
	// string in both cases, because bundle paths are recorded relative to a
	// site root too, so no primitive has to know which posture it is running in.
	root, verifier := env.SiteRoot, env.Manifest
	if root == "" {
		root, verifier = env.ToolRoot, env.ToolManifest
	}
	if root == "" {
		return nil, refusedf("primitive %q cannot run: this machine has no site root and no support bundle, so there is no tree to resolve %s in", p.Name, p.Script.ScriptPath)
	}
	if verifier == nil {
		return nil, refusedf("primitive %q cannot run: this agent has no manifest verifier, so it cannot prove the script it would execute as root is the one the publisher shipped", p.Name)
	}

	scriptPath := filepath.Join(root, filepath.FromSlash(p.Script.ScriptPath))
	if err := verifier.Verify(scriptPath); err != nil {
		return nil, refusedf("primitive %q refused: %v", p.Name, err)
	}

	argv, err := resolveArgv(ctx, env, p, params)
	if err != nil {
		return nil, err
	}

	cmd := exec.CommandContext(ctx, p.Script.Interpreter, append([]string{scriptPath}, argv...)...)

	// Resolved here and handed straight to the process. It is deliberately not
	// held anywhere that gets logged, returned, or attached to an error — see
	// ScriptSpec.StdinFrom.
	if p.Script.StdinFrom != nil {
		stdin, err := p.Script.StdinFrom(params)
		if err != nil {
			return nil, err
		}
		cmd.Stdin = strings.NewReader(stdin)
	}

	// The child's environment, with one thing guaranteed: a HOME.
	//
	// systemd sets $HOME only for units that set User= (systemd.exec: "$HOME,
	// $LOGNAME, and $SHELL are only set for the units that have User= set").
	// joinery-agent.service sets no User= — it runs as root because it is a
	// system agent — so the agent process, and every root process it starts,
	// inherits NO HOME at all.
	//
	// That is not cosmetic. The platform scripts resolve the node's own backup
	// key through it, and they fail two different ways on an empty value:
	// restore_database.sh runs under `set -o pipefail` alone, so
	// "$HOME/.joinery_backup_key" quietly becomes "/.joinery_backup_key" and the
	// node reports having no key; restore_project.sh runs under `set -euo
	// pipefail`, where an UNSET $HOME is an unbound variable and the script dies
	// mid-restore. A node that decrypts its own backups perfectly by hand would
	// have failed to over the agent, and the reason would have been nowhere in
	// the output.
	//
	// The value is resolved from the passwd database, never from a job: it is a
	// property of the account this process runs as, and nothing on the wire can
	// influence it.
	cmd.Env = EnvWithHome(os.Environ())

	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	runErr := cmd.Run()

	text, dropped := capOutput(out.Bytes(), MaxScriptOutputBytes)
	result := map[string]interface{}{
		"output":       text,
		"output_bytes": out.Len(),
	}
	if dropped {
		result["output_truncated"] = true
	}
	if runErr != nil {
		return result, fmt.Errorf("%s exited with an error: %w", p.Script.ScriptPath, runErr)
	}
	return result, nil
}

// resolveArgv produces the argument list for one run, from whichever of the two
// mechanisms the primitive declared. Neither one is reachable from the wire: a
// template can only emit validated values, and a builder is compiled-in code.
func resolveArgv(ctx context.Context, env *ExecEnv, p Primitive, params Params) ([]string, error) {
	if p.Script.ArgsFrom != nil {
		return p.Script.ArgsFrom(ctx, env, params)
	}
	return resolveArgs(p.Script.Args, params)
}

// resolveArgs fills the "{param}" slots of a fixed template from validated
// params. A slot naming a parameter the primitive never declared is a build
// mistake and refuses rather than passing a literal "{typo}" to a root process.
func resolveArgs(template []string, params Params) ([]string, error) {
	out := make([]string, 0, len(template))
	for _, element := range template {
		if !strings.HasPrefix(element, "{") || !strings.HasSuffix(element, "}") {
			out = append(out, element)
			continue
		}
		name := element[1 : len(element)-1]
		if !params.Has(name) {
			continue
		}
		switch v := params.values[name].(type) {
		case string:
			out = append(out, v)
		case int64:
			out = append(out, fmt.Sprintf("%d", v))
		case bool:
			if v {
				out = append(out, "true")
			} else {
				out = append(out, "false")
			}
		default:
			return nil, refusedf("argument slot %q has no usable value", name)
		}
	}
	return out, nil
}

// capOutput trims to max bytes, reporting whether anything was dropped.
//
// It keeps BOTH ENDS, and the tail is the larger share. Keeping only the head —
// which is what this did first — throws away the part of a transcript that says
// how it turned out. Every script this package runs puts its verdict last:
// upgrade.php's version lines and its "PLEASE RE-RUN THE UPGRADE" request, the
// installer runner's per-plugin results, run_backup.php's manifest summary. A
// head-only cap on a chatty run therefore returns the part nobody needs and
// drops the part the plane parses, which reads as an upgrade that produced no
// verdict rather than one whose verdict was discarded.
//
// The head is kept as well because the start of a transcript says what the run
// was doing — which release, which tree — and a tail alone can be a page of
// output with no idea what produced it.
//
// The notice between them is counted against the budget, so the result is never
// larger than max. It names the byte count rather than saying "truncated": the
// caller also reports output_bytes, and the two together let a reader tell a
// slightly-over run from one that produced megabytes.
func capOutput(b []byte, max int) (string, bool) {
	if len(b) <= max {
		return string(b), false
	}

	notice := fmt.Sprintf("\n\n[... %d bytes dropped by the agent's output cap ...]\n\n", len(b)-max)
	room := max - len(notice)
	if room <= 0 {
		// A cap too small to hold the notice: keep the end, which is the half
		// that carries the outcome.
		return string(trimPartialRuneAtStart(b[len(b)-max:])), true
	}

	head := room / 4
	tail := room - head
	return string(trimPartialRuneAtEnd(b[:head])) +
		notice +
		string(trimPartialRuneAtStart(b[len(b)-tail:])), true
}

// trimPartialRuneAtEnd and trimPartialRuneAtStart drop a multi-byte character
// left half-written by cutting at a byte offset. Both seams need it now that
// there are two of them, and a mangled rune at a seam is the kind of thing that
// gets read as corruption in the transcript rather than as an artifact of the
// cap.
// Both give up after UTFMax-1 bytes. A longer run of undecodable bytes is not a
// seam artefact, it is output that was never text — and eating it would turn a
// script that printed binary into a script that printed nothing.
func trimPartialRuneAtEnd(b []byte) []byte {
	for i := 0; i < utf8.UTFMax-1 && len(b) > 0; i++ {
		if r, size := utf8.DecodeLastRune(b); r != utf8.RuneError || size > 1 {
			break
		}
		b = b[:len(b)-1]
	}
	return b
}

func trimPartialRuneAtStart(b []byte) []byte {
	for i := 0; i < utf8.UTFMax-1 && len(b) > 0; i++ {
		if r, size := utf8.DecodeRune(b); r != utf8.RuneError || size > 1 {
			break
		}
		b = b[1:]
	}
	return b
}

// EnvWithHome returns env unchanged when it already carries a usable HOME, and
// otherwise appends one resolved from the passwd entry of the account this
// process runs as. A later assignment wins in execve, so appending is enough.
//
// It falls back to /root only when the passwd lookup itself fails, which on a
// managed node means a broken account database — and a root process with no
// home at all is worse than one pointed at the conventional answer.
func EnvWithHome(env []string) []string {
	for _, entry := range env {
		if strings.HasPrefix(entry, "HOME=") && len(entry) > len("HOME=") {
			return env
		}
	}
	home := "/root"
	if u, err := user.Current(); err == nil && u.HomeDir != "" {
		home = u.HomeDir
	}
	return append(env, "HOME="+home)
}
