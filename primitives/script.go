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
	"os/exec"
	"path/filepath"
	"strings"
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
	if env == nil || env.Manifest == nil {
		return nil, refusedf("primitive %q cannot run: this agent has no manifest verifier, so it cannot prove the script it would execute as root is the one the publisher shipped", p.Name)
	}
	if env.SiteRoot == "" {
		return nil, refusedf("primitive %q cannot run: this node has no site root", p.Name)
	}

	scriptPath := filepath.Join(env.SiteRoot, filepath.FromSlash(p.Script.ScriptPath))
	if err := env.Manifest.Verify(scriptPath); err != nil {
		return nil, refusedf("primitive %q refused: %v", p.Name, err)
	}

	argv, err := resolveArgs(p.Script.Args, params)
	if err != nil {
		return nil, err
	}

	cmd := exec.CommandContext(ctx, p.Script.Interpreter, append([]string{scriptPath}, argv...)...)

	// Resolved here and handed straight to the process. It is deliberately not
	// held anywhere that gets logged, returned, or attached to an error — see
	// ScriptSpec.Stdin.
	if p.Script.StdinFrom != nil {
		stdin, err := p.Script.StdinFrom(params)
		if err != nil {
			return nil, err
		}
		cmd.Stdin = strings.NewReader(stdin)
	}

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
func capOutput(b []byte, max int) (string, bool) {
	if len(b) <= max {
		return string(b), false
	}
	return string(b[:max]), true
}
