package primitives

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// pinnedVocabulary is the complete vocabulary this agent ships with, written
// out by hand.
//
// It is a pin in the same sense as the server_initiated_write caller list: the
// point is not that the list is correct, it is that the list cannot CHANGE
// without a human editing this file. A primitive that arrives without a line
// here fails the build's tests, so "the fleet quietly gained a capability" is
// not a thing that can happen between releases.
// Pins are written BEFORE the primitive they name, deliberately, while several
// primitives are being built at once. This file is the one file every new
// primitive has to touch, so five authors editing it is five chances to lose an
// edit; writing the intended vocabulary once, up front, makes it single-writer.
//
// The cost is that this test is red between the pin and the primitive, failing
// with "pinned but not registered". That is the honest reading — the vocabulary
// this release intends to ship, minus what has landed — and it is a checklist
// rather than a defect. It goes green when the last primitive lands, and a pin
// still red at release time is a primitive that was abandoned, which is exactly
// the thing worth being told about.
var pinnedVocabulary = map[string]Class{
	"check_status":        ClassObserve,
	"list_backups":        ClassObserve,
	"recovery_key_report": ClassObserve,
	"backup_run":          ClassOperate,

	"restart_agent":         ClassOperate,
	"upload_backup":         ClassOperate,
	"delete_backup":         ClassOperate,
	"run_plugin_installers": ClassOperate,

	"ssl_probe_place": ClassOperate,
	"ssl_probe_clear": ClassOperate,

	"provision_certificate": ClassOperate,

	"apply_update": ClassOperate,

	// The managed-domain pair. Both operate, and for the same reason the SSH
	// they replace was never observe: preparing a domain mints a DKIM key, and
	// the notice writes four settings. A node whose policy accepts only observe
	// has to be able to trust that an observe primitive writes nothing.
	//
	// managed_domain_notice is the one to read carefully if this list is being
	// reviewed: it writes SETTINGS, and what makes that bounded rather than
	// total is that the four setting NAMES are compiled into the node-side
	// script and are not parameters. See its own file.
	"managed_domain_prepare": ClassOperate,
	"managed_domain_notice":  ClassOperate,

	// Two more compiled-names settings writers, the same shape as the notice
	// and pinned for the same reason: each writes SETTINGS, and what bounds it
	// is that the names live in the node-side script. clone_export_arm hands
	// the SOURCE of a clone one export key for the length of a provision;
	// fleet_enroll seeds a new site's fleet-service credentials. Both retire
	// an SSH session (specs/ssh_single_bootstrap.md).
	"clone_export_arm": ClassOperate,
	"fleet_enroll":     ClassOperate,

	// Bringing a backup back off the shelf, so there is something to restore
	// FROM. Both are operate, and that classification is the load-bearing part
	// of the pin: writing a file into a backup directory destroys nothing, so
	// these ship and work on nodes that cannot yet be asked to approve
	// anything. A future change that made either destructive would be trading a
	// working recovery path for a refusal, and should be argued for here.
	"download_backup": ClassOperate,
	"stage_chain":     ClassOperate,

	// The restore family. The destructive primitives, and the pin is doing more
	// work here than anywhere else in this list: it is the line a reviewer
	// reads to see that this release taught nine nodes to replace their own
	// database and their own project tree. They are DISPATCHABLE in this build,
	// and what stands between one of them and a replaced project tree is an
	// operator on that machine's own site opening a challenge sealed to that
	// machine's own backup recovery key. See Execute, which requires it, and
	// SettingsApproval, which is the only implementation of it.
	"restore_database": ClassDestructive,
	"restore_project":  ClassDestructive,
	"restore_chain":    ClassDestructive,

	// The first destructive primitive whose approving party is NOT the machine
	// running it: a host-posture agent removes a container site, and the
	// VICTIM approves on its own admin with its own recovery key
	// (specs/docker_host_agent.md). The Ceremony field is what carries that;
	// Execute still runs no destructive job without a gate answering.
	"decommission_site": ClassDestructive,
}

func TestVocabularyIsPinned(t *testing.T) {
	for _, name := range Names() {
		if _, pinned := pinnedVocabulary[name]; !pinned {
			t.Errorf("primitive %q is registered but not pinned in gate_test.go — "+
				"add it here deliberately, or it does not ship", name)
			continue
		}
		p, _ := Lookup(name)
		if want := pinnedVocabulary[name]; p.Class != want {
			t.Errorf("primitive %q is registered as class %q but pinned as %q — "+
				"a class change moves what nodes accept unattended", name, p.Class, want)
		}
	}
	for name := range pinnedVocabulary {
		if _, ok := Lookup(name); !ok {
			t.Errorf("primitive %q is pinned but not registered — it was removed without updating the pin", name)
		}
	}
}

// TestThereIsNoExecClass is the spec's central claim (A1) as an assertion: the
// class set is exactly three, and none of them is an escape hatch.
func TestThereIsNoExecClass(t *testing.T) {
	got := Classes()
	want := []Class{ClassDestructive, ClassObserve, ClassOperate} // sorted
	if len(got) != len(want) {
		t.Fatalf("class set is %v, want exactly %v — a fourth class is a change to the security model", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("class set is %v, want %v", got, want)
		}
	}
	for _, c := range got {
		lower := strings.ToLower(string(c))
		for _, banned := range []string{"exec", "command", "shell", "run"} {
			if strings.Contains(lower, banned) {
				t.Errorf("class %q reads like arbitrary execution — no such class may exist (A1)", c)
			}
		}
	}
}

// packageSourceFiles returns the non-test .go files of this package.
func packageSourceFiles(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading package directory: %v", err)
	}
	var files []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		files = append(files, name)
	}
	if len(files) < 3 {
		t.Fatalf("found only %d source files — the scanner is looking in the wrong place", len(files))
	}
	return files
}

// TestOnlyScriptFileStartsProcesses is the structural half of "no exec class".
// Absence is not enough: the vocabulary has to live somewhere a new escape
// hatch cannot be added quietly. Exactly one file here may start a process —
// the one that refuses to run anything it has not verified against the signed
// release manifest.
//
// os/exec is the obvious way and not the only one. A primitive could shell out
// through syscall.ForkExec or os.StartProcess without importing os/exec at all,
// so those are caught at the CALL site rather than the import site: syscall
// itself is legitimately imported here for statfs and for the policy file's
// ownership check, and banning the package would ban those too.
func TestOnlyScriptFileStartsProcesses(t *testing.T) {
	const allowed = "script.go"

	bannedImports := map[string]bool{
		"os/exec": true,
	}
	// package → member. Every way the standard library hands you a new process.
	bannedCalls := map[string]map[string]bool{
		"syscall": {"Exec": true, "ForkExec": true, "StartProcess": true, "CreateProcess": true},
		"os":      {"StartProcess": true},
		"exec":    {"Command": true, "CommandContext": true, "LookPath": true},
	}

	fset := token.NewFileSet()
	for _, file := range packageSourceFiles(t) {
		parsed, err := parser.ParseFile(fset, file, nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", file, err)
		}

		for _, imp := range parsed.Imports {
			path, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				continue
			}
			if bannedImports[path] && file != allowed {
				t.Errorf("%s imports %q — only %s may start a process, and only after manifest "+
					"verification. If this file genuinely needs to run something, it belongs behind a ScriptSpec.",
					file, path, allowed)
			}
		}

		if file == allowed {
			continue
		}
		ast.Inspect(parsed, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			if members, watched := bannedCalls[pkg.Name]; watched && members[sel.Sel.Name] {
				t.Errorf("%s:%d calls %s.%s — that starts a process. Only %s may do that, "+
					"and only after the target verifies against the signed release manifest.",
					file, fset.Position(sel.Pos()).Line, pkg.Name, sel.Sel.Name, allowed)
			}
			return true
		})
	}
}

// TestNoShellInvocation bans the one construction that turns a validated
// parameter back into a command: handing a string to a shell. Argv is passed to
// the kernel as a list, so a parameter containing a semicolon stays a
// parameter; "-c" is what would undo that.
//
// String literals only — a comment cannot execute anything, and scanning raw
// text would make the package's own documentation unwritable.
func TestNoShellInvocation(t *testing.T) {
	fset := token.NewFileSet()
	for _, file := range packageSourceFiles(t) {
		parsed, err := parser.ParseFile(fset, file, nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", file, err)
		}
		ast.Inspect(parsed, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			value, err := strconv.Unquote(lit.Value)
			if err != nil {
				return true
			}
			trimmed := strings.TrimSpace(value)
			if trimmed == "-c" || strings.Contains(value, "sh -c") {
				t.Errorf("%s:%d contains the string literal %q — a shell would re-parse validated "+
					"parameters as syntax. Use a fixed argv template instead.",
					file, fset.Position(lit.Pos()).Line, value)
			}
			if trimmed == "system" || strings.Contains(value, "eval ") {
				t.Errorf("%s:%d contains %q", file, fset.Position(lit.Pos()).Line, value)
			}
			return true
		})
	}
}

// TestStdinIsDataNotACommandChannel guards the widening that came with
// backup_run.
//
// Adding stdin to the script framework is the kind of change that quietly
// reintroduces an exec class: a process fed arbitrary bytes on stdin is an
// arbitrary program IF the thing reading them is an interpreter reading a
// program. Two properties keep it data, and both are asserted rather than
// assumed, because the next person to add a script primitive will not have read
// this comment.
func TestStdinIsDataNotACommandChannel(t *testing.T) {
	// 1. Every script primitive names a ScriptPath, and it is the program. The
	//    interpreter always receives a manifest-verified file as its argument,
	//    so whatever arrives on stdin is INPUT TO that verified script and can
	//    never be the thing executed. An interpreter with no script path would
	//    read its program from stdin — that is the shape being excluded.
	for _, name := range Names() {
		p, _ := Lookup(name)
		if p.Script == nil {
			continue
		}
		if p.Script.ScriptPath == "" {
			t.Errorf("primitive %q supplies stdin with no script path — the interpreter would "+
				"take its program from stdin, which is an exec class by another name", name)
		}
		if p.Script.Interpreter == "" {
			t.Errorf("primitive %q has no interpreter", name)
		}
		// 2. The interpreter is compiled in and absolute. A relative one would
		//    resolve through PATH on the node.
		if !strings.HasPrefix(p.Script.Interpreter, "/") {
			t.Errorf("primitive %q interpreter %q is not an absolute path", name, p.Script.Interpreter)
		}
	}
}

// TestStdinIsNeverLogged pins the reason stdin exists at all.
//
// run_backup.php takes its config on stdin because that config carries a storage
// credential and "anything in argv is visible to every process on the box". A
// log line is exactly as visible as ps, so a stdin value that reaches the log,
// the result, or an error message gives back precisely what the change bought.
func TestStdinIsNeverLogged(t *testing.T) {
	raw, err := os.ReadFile("script.go")
	if err != nil {
		t.Fatalf("reading script.go: %v", err)
	}
	source := string(raw)

	// The resolved value must not be placed anywhere that travels: the result
	// map, an error, or a log call. Asserted structurally — the only thing done
	// with it is handing it to the process.
	// Scope to the stdin block itself: from where it is resolved to where the
	// command's own output handling begins. A wider window catches the result
	// map that legitimately follows and says nothing about stdin.
	start := strings.Index(source, "if p.Script.StdinFrom != nil {")
	if start < 0 {
		t.Fatal("could not find where stdin is resolved")
	}
	end := strings.Index(source[start:], "var out bytes.Buffer")
	if end < 0 {
		t.Fatal("could not find the end of the stdin block")
	}
	window := source[start : start+end]
	for _, forbidden := range []string{"log.", "result[", "fmt.Errorf(\"%s\", stdin", "refusedf"} {
		if strings.Contains(window, forbidden) {
			t.Errorf("the resolved stdin value appears near %q — it must go to the process and "+
				"nowhere else, or the credential it carries is back in plain sight", forbidden)
		}
	}
}

// TestPrimitiveExecutionEnvIsExplicit pins the fields a primitive can reach.
// Widening it is how a collector would grow the ability to read arbitrary files
// or run arbitrary SQL, both of which §3.5.3 refuses outright.
func TestPrimitiveExecutionEnvIsExplicit(t *testing.T) {
	// ToolRoot and ToolManifest are pinned DELIBERATELY, and they widen nothing:
	// they are the same two capabilities SiteRoot and Manifest already are — a
	// tree to resolve a script path in, and the signed manifest that says
	// whether that file may be executed as root — for a machine whose tree is
	// the support bundle rather than a site. No primitive reads a file through
	// them that it could not read through their site-tree equivalents, and the
	// verification is the same code against the same compiled-in key.
	// DBName is pinned deliberately and widens nothing. It is a fact about this
	// machine's own identity read from this machine's own config, in the same
	// class as SiteRoot — not a new thing a primitive may touch. A primitive
	// holding DB can already run SQL against that database; one that does not
	// hold DB gains no ability by learning its name. It is here because the
	// control plane stores no column for it, so the alternative was letting the
	// plane name a node's database, which in the operation that drops a schema
	// is the plane naming somebody else's.
	want := map[string]bool{
		"SiteRoot": true, "WebRoot": true, "DB": true, "DBName": true,
		"Manifest": true, "ToolRoot": true, "ToolManifest": true,
		// How a destructive primitive gets authorized. This is the largest
		// single addition to the boundary the package has taken: it lets
		// Execute BLOCK, holding a claimed job open while a human at this
		// machine's own site decides. Pinned deliberately, and worth reading
		// the approval.go type comment before changing.
		"Approval": true,

		// The victim's ceremony for decommission_site: a host-posture agent
		// staging an approval on the site it would destroy, answered with the
		// VICTIM's recovery key. Set only on a siteless machine; the widening
		// is deliberate and documented in specs/docker_host_agent.md.
		"VictimCeremony": true,
	}

	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, "dispatch.go", nil, 0)
	if err != nil {
		t.Fatalf("parsing dispatch.go: %v", err)
	}
	found := map[string]bool{}
	ast.Inspect(parsed, func(n ast.Node) bool {
		ts, ok := n.(*ast.TypeSpec)
		if !ok || ts.Name.Name != "ExecEnv" {
			return true
		}
		st, ok := ts.Type.(*ast.StructType)
		if !ok {
			return true
		}
		for _, field := range st.Fields.List {
			for _, name := range field.Names {
				found[name.Name] = true
			}
		}
		return false
	})
	for name := range found {
		if !want[name] {
			t.Errorf("ExecEnv gained field %q — a primitive can now reach something it could not before. "+
				"That is a change to the read side of the promise boundary (§3.5); pin it here deliberately.", name)
		}
	}
	for name := range want {
		if !found[name] {
			t.Errorf("ExecEnv lost field %q", name)
		}
	}
}

func TestPackageLayoutIsFlat(t *testing.T) {
	// A subdirectory would be a second place primitives could live, and the
	// scanners above only read this one.
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() {
			t.Errorf("primitives/%s exists — the gate scanners only read the package's own directory, "+
				"so a primitive hidden in a subdirectory would be unpinned", filepath.Base(e.Name()))
		}
	}
}
