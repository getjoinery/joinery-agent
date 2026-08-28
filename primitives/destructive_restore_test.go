package primitives

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// What is true of all three restores, asserted once. The per-primitive files
// below check each one's own argv; this file checks the properties that make
// the family safe to have compiled in at all.

var restoreFamily = []string{"restore_database", "restore_project", "restore_chain"}

// restoreEnv builds a node with a real backup directory under a temp site root,
// optionally holding the named files.
func restoreEnv(t *testing.T, files ...string) *ExecEnv {
	t.Helper()
	root := t.TempDir()
	for _, dir := range []string{"backups", filepath.Join("backups", managerSubdir)} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, rel := range files {
		path := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return &ExecEnv{
		SiteRoot: root,
		WebRoot:  filepath.Join(root, "public_html"),
		// What this machine's own config says its database is called. The plane
		// has no column for it; see ExecEnv.DBName.
		DBName: "jeremytunnell",
	}
}

func restorePrimitive(t *testing.T, name string) Primitive {
	t.Helper()
	p, ok := Lookup(name)
	if !ok {
		t.Fatalf("%s should be registered", name)
	}
	return p
}

func TestEveryRestoreIsDestructive(t *testing.T) {
	// The class is not a label, it is what the compiled ceiling keys off. A
	// restore registered as operate would be dispatchable unattended on every
	// node in the fleet the moment it shipped.
	for _, name := range restoreFamily {
		if class := restorePrimitive(t, name).Class; class != ClassDestructive {
			t.Errorf("%s is class %q — a restore replaces data and must be %q", name, class, ClassDestructive)
		}
	}
}

func TestARestoreIsRefusedAtTheCeiling(t *testing.T) {
	// The resting state this round ships. Every node runs the shipped policy or
	// a policy file, and neither can accept this: the refusal is compiled in
	// above both, and it names the missing piece rather than saying "denied".
	for _, policy := range []*Policy{ShippedPolicy(), {Accept: []Class{ClassObserve, ClassOperate, ClassDestructive}, source: "a policy file that asks for everything"}} {
		for _, name := range restoreFamily {
			_, err := Execute(context.Background(), restoreEnv(t), policy, Request{
				JobID: 1, Primitive: name, Params: map[string]interface{}{},
			})
			if err == nil {
				t.Fatalf("%s ran unattended — the destructive ceiling is gone", name)
			}
			if !Refused(err) {
				t.Errorf("%s: a ceiling refusal must be a refusal, not a failure: %v", name, err)
			}
			if !strings.Contains(err.Error(), "approval verifier") {
				t.Errorf("%s: the refusal should name what is missing, got %q", name, err)
			}
		}
	}
}

func TestTheCeilingIsCheckedBeforeAnythingElse(t *testing.T) {
	// A destructive job is refused for BEING destructive, before its parameters
	// are looked at. Otherwise the refusal an operator sees depends on which
	// mistake they made, and a well-formed job would get further into the
	// machinery than a malformed one.
	_, err := Execute(context.Background(), restoreEnv(t), ShippedPolicy(), Request{
		JobID: 2, Primitive: "restore_project",
		Params: map[string]interface{}{"nonsense": strings.Repeat("x", 40)},
	})
	if err == nil || !strings.Contains(err.Error(), "approval verifier") {
		t.Fatalf("an undeclared key should not change the answer for a destructive job, got %v", err)
	}
}

func TestNoRestoreHasAParameterThatCouldCarryAKey(t *testing.T) {
	// A4's read side, enforced by the vocabulary rather than by a check. There
	// is no field for key material, so a job carrying some is refused by
	// Validate as an undeclared key before any restore code is reached.
	banned := []string{
		"key", "key_file", "keyfile", "key_path", "encryption_key",
		"recovery_key", "recovery_private_key", "recovery_public_key",
		"recovery_fpr", "private_key", "passphrase", "password", "secret",
	}
	for _, name := range restoreFamily {
		for _, spec := range restorePrimitive(t, name).Params {
			for _, bad := range banned {
				if spec.Name == bad {
					t.Errorf("%s declares %q — no key material may cross the wire", name, spec.Name)
				}
			}
		}
	}
}

func TestAJobCarryingKeyMaterialIsRefused(t *testing.T) {
	// The same property from the other side: the actual refusal a plane trying
	// to send a key would get. Checked at Validate, since the ceiling would
	// otherwise answer first.
	for _, name := range restoreFamily {
		p := restorePrimitive(t, name)
		for _, bad := range []string{"key_file", "encryption_key", "recovery_private_key"} {
			raw := map[string]interface{}{bad: "AAAAC3NzaC1lZDI1NTE5"}
			if _, err := Validate(p.Params, raw); err == nil {
				t.Errorf("%s accepted %q — key material must have nowhere to land", name, bad)
			} else if !strings.Contains(err.Error(), "undeclared key") {
				t.Errorf("%s: %q should be refused as undeclared, got %q", name, bad, err)
			}
		}
	}
}

func TestNoRestoreCanBeAskedToNameAPath(t *testing.T) {
	// Rule 1. Under SSH the plane composed the path and handed it to a root
	// process that drops a schema or extracts over a tree.
	for _, name := range []string{"restore_database", "restore_project"} {
		p := restorePrimitive(t, name)
		for _, bad := range []string{
			"/backups/site.sql.gz", "../../etc/shadow", "..", ".",
			".hidden.sql.gz", "sub/dir.tar.gz", "a.sql.gz\x00.png", "a b.sql.gz", "",
		} {
			raw := validRestoreParams(name)
			raw["file"] = bad
			if _, err := Validate(p.Params, raw); err == nil {
				t.Errorf("%s accepted file %q — that is a path", name, bad)
			}
		}
	}

	// The chain names no file at all; its one wire-supplied path component is
	// the chain id, which becomes a directory name.
	chain := restorePrimitive(t, "restore_chain")
	for _, bad := range []string{"../escape", "chain-1/../..", "/backups/chain-1", "chain-1;rm", "chain-.."} {
		raw := validRestoreParams("restore_chain")
		raw["chain_id"] = bad
		if _, err := Validate(chain.Params, raw); err == nil {
			t.Errorf("restore_chain accepted chain_id %q — it becomes a directory name", bad)
		}
	}
}

func TestEveryRestoreDeclaresItsOwnTimeout(t *testing.T) {
	// A restore inheriting the 5-minute default would be killed part-way
	// through, which for these three is the worst state each one has.
	for _, name := range restoreFamily {
		p := restorePrimitive(t, name)
		if p.Timeout <= DefaultTimeout {
			t.Errorf("%s declares %v, at or under the %v default — a restore is not five minutes' work",
				name, p.Timeout, DefaultTimeout)
		}
		if p.Timeout > MaxTimeout {
			t.Errorf("%s declares %v, over the %v ceiling", name, p.Timeout, MaxTimeout)
		}
	}
}

func TestEveryRestoreRunsAManifestVerifiedScript(t *testing.T) {
	// Not an embedded implementation: the thing that runs as root is a file on
	// the node's disk, checked against the signed release manifest first. And
	// none of them takes stdin — the scripts read argv, and the one thing that
	// would justify a stdin channel is a credential this vocabulary does not
	// carry.
	for _, name := range restoreFamily {
		p := restorePrimitive(t, name)
		if p.Script == nil {
			t.Fatalf("%s must invoke a shipped script, not embed the logic", name)
		}
		if !strings.HasPrefix(p.Script.ScriptPath, "maintenance_scripts/sysadmin_tools/restore_") {
			t.Errorf("%s runs %q, which is not the shipped restore engine", name, p.Script.ScriptPath)
		}
		if p.Script.StdinFrom != nil {
			t.Errorf("%s supplies stdin; these scripts read argv and carry no credential", name)
		}
		if p.Script.ArgsFrom == nil {
			t.Errorf("%s must compose argv node-side — a template can only emit what the wire sent", name)
		}
	}
}

func TestAMissingScriptTreeRefusesRatherThanRuns(t *testing.T) {
	// A machine with no site root and no support bundle has no tree to resolve
	// the script in, and no manifest to check it against.
	p := restorePrimitive(t, "restore_database")
	params, err := Validate(p.Params, validRestoreParams("restore_database"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runScriptPrimitive(context.Background(), &ExecEnv{}, p, params); err == nil || !Refused(err) {
		t.Fatalf("a machine with no tree must refuse, got %v", err)
	}
}

// validRestoreParams is one well-formed job per primitive, so every negative
// test above varies exactly one field of something that otherwise passes.
func validRestoreParams(name string) map[string]interface{} {
	switch name {
	case "restore_database":
		return map[string]interface{}{
			"db_name": "jeremytunnell", "file": "db_2026-08-27.sql.gz.enc", "profile": "manager",
		}
	case "restore_project":
		return map[string]interface{}{
			"project_name": "jeremytunnell", "file": "jeremytunnell_2026-08-27.tar.gz.enc",
			"profile": "manager", "force": true,
		}
	default:
		return map[string]interface{}{
			"project": "jeremytunnell", "chain_id": "chain-20260807_231507",
		}
	}
}
