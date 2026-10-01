package primitives

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// site_census (specs/site_copy.md WP3): the node's own count of what it holds.
// What matters about its shape: it reads, the plane chooses nothing, and it
// answers on a dormant copy and a frozen source, where a copy is checked.

func TestSiteCensusIsAReadOnlyWordThePlaneCannotSteer(t *testing.T) {
	p := mustLookup(t, "site_census")
	if p.Class != ClassObserve {
		t.Fatalf("site_census reads; it is observe, not %q", p.Class)
	}
	if len(p.Params) != 0 {
		t.Fatalf("site_census declares %d parameter(s); it must declare none", len(p.Params))
	}
	if p.Script == nil || p.Script.Interpreter != "/usr/bin/php" ||
		p.Script.ScriptPath != "maintenance_scripts/sysadmin_tools/site_census.php" {
		t.Fatal("site_census runs the site's own shipped census script")
	}
	if len(p.Script.Args) != 0 || p.Script.ArgsFrom != nil || p.Script.StdinFrom != nil {
		t.Error("the census takes no arguments and no stdin")
	}
	if p.Script.Redact {
		t.Error("the census is not redacted: a masked digest compares equal to any other")
	}
	if owner := owningArtifact(p.Script.ScriptPath); owner != "" {
		t.Errorf("the census script resolved to artifact %q; it must verify against the site-root manifest", owner)
	}
	if p.Machine {
		t.Error("a machine with no site has nothing to count")
	}
	for _, key := range []string{"path", "root", "exclude", "database"} {
		if _, err := Validate(p.Params, map[string]interface{}{key: "x"}); err == nil {
			t.Errorf("a job carrying %q must be refused", key)
		}
	}
}

func TestSiteCensusRunsOnADormantCopyAndAFrozenSource(t *testing.T) {
	p := mustLookup(t, "site_census")
	for _, state := range []string{"quiet copy", "quiet switchover"} {
		env, _ := copyEnv(t, state, nil)
		if err := quietAllows(env, p); err != nil {
			t.Errorf("site_census must run under %s: %v", state, err)
		}
	}
}

func TestTheCENSUSLineReachesThePlane(t *testing.T) {
	requirePHP(t)
	p := mustLookup(t, "site_census")
	rel := p.Script.ScriptPath
	body := "<?php echo 'argc=' . ($argc - 1) . \"\\n\" . 'CENSUS={\"version\":1}' . \"\\n\";\n"

	root := t.TempDir()
	full := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(body))
	manifest := []byte(hex.EncodeToString(sum[:]) + "  " + rel + "\n")
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewSignedTreeVerifier(root, manifest, ed25519.Sign(priv, manifest), pub)
	if err != nil {
		t.Fatal(err)
	}

	env := &ExecEnv{SiteRoot: root, WebRoot: filepath.Join(root, "public_html"), Manifest: verifier}
	result, err := Execute(context.Background(), env, ShippedPolicy(), Request{JobID: 1, Primitive: "site_census"})
	if err != nil {
		t.Fatalf("a verified census script should execute: %v", err)
	}
	out := result["output"].(string)
	if !strings.Contains(out, "argc=0") || !strings.Contains(out, `CENSUS={"version":1}`) {
		t.Errorf("the census gets no arguments and its line reaches the result: %q", out)
	}
}
