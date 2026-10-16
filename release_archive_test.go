package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A release tree as the publisher builds one: core files listed and signed,
// the config template beside them unlisted, as PackageSignature excludes it.
func releaseFiles(version string) map[string]string {
	return map[string]string{
		"public_html/VERSION":                          version + "\n",
		"public_html/index.php":                        "<?php echo 'hi';\n",
		"maintenance_scripts/install_tools/install.sh": "#!/bin/bash\necho install\n",
	}
}

func releaseArchive(t *testing.T, priv ed25519.PrivateKey, version string, mangle func(map[string]string, *string), extra ...tarEntry) []byte {
	t.Helper()
	raw := signedBundle(t, priv, releaseFiles(version), mangle)
	if len(extra) == 0 {
		return raw
	}
	// Rebuild with the extra entries: the same signed manifest, more files.
	dir := t.TempDir()
	if err := unpackTree(bytes.NewReader(raw), dir, treeLimits{what: "fixture", entries: 100, bytes: 1 << 20}); err != nil {
		t.Fatal(err)
	}
	var entries []tarEntry
	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			rel, _ := filepath.Rel(dir, path)
			body, _ := os.ReadFile(path)
			entries = append(entries, tarEntry{name: filepath.ToSlash(rel), body: string(body)})
		}
		return nil
	})
	return makeBundleTar(t, append(entries, extra...))
}

func checkRelease(t *testing.T, pub ed25519.PublicKey, raw []byte, version string) error {
	t.Helper()
	c := releaseTreeChecks{releaseKeys: releaseKeysOf(pub)}
	_, err := c.unpackAndVerify(bytes.NewReader(raw), t.TempDir(), version)
	return err
}

func TestAReleaseThePublisherSignedVerifies(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	raw := releaseArchive(t, priv, "0.8.496", nil, tarEntry{name: "config/default_Globalvars_site.php", body: "<?php\n"})
	c := releaseTreeChecks{releaseKeys: releaseKeysOf(pub)}
	dir := t.TempDir()
	v, err := c.unpackAndVerify(bytes.NewReader(raw), dir, "0.8.496")
	if err != nil {
		t.Fatalf("a signed release, its config template beside it: %v", err)
	}
	if err := v.Verify(filepath.Join(dir, "maintenance_scripts/install_tools/install.sh")); err != nil {
		t.Fatalf("the verifier handed back checks the script the word runs: %v", err)
	}
}

func TestAReleaseIsRefusedUnlessItIsThePublishersAndTheOneAsked(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	for _, c := range []struct {
		name string
		raw  []byte
		want string
	}{
		{"signed by another key", releaseArchive(t, other, "0.8.496", nil), "does not verify"},
		{"a listed file changed", releaseArchive(t, priv, "0.8.496", func(f map[string]string, _ *string) {
			f["maintenance_scripts/install_tools/install.sh"] = "#!/bin/bash\nrm -rf /\n"
		}), "does not match"},
		{"a listed file missing", releaseArchive(t, priv, "0.8.496", func(f map[string]string, _ *string) {
			delete(f, "public_html/index.php")
		}), "does not match"},
		{"an unlisted script beside the listed ones", releaseArchive(t, priv, "0.8.496", nil,
			tarEntry{name: "maintenance_scripts/install_tools/extra.sh", body: "#!/bin/bash\n"}), "does not list"},
		{"a file under a path a manifest never lists", releaseArchive(t, priv, "0.8.496", nil,
			tarEntry{name: "public_html/cache/x.sh", body: "#!/bin/bash\n"}), "does not list"},
		{"a config file beside the template", releaseArchive(t, priv, "0.8.496", nil,
			tarEntry{name: "config/evil.php", body: "<?php\n"}), "does not list"},
		{"another version's tree", releaseArchive(t, priv, "0.8.495", nil), "says it is version"},
		{"a link in the tree", makeBundleTar(t, []tarEntry{{name: "x", typeflag: '2', linkname: "/etc/shadow"}}), "not a plain file"},
	} {
		err := checkRelease(t, pub, c.raw, "0.8.496")
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: refused with %q, got %v", c.name, c.want, err)
		}
	}
}

// The only file a fetched release may carry unlisted is the one a published
// core archive does: the plane's agent_release_tree_rule_test pins the list
// to the newest archive on its box (reviewer2 WP5 R6).
func TestOnlyThePublishedArchivesUnlistedFilePasses(t *testing.T) {
	for rel, want := range map[string]bool{
		"config/default_Globalvars_site.php": true,
		"config/evil.php":                    false,
		"vendor/autoload.php":                false,
		"public_html/cache/x.sh":             false,
		"maintenance_scripts/cache/x.sh":     false,
		"public_html/plugins/p/.gitignore":   false,
		"public_html/specs/a.md":             false,
		"maintenance_scripts/x.sh":           false,
	} {
		if got := releaseUnlisted(rel); got != want {
			t.Errorf("%s: unlisted %v, want %v", rel, got, want)
		}
	}
}

// statementSubject is PackageSignature::statementSubject: the value below is
// the plane's answer for the same body (php -r, 2026-10-14).
func TestStatementSubjectIsThePlanes(t *testing.T) {
	body := "# Joinery release manifest\n# Signed with the release key.\n" +
		strings.Repeat("a", 64) + "  public_html/VERSION\n" +
		strings.Repeat("b", 64) + "  public_html/RELEASE_STATEMENT\n" +
		strings.Repeat("c", 64) + "  maintenance_scripts/install_tools/install.sh\n" +
		strings.Repeat("d", 64) + "  public_html/agent_dist/RELEASE_STATEMENT\n"
	if got := statementSubject([]byte(body)); got != "e85be0544608afe4523d32fef10fb5fbefdf8ebdfe37fb7936a8ff9a5b9754e2" {
		t.Fatalf("statementSubject %s", got)
	}
}

// A machine that holds the release log's keys installs only a release whose
// statement records it; one with none in its tree is refused.
func TestAMachineHoldingTheLogsKeysWantsTheStatement(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	raw := releaseArchive(t, priv, "0.8.496", nil)
	held := newReleaseLogKeys()
	held.addStatement(make([]byte, 91))
	held.addLog("log.example", make([]byte, 32))
	c := releaseTreeChecks{releaseKeys: releaseKeysOf(pub), held: func() releaseLogKeys { return held }}
	if !held.holds() {
		t.Skip("the fixture keys are not accepted as held; the refusal is proven on a box instead")
	}
	_, err := c.unpackAndVerify(bytes.NewReader(raw), t.TempDir(), "0.8.496")
	if err == nil || !strings.Contains(err.Error(), "release statement") {
		t.Fatalf("no statement in the tree, keys held: refused, got %v", err)
	}
}

func TestAReleaseVersionIsOneShape(t *testing.T) {
	for _, v := range []string{"0.8.496", "1.0.0", "10.20.300"} {
		if !releaseVersionPattern.MatchString(v) {
			t.Errorf("%s is a version", v)
		}
	}
	for _, v := range []string{"", "0.8", "0.8.496-rc1", "../0.8.496", "0.8.496/x", "latest"} {
		if releaseVersionPattern.MatchString(v) {
			t.Errorf("%q is not a version", v)
		}
	}
}
