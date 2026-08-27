package primitives

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Resolution to the OWNING artifact, and the two rules that make per-artifact
// manifests safe: no cross-manifest fallback, and no manifest means unavailable.
// Both are the difference between verification and the appearance of it.

func artifactTree(t *testing.T) (root string, pub ed25519.PublicKey, priv ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	return t.TempDir(), pub, priv
}

// writeFile creates a file under root and returns its absolute path.
func writeFile(t *testing.T, root, rel, contents string) string {
	t.Helper()
	abs := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(abs), 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(abs, []byte(contents), 0755); err != nil {
		t.Fatalf("write: %v", err)
	}
	return abs
}

// signManifest writes a manifest covering the given site-root-relative paths
// into the artifact directory, signed with priv.
func signManifest(t *testing.T, root, artifactDir string, priv ed25519.PrivateKey, rels ...string) {
	t.Helper()
	body := "# test manifest\n"
	for _, rel := range rels {
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		sum := sha256.Sum256(data)
		body += hex.EncodeToString(sum[:]) + "  " + rel + "\n"
	}
	dir := filepath.Join(root, filepath.FromSlash(artifactDir))
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "RELEASE_MANIFEST"), []byte(body), 0644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	sig := ed25519.Sign(priv, []byte(body))
	if err := os.WriteFile(filepath.Join(dir, "RELEASE_MANIFEST.sig"),
		[]byte(base64.StdEncoding.EncodeToString(sig)+"\n"), 0644); err != nil {
		t.Fatalf("write signature: %v", err)
	}
}

func TestFilesResolveToTheArtifactThatShipsThem(t *testing.T) {
	root, pub, priv := artifactTree(t)

	core := writeFile(t, root, "maintenance_scripts/install_tools/install_agent.sh", "#!/bin/bash\ncore\n")
	plug := writeFile(t, root, "public_html/plugins/mailbox/provisioning/install_email.sh", "#!/bin/bash\nmail\n")

	signManifest(t, root, "", priv, "maintenance_scripts/install_tools/install_agent.sh")
	signManifest(t, root, "public_html/plugins/mailbox", priv, "public_html/plugins/mailbox/provisioning/install_email.sh")

	m := NewArtifactManifests(root, pub)

	if err := m.Verify(core); err != nil {
		t.Fatalf("a core script should verify against the core manifest: %v", err)
	}
	if err := m.Verify(plug); err != nil {
		t.Fatalf("a plugin script should verify against its own manifest: %v", err)
	}
}

func TestAPluginScriptIsNeverVerifiedByTheCoreManifest(t *testing.T) {
	// The rule that makes per-artifact manifests mean anything. Core's manifest
	// exists and is valid; the plugin has none. Falling back would "verify" a
	// file against a manifest that never listed it.
	root, pub, priv := artifactTree(t)

	writeFile(t, root, "maintenance_scripts/install_tools/install_agent.sh", "#!/bin/bash\ncore\n")
	plug := writeFile(t, root, "public_html/plugins/mailbox/provisioning/install_email.sh", "#!/bin/bash\nmail\n")

	// Core's manifest even lists the plugin file — the strongest version of the
	// trap. Resolution must still refuse, because core does not own it.
	signManifest(t, root, "", priv,
		"maintenance_scripts/install_tools/install_agent.sh",
		"public_html/plugins/mailbox/provisioning/install_email.sh")

	m := NewArtifactManifests(root, pub)

	err := m.Verify(plug)
	if err == nil {
		t.Fatal("a plugin file must not be verified by the core manifest")
	}
	if !strings.Contains(err.Error(), "mailbox") {
		t.Fatalf("the refusal should name the artifact that cannot be verified: %v", err)
	}
}

func TestAnArtifactWithNoManifestIsUnavailableNotPermitted(t *testing.T) {
	// Rider 2: older archives and third-party plugins yield a refusal, never a
	// warning and a run.
	root, pub, _ := artifactTree(t)
	plug := writeFile(t, root, "public_html/plugins/thirdparty/provisioning/setup.sh", "#!/bin/bash\n")

	m := NewArtifactManifests(root, pub)

	if err := m.Verify(plug); err == nil {
		t.Fatal("an artifact with no manifest must refuse, not permit")
	}
}

func TestAManifestSignedByTheWrongKeyIsRefused(t *testing.T) {
	// The signature is the whole trust chain: the key is compiled into the
	// agent, so a manifest anyone could write must be worth nothing.
	root, pub, _ := artifactTree(t)
	_, attacker, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	script := writeFile(t, root, "maintenance_scripts/install_tools/install_agent.sh", "#!/bin/bash\n")
	signManifest(t, root, "", attacker, "maintenance_scripts/install_tools/install_agent.sh")

	m := NewArtifactManifests(root, pub)

	if err := m.Verify(script); err == nil {
		t.Fatal("a manifest signed by another key must not be trusted")
	}
}

func TestATamperedScriptIsRefusedEvenWithAValidManifest(t *testing.T) {
	root, pub, priv := artifactTree(t)

	script := writeFile(t, root, "maintenance_scripts/install_tools/install_agent.sh", "#!/bin/bash\ngood\n")
	signManifest(t, root, "", priv, "maintenance_scripts/install_tools/install_agent.sh")

	m := NewArtifactManifests(root, pub)
	if err := m.Verify(script); err != nil {
		t.Fatalf("precondition: the untouched script should verify: %v", err)
	}

	// The web user rewrites it — the exact scenario this boundary exists for.
	if err := os.WriteFile(script, []byte("#!/bin/bash\nrm -rf /\n"), 0755); err != nil {
		t.Fatalf("tamper: %v", err)
	}

	if err := m.Verify(script); err == nil {
		t.Fatal("a script modified after release must not run as root")
	}
}

func TestAFileNotListedInItsOwnersManifestIsRefused(t *testing.T) {
	// A manifest that exists and verifies still says nothing about a file it
	// does not list — a script dropped into a shipped directory, for instance.
	root, pub, priv := artifactTree(t)

	writeFile(t, root, "maintenance_scripts/install_tools/install_agent.sh", "#!/bin/bash\n")
	planted := writeFile(t, root, "maintenance_scripts/install_tools/planted.sh", "#!/bin/bash\n")
	signManifest(t, root, "", priv, "maintenance_scripts/install_tools/install_agent.sh")

	m := NewArtifactManifests(root, pub)

	if err := m.Verify(planted); err == nil {
		t.Fatal("a file the manifest does not list must not run as root")
	}
}

func TestOwningArtifactResolution(t *testing.T) {
	cases := map[string]string{
		"public_html/plugins/mailbox/provisioning/x.sh": "public_html/plugins/mailbox",
		"public_html/theme/canvas/assets/x.sh":          "public_html/theme/canvas",
		"public_html/utils/upgrade.php":                 "",
		"maintenance_scripts/install_tools/x.sh":        "",
		"public_html/plugins":                           "",
		"VERSION":                                       "",
	}
	for rel, want := range cases {
		if got := owningArtifact(rel); got != want {
			t.Errorf("%s: owner %q, want %q", rel, got, want)
		}
	}
}

func TestAMissingManifestIsRetriedRatherThanRemembered(t *testing.T) {
	// An upgrade can deliver a manifest to an artifact that had none, and this
	// process may outlive that. Caching the failure would keep refusing scripts
	// the agent has since been given the means to verify.
	root, pub, priv := artifactTree(t)
	script := writeFile(t, root, "maintenance_scripts/install_tools/install_agent.sh", "#!/bin/bash\n")

	m := NewArtifactManifests(root, pub)
	if err := m.Verify(script); err == nil {
		t.Fatal("precondition: no manifest yet, so it should refuse")
	}

	signManifest(t, root, "", priv, "maintenance_scripts/install_tools/install_agent.sh")

	if err := m.Verify(script); err != nil {
		t.Fatalf("a manifest that arrived later must be picked up: %v", err)
	}
}
