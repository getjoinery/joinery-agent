package recipes

import (
	"os"
	"path/filepath"
	"testing"
)

// The outward copies live in a directory the web user owns. A link planted
// under one of the agent's names must never be followed: the write lands in a
// fresh regular file under that name, and the link's target is untouched
// (specs/shell_command_audit.md C1).
func TestOutwardWritesNeverFollowAPlantedLink(t *testing.T) {
	root := t.TempDir()
	site := filepath.Join(root, "site")
	if err := os.MkdirAll(filepath.Join(site, "cache", "recipes"), 0o755); err != nil {
		t.Fatal(err)
	}
	restore := OutwardDir
	OutwardDir = filepath.Join(site, "cache", "recipes")
	t.Cleanup(func() { OutwardDir = restore })

	target := filepath.Join(root, "precious")
	if err := os.WriteFile(target, []byte("keep\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"probe.jsonl", "probe.case.json", "probe.case.json.tmp"} {
		if err := os.Symlink(target, filepath.Join(OutwardDir, name)); err != nil {
			t.Fatal(err)
		}
	}

	d := openOutward()
	if d == nil {
		t.Fatal("the outward directory should open")
	}
	d.appendCapped("probe.jsonl", []byte("{\"a\":1}\n"), 0o644)
	d.writeWhole("probe.case.json", []byte("{\"case\":1}\n"), 0o644)
	d.close()

	got, err := os.ReadFile(target)
	if err != nil || string(got) != "keep\n" {
		t.Fatalf("the link's target must be untouched, got %q, %v", got, err)
	}
	// The append under a linked name is skipped: nothing of ours goes through a link.
	if fi, err := os.Lstat(filepath.Join(OutwardDir, "probe.jsonl")); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("the planted link under probe.jsonl is left alone, not written through: %v %v", fi, err)
	}
	// The whole-file write replaces the planted link with a regular file.
	fi, err := os.Lstat(filepath.Join(OutwardDir, "probe.case.json"))
	if err != nil || !fi.Mode().IsRegular() {
		t.Fatalf("probe.case.json should be a regular file now, got %v %v", fi, err)
	}
	raw, _ := os.ReadFile(filepath.Join(OutwardDir, "probe.case.json"))
	if string(raw) != "{\"case\":1}\n" {
		t.Fatalf("probe.case.json should hold the rendered case, got %q", raw)
	}
}

// A link where the recipes directory itself should be is not followed either.
func TestOutwardDirectoryThatIsALinkIsSkipped(t *testing.T) {
	root := t.TempDir()
	site := filepath.Join(root, "site")
	elsewhere := filepath.Join(root, "elsewhere")
	if err := os.MkdirAll(filepath.Join(site, "cache"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(elsewhere, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, filepath.Join(site, "cache", "recipes")); err != nil {
		t.Fatal(err)
	}
	restore := OutwardDir
	OutwardDir = filepath.Join(site, "cache", "recipes")
	t.Cleanup(func() { OutwardDir = restore })
	if d := openOutward(); d != nil {
		d.close()
		t.Fatal("a recipes directory that is a link must not open")
	}
	if entries, _ := os.ReadDir(elsewhere); len(entries) != 0 {
		t.Fatalf("nothing may be written where the link points, found %d entries", len(entries))
	}
}
