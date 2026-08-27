package primitives

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// list_backups replaces a shelled glob-and-stat loop whose output the plane
// parsed by regex. These pin the shape the plane still consumes, and the two
// judgements the primitive makes: what counts as a backup, and what an absent
// backup directory means.

// listBackupsIn runs the primitive against a directory by temporarily pointing
// the compiled-in path at it. The path is a const precisely so a job cannot
// choose it; a test may, because a test is not a job.
func listBackupsIn(t *testing.T, dir string) []map[string]interface{} {
	t.Helper()
	result, err := runListBackupsFrom(context.Background(), dir)
	if err != nil {
		t.Fatalf("list_backups: %v", err)
	}
	files, ok := result["files"].([]map[string]interface{})
	if !ok {
		t.Fatalf("result should carry a files list, got %#v", result["files"])
	}
	return files
}

func seedBackup(t *testing.T, dir, name string, size int, age time.Duration) {
	t.Helper()
	abs := filepath.Join(dir, name)
	if err := os.WriteFile(abs, make([]byte, size), 0644); err != nil {
		t.Fatalf("seed %s: %v", name, err)
	}
	when := time.Now().Add(-age)
	if err := os.Chtimes(abs, when, when); err != nil {
		t.Fatalf("chtimes %s: %v", name, err)
	}
}

func TestEveryRecognisedBackupShapeIsListed(t *testing.T) {
	// All four suffixes, longest first on the platform side because '.sql.gz'
	// is a suffix of '.sql.gz.enc'. Missing one is how encrypted project
	// backups once became invisible to the listing and unrestorable from the UI
	// while everything reported success.
	dir := t.TempDir()
	for _, name := range []string{
		"joinery-2026-08-26.tar.gz",
		"joinery-2026-08-26.sql.gz",
		"joinery-2026-08-26.tar.gz.enc",
		"joinery-2026-08-26.sql.gz.enc",
	} {
		seedBackup(t, dir, name, 1024, time.Hour)
	}

	files := listBackupsIn(t, dir)
	if len(files) != 4 {
		t.Fatalf("every recognised shape should be listed; got %d", len(files))
	}
}

func TestFilesThatAreNotBackupsAreIgnored(t *testing.T) {
	dir := t.TempDir()
	seedBackup(t, dir, "joinery-2026-08-26.tar.gz", 1024, time.Hour)
	seedBackup(t, dir, "notes.txt", 10, time.Hour)
	seedBackup(t, dir, "archive.zip", 10, time.Hour)
	if err := os.Mkdir(filepath.Join(dir, "chain-20260825"), 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	files := listBackupsIn(t, dir)
	if len(files) != 1 {
		t.Fatalf("only backup artifacts should be listed; got %d", len(files))
	}
	if files[0]["filename"] != "joinery-2026-08-26.tar.gz" {
		t.Fatalf("wrong file listed: %v", files[0]["filename"])
	}
}

func TestNoBackupDirectoryIsAnEmptyListNotAFailure(t *testing.T) {
	// A node that has never been backed up is a legitimate state, and several
	// nodes in the fleet are deliberately in it. Reporting that as a job failure
	// would put a red mark on a dashboard for a node behaving correctly.
	files := listBackupsIn(t, filepath.Join(t.TempDir(), "nothing-here"))

	if len(files) != 0 {
		t.Fatalf("expected an empty list, got %d entries", len(files))
	}
}

func TestTheListingCarriesWhatThePlaneDisplays(t *testing.T) {
	// The plane consumes these keys directly — the primitive's result is
	// re-encoded into the same envelope the management API produces, so a key
	// missing here is a blank column rather than an error.
	dir := t.TempDir()
	seedBackup(t, dir, "joinery-2026-08-26.tar.gz", 2048, 2*time.Hour)

	files := listBackupsIn(t, dir)
	if len(files) != 1 {
		t.Fatalf("expected one file, got %d", len(files))
	}
	for _, key := range []string{"filename", "size", "size_bytes", "date", "mtime", "local_path", "location"} {
		if _, ok := files[0][key]; !ok {
			t.Errorf("the listing is missing %q, which the plane displays", key)
		}
	}
	if files[0]["location"] != "local" {
		t.Errorf("a node's own backups are local, got %v", files[0]["location"])
	}
	if files[0]["size_bytes"].(int64) != 2048 {
		t.Errorf("size_bytes should be the real size, got %v", files[0]["size_bytes"])
	}
	if got := files[0]["local_path"]; got != filepath.Join(dir, "joinery-2026-08-26.tar.gz") {
		t.Errorf("local_path should be usable to fetch the file, got %v", got)
	}
}

func TestNewestFirst(t *testing.T) {
	// Directory iteration order is not an order. Two identical nodes listing
	// their backups differently is the kind of thing that reads as data loss.
	dir := t.TempDir()
	seedBackup(t, dir, "old.tar.gz", 10, 48*time.Hour)
	seedBackup(t, dir, "newest.tar.gz", 10, time.Minute)
	seedBackup(t, dir, "middle.tar.gz", 10, 12*time.Hour)

	files := listBackupsIn(t, dir)
	if len(files) != 3 {
		t.Fatalf("expected three files, got %d", len(files))
	}
	want := []string{"newest.tar.gz", "middle.tar.gz", "old.tar.gz"}
	for i, name := range want {
		if files[i]["filename"] != name {
			t.Errorf("position %d: got %v, want %s", i, files[i]["filename"], name)
		}
	}
}

func TestListBackupsTakesNoParameters(t *testing.T) {
	// The directory is compiled in. A primitive that accepted one would let
	// whatever asked enumerate any path on the node — an observe class is still
	// a disclosure surface.
	p, ok := Lookup("list_backups")
	if !ok {
		t.Fatal("list_backups should be registered")
	}
	if len(p.Params) != 0 {
		t.Fatalf("list_backups must accept no parameters, declares %d", len(p.Params))
	}
	if p.Class != ClassObserve {
		t.Fatalf("list_backups must be observe, is %q", p.Class)
	}
}

func TestAnArchiveReportsWhetherItsKeyIsBesideIt(t *testing.T) {
	// The plane cannot see the node's disk, so this listing is the only thing
	// that can say whether an encrypted archive still has the file that opens
	// it. Without it, "this backup has no key anywhere" is a state nothing can
	// detect, and an operator finds out at restore time.
	dir := t.TempDir()
	for _, name := range []string{
		"paired-2026-08-01.tar.gz.enc",
		"paired-2026-08-01.tar.gz.enc.keys.json",
		"lonely-2026-08-02.sql.gz.enc",
		"plain-2026-08-03.sql.gz",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0600); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
	}

	result, err := runListBackupsFrom(context.Background(), dir)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	files, _ := result["files"].([]map[string]interface{})

	got := map[string]map[string]interface{}{}
	for _, f := range files {
		got[f["filename"].(string)] = f
	}

	// The envelope is not a backup and is never offered as one.
	if _, listed := got["paired-2026-08-01.tar.gz.enc.keys.json"]; listed {
		t.Error("an envelope must not be listed as a backup in its own right")
	}
	if len(got) != 3 {
		t.Errorf("expected the three archives, got %d", len(got))
	}

	if got["paired-2026-08-01.tar.gz.enc"]["has_envelope"] != true {
		t.Error("an archive with its key beside it should say so")
	}
	if got["lonely-2026-08-02.sql.gz.enc"]["has_envelope"] != false {
		t.Error("an encrypted archive with no key file should say so — this is the whole point")
	}
	// A plaintext archive has no key to lose. Reporting it as unpaired would be
	// a false alarm, and a listing that cries wolf is ignored when it is right.
	if got["plain-2026-08-03.sql.gz"]["encrypted"] != false ||
		got["plain-2026-08-03.sql.gz"]["has_envelope"] != false {
		t.Error("a plaintext archive is not encrypted and is never missing a key")
	}
}
