package primitives

import (
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
)

// A site on a shared host is measured against its own disk allowance, as the
// management API's stats endpoint measures it (hosting_paid_launch B6).
func TestCheckStatusMeasuresASiteAgainstItsAllowance(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "config"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "uploads"), 0o755); err != nil {
		t.Fatal(err)
	}
	var fs syscall.Statfs_t
	if err := syscall.Statfs(filepath.Join(root, "uploads"), &fs); err != nil {
		t.Fatal(err)
	}
	total := fs.Blocks * uint64(fs.Bsize)
	used := total - fs.Bavail*uint64(fs.Bsize)

	write := func(v string) {
		if err := os.WriteFile(filepath.Join(root, "config", "disk_allowance"), []byte(v), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	base := func() map[string]interface{} {
		return map[string]interface{}{"disk_usage_percent": 7, "disk_total": "web root"}
	}

	// No file: the web root's figures stand.
	r := base()
	collectDiskAllowance(root, r)
	if r["disk_usage_percent"] != 7 {
		t.Fatalf("no allowance file changed the figure: %v", r)
	}

	// An allowance far smaller than the disk seen is a limit not in force.
	write(strconv.FormatUint(total/4, 10))
	r = base()
	collectDiskAllowance(root, r)
	if r["disk_usage_percent"] != 7 {
		t.Fatalf("a limit not in force changed the figure: %v", r)
	}

	// Garbage is no allowance.
	write("lots")
	r = base()
	collectDiskAllowance(root, r)
	if r["disk_usage_percent"] != 7 {
		t.Fatalf("an unreadable allowance changed the figure: %v", r)
	}

	// The disk seen is the allowance plus 10%: the figure is use out of the allowance.
	allowance := uint64(float64(total) / 1.1)
	write(strconv.FormatUint(allowance, 10) + "\n")
	r = base()
	collectDiskAllowance(root, r)
	want := int(((used * 100) + allowance/2) / allowance)
	if r["disk_usage_percent"] != want || r["disk_total"] != formatSize(allowance) {
		t.Fatalf("against the allowance: got %v, want %d%% of %s", r, want, formatSize(allowance))
	}
}
