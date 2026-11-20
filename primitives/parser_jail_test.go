package primitives

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParserJailFacts(t *testing.T) {
	root := t.TempDir()
	parserJailFSRoot, parserJailOwnerUid = root, uint32(os.Getuid())
	defer func() { parserJailFSRoot, parserJailOwnerUid = "", 0 }()
	bin := root + parserJailLauncher
	os.MkdirAll(filepath.Dir(bin), 0o755)
	os.MkdirAll(root+"/etc", 0o755)
	want := func(state string, iface int, user bool) {
		t.Helper()
		got := parserJailFacts()
		if got["state"] != state || got["interface"] != iface || got["user"] != user {
			t.Fatalf("got %v, want state=%s interface=%d user=%v", got, state, iface, user)
		}
	}

	want("absent", 0, false)

	os.WriteFile(root+"/etc/passwd", []byte("root:x:0:0::/root:/bin/bash\njoinery-jailx:x:5:5::/:/bin/false\n"), 0o644)
	want("absent", 0, false) // a longer name is not the jail user
	os.WriteFile(root+"/etc/passwd", []byte("root:x:0:0::/root:/bin/bash\njoinery-jail:x:999:983::/nonexistent:/usr/sbin/nologin\n"), 0o644)
	want("absent", 0, true)

	// Present but not setuid: the site does not use it.
	os.WriteFile(bin, []byte("\x7fELF usage: joinery-jail JOINERY_JAIL_INTERFACE=2\n"), 0o755)
	os.Chmod(bin, 0o755)
	want("not_setuid", 0, true)

	// Setuid, but owned by someone else.
	if err := os.Chmod(bin, os.ModeSetuid|0o755); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Lstat(bin); fi.Mode()&os.ModeSetuid == 0 {
		t.Fatalf("setuid did not stick: %v", fi.Mode())
	}
	parserJailOwnerUid = uint32(os.Getuid()) + 1
	want("not_setuid", 0, true)
	parserJailOwnerUid = uint32(os.Getuid())

	want("fenced", 2, true)

	// The launcher before the fence carries no mark.
	os.WriteFile(bin, []byte("\x7fELF usage: joinery-jail [--timeout=S] -- command\n"), 0o755)
	os.Chmod(bin, os.ModeSetuid|0o755)
	want("deny_list", 0, true)

	// A mark past the first read chunk is still found.
	big := make([]byte, 3<<20)
	copy(big[len(big)-40:], "JOINERY_JAIL_INTERFACE=2\n")
	os.WriteFile(bin, big, 0o755)
	os.Chmod(bin, os.ModeSetuid|0o755)
	want("fenced", 2, true)

	// A link in place of the launcher is not followed.
	real := root + "/real-jail"
	os.Rename(bin, real)
	os.Symlink(real, bin)
	want("not_setuid", 0, true)
}
