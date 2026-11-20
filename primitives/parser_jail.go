package primitives

// The parser jail's launcher, as check_status reports it (specs/parser_jail.md,
// specs/sandboxed_php_plugins.md design 2): whether this node parses
// strangers' bytes inside the fence, without signing in to read the site's
// Vault Health page.
//
// Read the way the site itself decides (DocumentText::jailAvailable and
// ::jailFenced): the launcher at its one compiled path, a regular file owned
// by root with the setuid bit, and the interface mark in the binary. Nothing
// is run. The jail user is read from /etc/passwd by name.
//
//	fenced     installed, and the binary names JOINERY_JAIL_INTERFACE=2: the allowlist fence
//	deny_list  installed, but the binary does not carry that mark: the launcher before the fence
//	not_setuid a file is there but is not root's and setuid, so the site does not use it
//	absent     no launcher: the site parses as the web user (Vault Health's row is unmet)
//
// HOSTILE-CALLER REVIEW: check_status takes no parameters; the paths are
// compiled in. A link in place of the launcher is not followed (Lstat, and
// the open refuses a link). The binary is read to a size cap and only
// searched for one fixed string; nothing of it is returned.

import (
	"bufio"
	"bytes"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// Test seams: a directory standing in for /, and the owner the launcher must
// have (root; a test cannot make a root-owned file).
var (
	parserJailFSRoot   = ""
	parserJailOwnerUid = uint32(0)
)

const (
	parserJailLauncher = "/usr/local/sbin/joinery-jail"
	parserJailUser     = "joinery-jail"
	parserJailMark     = "JOINERY_JAIL_INTERFACE="
	parserJailMaxBytes = 64 << 20
)

// parserJailFacts returns check_status's parser_jail entry.
func parserJailFacts() map[string]interface{} {
	out := map[string]interface{}{
		"state":     "absent",
		"interface": 0,
		"user":      parserJailUserExists(parserJailFSRoot + "/etc/passwd"),
	}
	path := parserJailFSRoot + parserJailLauncher
	fi, err := os.Lstat(path)
	if err != nil {
		return out
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !fi.Mode().IsRegular() || !ok || st.Uid != parserJailOwnerUid || fi.Mode()&os.ModeSetuid == 0 {
		out["state"] = "not_setuid"
		return out
	}
	iface := parserJailInterface(path)
	out["interface"] = iface
	if iface >= 2 {
		out["state"] = "fenced"
	} else {
		out["state"] = "deny_list"
	}
	return out
}

// parserJailInterface is the number after the mark in the binary (its usage
// line carries it), 0 when there is none.
func parserJailInterface(path string) int {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return 0
	}
	defer f.Close()
	buf := make([]byte, 0, 1<<20)
	tmp := make([]byte, 1<<20)
	for len(buf) < parserJailMaxBytes {
		n, err := f.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if err != nil {
			break
		}
	}
	best := 0
	rest := buf
	for {
		i := bytes.Index(rest, []byte(parserJailMark))
		if i < 0 {
			return best
		}
		rest = rest[i+len(parserJailMark):]
		j := 0
		for j < len(rest) && j < 4 && rest[j] >= '0' && rest[j] <= '9' {
			j++
		}
		if n, err := strconv.Atoi(string(rest[:j])); err == nil && n > best {
			best = n
		}
	}
}

func parserJailUserExists(passwd string) bool {
	f, err := os.Open(passwd)
	if err != nil {
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if strings.HasPrefix(sc.Text(), parserJailUser+":") {
			return true
		}
	}
	return false
}
