package primitives

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// Whether an upgrade is running on this site, asked of the kernel's lock table.
//
// upgrade.php holds SITE/uploads/.upgrade.lock (flock, LOCK_EX) for its whole
// run, and takes it with LOCK_NB: a run that finds it held refuses to start. So
// asking by taking the lock, even for a moment, can turn an upgrade away. The
// question is answered here by reading /proc/locks for a lock on the file's
// device and inode instead, which no upgrade can collide with.
//
// While one runs, the five deployment files are in flux: upgrade.php replaces
// itself first and the signed manifest changes only when the release is swapped
// in, minutes later. What they look like then is not a finding.

const procLocks = "/proc/locks"

// UpgradeLockPath is the lock upgrade.php holds while it runs.
func UpgradeLockPath(siteRoot string) string {
	return filepath.Join(siteRoot, "uploads", ".upgrade.lock")
}

// UpgradeRunning reports whether something holds this site's upgrade lock. A
// table that cannot be read is not known, and reads as no upgrade.
func UpgradeRunning(env *ExecEnv) bool {
	if env == nil || env.SiteRoot == "" {
		return false
	}
	held, known := lockHeld(UpgradeLockPath(env.SiteRoot))
	return known && held
}

// lockHeld reports whether the kernel lists a lock on path, and whether it could
// tell: no file is no lock; a lock table that cannot be read is not known.
func lockHeld(path string) (held bool, known bool) {
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return false, os.IsNotExist(err)
	}
	table, err := os.ReadFile(procLocks)
	if err != nil {
		return false, false
	}
	dev := uint64(st.Dev)
	return lockHeldIn(string(table), unix.Major(dev), unix.Minor(dev), st.Ino), true
}

// lockHeldIn reads a /proc/locks table for a granted lock on the inode named by
// major, minor and ino. Each line is "N: TYPE MODE ACCESS PID MAJ:MIN:INODE
// START END", the device numbers in hex; a line with "->" is a waiter, not a
// holder.
func lockHeldIn(table string, major, minor uint32, ino uint64) bool {
	for _, line := range strings.Split(table, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 || fields[1] == "->" {
			continue
		}
		parts := strings.Split(fields[5], ":")
		if len(parts) != 3 {
			continue
		}
		maj, err1 := strconv.ParseUint(parts[0], 16, 32)
		min, err2 := strconv.ParseUint(parts[1], 16, 32)
		in, err3 := strconv.ParseUint(parts[2], 10, 64)
		if err1 != nil || err2 != nil || err3 != nil {
			continue
		}
		if uint32(maj) == major && uint32(min) == minor && in == ino {
			return true
		}
	}
	return false
}
