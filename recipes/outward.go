package recipes

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// The outward copies live under the site's cache/, which the web user owns, so
// every entry there can be swapped for a link before root writes. Nothing here
// goes by path once inside that tree: the directory is opened without
// following a link, each file is opened or made relative to that directory
// with O_NOFOLLOW, and a rewrite goes to a fresh O_EXCL temp file that
// renameat moves over the name (a rename replaces a planted link; it does not
// follow one). The two directories above OutwardDir are root's or the tree
// owner's, not the web user's, and are opened the ordinary way
// (specs/shell_command_audit.md C1).

// outwardDir is an open handle on OutwardDir, or nil when it cannot be had.
type outwardDir struct {
	fd int
}

// openOutward opens OutwardDir as a directory reached without following a link
// at either of its last two components, making the last one if it is missing.
// A nil result means the copy is skipped this time; the read-back ledger under
// LedgerDir is unaffected.
func openOutward() *outwardDir {
	if OutwardDir == "" {
		return nil
	}
	parent := filepath.Dir(OutwardDir) // cache/
	grand := filepath.Dir(parent)      // the site root, trusted
	leaf := filepath.Base(OutwardDir)  // recipes
	mid := filepath.Base(parent)       // cache
	if leaf == "" || leaf == "." || leaf == "/" || mid == "" || mid == "." || mid == "/" {
		return nil
	}
	gfd, err := unix.Open(grand, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil
	}
	defer unix.Close(gfd)
	pfd, err := openOrMakeDir(gfd, mid, 0o755)
	if err != nil {
		return nil
	}
	defer unix.Close(pfd)
	fd, err := openOrMakeDir(pfd, leaf, 0o755)
	if err != nil {
		return nil
	}
	return &outwardDir{fd: fd}
}

// openOrMakeDir opens name as a directory inside dirfd without following a
// link, making it first when it is not there.
func openOrMakeDir(dirfd int, name string, perm uint32) (int, error) {
	flags := unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
	fd, err := unix.Openat(dirfd, name, flags, 0)
	if errors.Is(err, unix.ENOENT) {
		if merr := unix.Mkdirat(dirfd, name, perm); merr != nil && !errors.Is(merr, unix.EEXIST) {
			return -1, merr
		}
		fd, err = unix.Openat(dirfd, name, flags, 0)
	}
	return fd, err
}

func (d *outwardDir) close() {
	if d != nil {
		unix.Close(d.fd)
	}
}

// openRegular opens name inside the directory with flags, never through a link,
// and only as a regular file. perm applies when O_CREAT makes it.
func (d *outwardDir) openRegular(name string, flags int, perm uint32) (*os.File, error) {
	// O_NONBLOCK for the open alone: a FIFO with no reader under one of our
	// names would otherwise hold this process for good (reviewer1 B6). A
	// regular file's reads and writes never block, so it is cleared after.
	fd, err := unix.Openat(d.fd, name, flags|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, perm)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), filepath.Join(OutwardDir, name))
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		f.Close()
		if err == nil {
			err = errors.New("not a regular file")
		}
		return nil, err
	}
	if err := unix.SetNonblock(fd, false); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// writeWhole replaces name with raw: a fresh temp file beside it (a planted
// entry under the temp name is unlinked first, never opened), then renameat.
func (d *outwardDir) writeWhole(name string, raw []byte, perm uint32) {
	tmp := name + ".tmp"
	_ = unix.Unlinkat(d.fd, tmp, 0)
	f, err := d.openRegular(tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, perm)
	if err != nil {
		return
	}
	_, werr := f.Write(raw)
	f.Close()
	if werr != nil {
		_ = unix.Unlinkat(d.fd, tmp, 0)
		return
	}
	if err := unix.Renameat(d.fd, tmp, d.fd, name); err != nil {
		_ = unix.Unlinkat(d.fd, tmp, 0)
	}
}

// appendCapped appends line to name, first trimming the file to the newest
// half of LedgerMaxBytes when the append would take it past the cap, as
// appendCapped does for the read-back ledger, through the directory handle.
func (d *outwardDir) appendCapped(name string, line []byte, perm uint32) {
	var st unix.Stat_t
	if err := unix.Fstatat(d.fd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err == nil {
		if st.Mode&unix.S_IFMT != unix.S_IFREG {
			return // a link or anything else under this name is left alone
		}
		if st.Size+int64(len(line)) > LedgerMaxBytes {
			d.trimToNewest(name, LedgerMaxBytes/2, perm)
		}
	}
	f, err := d.openRegular(name, unix.O_WRONLY|unix.O_APPEND|unix.O_CREAT, perm)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(line)
}

func (d *outwardDir) trimToNewest(name string, keep int, perm uint32) {
	f, err := d.openRegular(name, unix.O_RDONLY, 0)
	if err != nil {
		return
	}
	raw, err := readTail(f, keep)
	f.Close()
	if err != nil {
		return
	}
	// The first line is a partial one unless the whole file fit.
	if len(raw) == keep {
		if i := bytes.IndexByte(raw, '\n'); i >= 0 {
			raw = raw[i+1:]
		}
	}
	d.writeWhole(name, raw, perm)
}

// readTail reads the last keep bytes of f (all of it when it is shorter),
// whatever its size: the newest lines are at the end.
func readTail(f *os.File, keep int) ([]byte, error) {
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	size := st.Size()
	start := int64(0)
	if size > int64(keep) {
		start = size - int64(keep)
	}
	buf := make([]byte, size-start)
	n, err := f.ReadAt(buf, start)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return buf[:n], nil
}
