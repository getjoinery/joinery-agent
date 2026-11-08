package primitives

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// openPlainFile opens path for reading as a regular file and nothing else:
// a link is not followed, a FIFO does not block, and a directory or a device is
// refused. It is for files under a directory the web user can write (the
// site's logs/, cache/), where a name the agent knows can be swapped for a link
// to any file root can read, or for a FIFO that would hold the job lock for
// good (specs/shell_command_audit.md C2). A path that is not there returns an
// error for which os.IsNotExist is true, as os.Open does.
func openPlainFile(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return nil, fmt.Errorf("%s is a link, which is not followed", path)
		}
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	f := os.NewFile(uintptr(fd), path)
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if !st.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("%s is not a regular file (%v), which is not read", path, st.Mode().Type())
	}
	// Non-blocking was for the open; reads of a regular file never block.
	if err := unix.SetNonblock(fd, false); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}
