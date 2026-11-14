package security

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
)

var (
	errNotRegular = errors.New("not a regular file")
	errTooLarge   = errors.New("file exceeds the size limit")
)

// afterStat runs between the stat and the open; tests use it to swap the file.
var afterStat = func(string) {}

// openFile opens a regular file without the side effects of opening anything
// else: a FIFO would block the open and a device may act on it
// (/dev/watchdog). The file is stat-ed first, opened non-blocking and without
// becoming a controlling terminal, and its (dev, ino) checked again after the
// open, so swapping the path in between does not help. With noFollow a
// symlink at the last path component is refused.
func openFile(path string, noFollow bool) (*os.File, error) {
	stat, flags := os.Stat, os.O_RDONLY|openFlags
	if noFollow {
		stat, flags = os.Lstat, flags|oNoFollow
	}
	before, err := stat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() {
		return nil, &fs.PathError{Op: "open", Path: path, Err: errNotRegular}
	}
	afterStat(path)

	f, err := os.OpenFile(path, flags, 0)
	if err != nil {
		return nil, err
	}
	after, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if !os.SameFile(before, after) {
		f.Close()
		return nil, &fs.PathError{Op: "open", Path: path, Err: errNotRegular}
	}
	return f, nil
}

// readFile reads a regular file through openFile, following symlinks, and
// fails with errTooLarge past limit bytes.
func readFile(path string, limit int64) ([]byte, error) {
	return readLimited(path, limit, false)
}

// readFileNoFollow is readFile that refuses a symlink at the last component:
// for files under the control of other users.
func readFileNoFollow(path string, limit int64) ([]byte, error) {
	return readLimited(path, limit, true)
}

func readLimited(path string, limit int64, noFollow bool) ([]byte, error) {
	f, err := openFile(path, noFollow)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s: %w (%d bytes)", path, errTooLarge, limit)
	}
	return b, nil
}

// readHead reads up to n bytes from the start of a regular file: for files
// of which only the beginning matters.
func readHead(path string, n int64) ([]byte, error) {
	f, err := openFile(path, false)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, n))
}
