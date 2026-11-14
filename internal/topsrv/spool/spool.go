// Package spool keeps payloads that could not be delivered on disk and
// replays them later, oldest first. A spool file is named
// <prefix><unix-ms>[...]<ext>, so lexical order within a prefix is the order
// the payloads were written.
package spool

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const tmpExt = ".tmp"

// Dir is one spool directory holding files with one extension. A Dir with an
// empty Path is a disabled spool: it lists, trims and replays nothing.
type Dir struct {
	Path string // created 0700 on the first Write
	Ext  string // including the dot: ".gz", ".json", ".ndjson.gz"
}

// Write stores body as <Path>/<name><Ext>. The body goes to a 0600 temp file
// first and is renamed into place, so a crash never leaves half a payload
// for Replay to send. The temp file is created exclusively under a random
// name, so nothing planted in the directory can redirect the write.
func (d Dir) Write(name string, body []byte) error {
	if err := os.MkdirAll(d.Path, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(d.Path, name+".*"+d.Ext+tmpExt) // 0600, O_EXCL
	if err != nil {
		return err
	}
	_, err = f.Write(body)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(f.Name(), filepath.Join(d.Path, name+d.Ext))
	}
	if err != nil {
		os.Remove(f.Name())
	}
	return err
}

// Files returns the paths of the spool files whose names start with prefix,
// oldest first. A missing directory has no files.
func (d Dir) Files(prefix string) []string {
	if d.Path == "" {
		return nil
	}
	entries, err := os.ReadDir(d.Path) // sorted by name
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		name := e.Name()
		if !e.IsDir() && strings.HasPrefix(name, prefix) && strings.HasSuffix(name, d.Ext) {
			out = append(out, filepath.Join(d.Path, name))
		}
	}
	return out
}

// Trim removes the oldest files with the prefix so that at most keep remain,
// and reports how many it removed.
func (d Dir) Trim(prefix string, keep int) int {
	files := d.Files(prefix)
	if len(files) <= keep {
		return 0
	}
	removed := 0
	for _, f := range files[:len(files)-keep] {
		if os.Remove(f) == nil {
			removed++
		}
	}
	return removed
}

// TrimBytes removes the oldest files until the rest fit in budget bytes, and
// reports how many it removed.
func (d Dir) TrimBytes(budget int64) int {
	files := d.Files("")
	sizes := make([]int64, len(files))
	var total int64
	for i, f := range files {
		if st, err := os.Stat(f); err == nil {
			sizes[i] = st.Size()
			total += sizes[i]
		}
	}
	removed := 0
	for i, f := range files {
		if total <= budget {
			break
		}
		if os.Remove(f) == nil {
			total -= sizes[i]
			removed++
		}
	}
	return removed
}

// Usage reports the number of spool files and their total size.
func (d Dir) Usage() (files int, size int64) {
	for _, f := range d.Files("") {
		if st, err := os.Stat(f); err == nil {
			files++
			size += st.Size()
		}
	}
	return files, size
}

// CleanupTmp removes temp files left by a crash between write and rename, and
// reports how many it removed.
func (d Dir) CleanupTmp() int {
	removed := 0
	for _, f := range (Dir{Path: d.Path, Ext: d.Ext + tmpExt}).Files("") {
		if os.Remove(f) == nil {
			removed++
		}
	}
	return removed
}

// Policy limits one Replay pass.
type Policy struct {
	MaxSends     int           // requests per pass; 0 = no limit
	MaxAge       time.Duration // older files are removed unsent; 0 = no limit
	MaxTransient int           // retryable failures that end the pass; 0 = the first one
}

// Result reports what one Replay pass did.
type Result struct {
	Sent     int         // delivered and removed
	Rejected []Rejection // failed with a non-retryable error and removed
	Expired  int         // older than MaxAge, removed unsent
	Dropped  int         // not a regular file of the agent's user, or unreadable; removed unsent
}

// Rejection is a spool file the backend refused for good.
type Rejection struct {
	Name string // file name without the extension
	Err  error
}

// Replay sends the spool files oldest first. A file that was delivered or
// rejected for good is removed; a retryable error keeps it for the next pass.
// send gets the file name without the extension.
func (d Dir) Replay(p Policy, send func(name string, body []byte) error) Result {
	maxTransient := max(p.MaxTransient, 1)
	var res Result
	transient := 0
	for _, path := range d.Files("") {
		if p.MaxSends > 0 && res.Sent+len(res.Rejected)+transient >= p.MaxSends {
			break
		}
		lst, err := ownFile(path)
		switch {
		case errors.Is(err, fs.ErrNotExist): // gone since the listing
			continue
		case err != nil:
			os.Remove(path)
			res.Dropped++
			continue
		case p.MaxAge > 0 && time.Since(lst.ModTime()) > p.MaxAge: // checked before reading
			os.Remove(path)
			res.Expired++
			continue
		}
		body, err := readSame(path, lst)
		if err != nil {
			os.Remove(path)
			res.Dropped++
			continue
		}

		name := strings.TrimSuffix(filepath.Base(path), d.Ext)
		err = send(name, body)
		if Retryable(err) {
			if transient++; transient >= maxTransient {
				break
			}
			continue
		}
		os.Remove(path)
		if err != nil {
			res.Rejected = append(res.Rejected, Rejection{Name: name, Err: err})
		} else {
			res.Sent++
		}
	}
	return res
}

// errNotOwn marks a spool entry Replay must not send: not a regular file of
// the agent's user, or swapped after the check.
var errNotOwn = errors.New("spool: not a regular file of the agent's user")

// ownFile returns the Lstat of a regular file owned by the agent's user.
// Anything else planted in the spool — a symlink to a secret, a file of
// another user — would be posted under the agent's token.
func ownFile(path string) (os.FileInfo, error) {
	lst, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !lst.Mode().IsRegular() {
		return nil, errNotOwn
	}
	if uid, ok := fileUID(lst); ok && uid != os.Getuid() {
		return nil, errNotOwn
	}
	return lst, nil
}

// readSame reads the file at path if it is still the one ownFile checked, so
// swapping the path between the two calls does not help.
func readSame(path string, lst os.FileInfo) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(lst, st) {
		return nil, errNotOwn
	}
	body := make([]byte, st.Size())
	if _, err := io.ReadFull(f, body); err != nil {
		return nil, err
	}
	return body, nil
}
