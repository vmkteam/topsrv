//go:build linux

package packages

import (
	"errors"
	"io"
	"maps"
	"os"
	"regexp"
	"slices"
	"strings"
	"syscall"
)

// Debian and Ubuntu mark a pending reboot with these files: update-notifier
// and the postinst scripts of libc6, systemd, linux-base, microcode and the
// kernel write them. A reboot for libc6 alone has no newer kernel to show.
const (
	rebootRequiredFile = "/var/run/reboot-required"
	rebootRequiredPkgs = "/var/run/reboot-required.pkgs"
	rebootPkgsLimit    = 64 << 10 // one name per update: a host up for a year repeats them
	maxRebootPkgs      = 64
	maxRebootPkgName   = 64
)

// rebootFilesRoot is where /var/run is read from: "" in production, a
// fixture in tests.
var rebootFilesRoot = ""

// debianPkgName is the shape of a Debian package name; anything else in the
// file is not sent.
var debianPkgName = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]+$`)

// debianRebootRequired reports whether a reboot is pending and, if so, the
// packages that asked for it: unique names, sorted, at most maxRebootPkgs.
func debianRebootRequired(root string) (pending bool, pkgs []string) {
	if _, err := os.Stat(root + rebootRequiredFile); err != nil {
		return false, nil
	}
	b, err := readRegular(root+rebootRequiredPkgs, rebootPkgsLimit)
	if err != nil {
		return true, nil
	}
	return true, parseRebootPkgs(b)
}

func parseRebootPkgs(b []byte) []string {
	seen := map[string]bool{}
	for line := range strings.SplitSeq(string(b), "\n") {
		name := strings.TrimSpace(line)
		if len(name) <= maxRebootPkgName && debianPkgName.MatchString(name) {
			seen[name] = true
		}
	}
	out := slices.Sorted(maps.Keys(seen))
	return out[:min(len(out), maxRebootPkgs)]
}

var errNotRegular = errors.New("not a regular file")

// readRegular reads up to limit bytes of a regular file. It is opened
// non-blocking and without becoming a controlling terminal, so a FIFO in its
// place cannot hang the open, and checked to be a regular file again after
// the open. (A copy of security's safefile, to be shared.)
func readRegular(path string, limit int64) ([]byte, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, errNotRegular
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOCTTY, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	// The same inode may go to a FIFO put in place of a removed file: the type
	// is checked again on what was opened.
	if after, statErr := f.Stat(); statErr != nil || !os.SameFile(fi, after) || !after.Mode().IsRegular() {
		return nil, errNotRegular
	}
	return io.ReadAll(io.LimitReader(f, limit)) // a longer file: its first names
}
