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

// readRegular reads a regular file of at most limit bytes. It is opened
// non-blocking, so a FIFO in its place cannot hang the open, and checked to
// be a regular file again after the open.
func readRegular(path string, limit int64) ([]byte, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, errNotRegular
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if after, statErr := f.Stat(); statErr != nil || !os.SameFile(fi, after) {
		return nil, errNotRegular
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, errors.New("file exceeds the size limit")
	}
	return b, nil
}
