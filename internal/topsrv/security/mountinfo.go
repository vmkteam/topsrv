package security

import (
	"bytes"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// errRemoteFS: the path is on a network or automount filesystem and was not
// touched.
var errRemoteFS = errors.New("on a remote or automount filesystem")

// errPseudoFS: a user path leads into proc, sysfs or the like, where a read
// may block or consume what others need (/proc/kmsg, trace_pipe).
var errPseudoFS = errors.New("on a pseudo filesystem")

// mountinfoLimit caps /proc/self/mountinfo; a k8s node has a few thousand
// lines of about 200 bytes.
const mountinfoLimit = 4 << 20

// mount is one line of /proc/self/mountinfo.
type mount struct {
	point  string
	fsType string
}

// mounts in /proc/self/mountinfo order: a later mount on the same point
// covers an earlier one.
type mounts []mount

// loadMounts reads <root>/proc/self/mountinfo.
func loadMounts(root string) (mounts, error) {
	b, err := readFile(root+"/proc/self/mountinfo", mountinfoLimit)
	if err != nil {
		return nil, err
	}
	return parseMountinfo(b)
}

// parseMountinfo parses the mountinfo format (proc(5)): mount point is field
// 5, the filesystem type follows the "-" separator after the optional fields.
// Errors carry the line number only.
func parseMountinfo(b []byte) (mounts, error) {
	var out mounts
	for i, line := range bytes.Split(b, []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		f := strings.Fields(string(line))
		sep := -1
		for j := 6; j < len(f); j++ {
			if f[j] == "-" {
				sep = j
				break
			}
		}
		if len(f) < 7 || sep < 0 || sep+1 >= len(f) {
			return nil, fmt.Errorf("mountinfo line %d: %w", i+1, errParse)
		}
		point, err := unescapeOctal(f[4])
		if err != nil {
			return nil, fmt.Errorf("mountinfo line %d: %w", i+1, errParse)
		}
		out = append(out, mount{point: point, fsType: f[sep+1]})
	}
	return out, nil
}

// unescapeOctal decodes the \NNN escapes the kernel uses for space, tab,
// newline and backslash in mount points.
func unescapeOctal(s string) (string, error) {
	if !strings.Contains(s, `\`) {
		return s, nil
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			b.WriteByte(s[i])
			continue
		}
		if i+3 >= len(s) {
			return "", errParse
		}
		n, err := strconv.ParseUint(s[i+1:i+4], 8, 8)
		if err != nil {
			return "", errParse
		}
		b.WriteByte(byte(n))
		i += 3
	}
	return b.String(), nil
}

// isRemote reports whether path lies on a network or automount filesystem:
// touching such a path may hang or mount it, so the caller must skip it
// before any syscall on the path.
func (m mounts) isRemote(path string) bool { return isRemoteFS(m.fsTypeOf(path)) }

// fsTypeOf is the filesystem type of the longest mount point that contains
// path; "" when no mount of the table does.
func (m mounts) fsTypeOf(path string) string {
	path = filepath.Clean(path)
	best, fsType := -1, ""
	for _, mt := range m {
		if !underMount(path, mt.point) || len(mt.point) < best {
			continue
		}
		best, fsType = len(mt.point), mt.fsType
	}
	return fsType
}

// riskyOnly keeps what the checks need: remote and pseudo mounts and the
// mounts under them, which may bring a path back to a local filesystem. A
// host has a few pseudo mounts and rarely a remote one, so a check is cheap.
func (m mounts) riskyOnly() mounts {
	var risky []string
	for _, mt := range m {
		if isRemoteFS(mt.fsType) || isPseudoFS(mt.fsType) {
			risky = append(risky, mt.point)
		}
	}
	var out mounts
	for _, mt := range m {
		if slices.ContainsFunc(risky, func(point string) bool { return underMount(mt.point, point) }) {
			out = append(out, mt)
		}
	}
	return out
}

// isPseudoFS: kernel filesystems whose files are not data — reading one may
// block, consume events or act (/proc/kmsg, tracefs trace_pipe). System
// paths are read there on purpose; a user path never leads there.
func isPseudoFS(fsType string) bool {
	switch fsType {
	case "proc", "sysfs", "debugfs", "tracefs", "securityfs", "configfs", "devtmpfs", "devpts", "cgroup", "cgroup2",
		"pstore", "bpf", "efivarfs", "fusectl", "mqueue", "hugetlbfs", "binfmt_misc", "rpc_pipefs", "nsfs", "selinuxfs", "nfsd":
		return true
	}
	return false
}

func underMount(path, point string) bool {
	if point == "/" {
		return true
	}
	return strings.HasPrefix(path, point) && (len(path) == len(point) || path[len(point)] == '/')
}

// localFUSE are FUSE drivers of local data: snap images where squashfs
// cannot be mounted (LXC, LXD), and lxcfs, which serves /proc of system
// containers.
var localFUSE = []string{"fuse.snapfuse", "fuse.squashfuse", "fuse.squashfuse_ll", "fuse.lxcfs"}

// isRemoteFS: network filesystems, FUSE (often network-backed: sshfs,
// s3fs) but the local drivers above, and autofs, which mounts on access.
func isRemoteFS(fsType string) bool {
	switch {
	case slices.Contains(localFUSE, fsType):
		return false
	case strings.HasPrefix(fsType, "nfs") && fsType != "nfsd", // nfsd is the local server's control fs
		fsType == "fuse", strings.HasPrefix(fsType, "fuse."):
		return true
	}
	switch fsType {
	case "cifs", "smb3", "smbfs", "autofs", "ceph", "glusterfs", "9p", "afs", "lustre", "gpfs":
		return true
	}
	return false
}
