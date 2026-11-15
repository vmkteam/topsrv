package security

import (
	"path"
	"slices"
	"strings"
)

// systemd unit files, read without D-Bus.

// unitDirs in systemd's order of precedence.
var unitDirs = []string{"/etc/systemd/system", "/run/systemd/system", "/usr/local/lib/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system"}

// maskDirs are where a unit is masked: a mask in /usr is a packaging bug.
var maskDirs = []string{"/etc/systemd/system", "/run/systemd/system"}

// unitLines returns the lines of the first unit file found in unitDirs and
// of its drop-ins in /etc/systemd/system/<unit>.d, in order; nil without a
// unit file.
func unitLines(sc *scanCtx, unit string) []string {
	var out []string
	for _, dir := range unitDirs {
		if b, err := sc.read(dir+"/"+unit, smallFileLimit); err == nil {
			out = strings.Split(string(b), "\n")
			break
		}
	}
	if out == nil {
		return nil
	}
	for _, dir := range slices.Backward(unitDirs) { // the lowest precedence first: /etc is read last and wins
		dropins, _ := sc.readDir(dir + "/" + unit + ".d")
		for _, e := range dropins {
			if strings.HasSuffix(e.Name(), ".conf") {
				if b, err := sc.read(dir+"/"+unit+".d/"+e.Name(), smallFileLimit); err == nil {
					out = append(out, strings.Split(string(b), "\n")...)
				}
			}
		}
	}
	return out
}

// unitAlias: the unit file is a link to a unit of another name, as
// systemctl's "alias" state.
func unitAlias(sc *scanCtx, unit string) bool {
	target, err := sc.readlink(unit)
	return err == nil && target != "/dev/null" && path.Base(target) != path.Base(unit)
}

func unitMasked(sc *scanCtx, path string) bool {
	if target, err := sc.readlink(path); err == nil {
		return target == "/dev/null"
	}
	fi, err := sc.stat(path)
	return err == nil && fi.Mode().IsRegular() && fi.Size() == 0
}
