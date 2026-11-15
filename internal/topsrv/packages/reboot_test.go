//go:build linux

package packages

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

// rebootRoot writes /var/run/reboot-required and its .pkgs under a temp
// root; an empty pkgs leaves .pkgs out.
func rebootRoot(t *testing.T, flag bool, pkgs string) string {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "var/run")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if flag {
		if err := os.WriteFile(filepath.Join(dir, "reboot-required"), []byte("*** System restart required ***\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if pkgs != "" {
		if err := os.WriteFile(filepath.Join(dir, "reboot-required.pkgs"), []byte(pkgs), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestDebianRebootRequired(t *testing.T) {
	t.Run("libc6 without a new kernel; repeated names come once, sorted", func(t *testing.T) {
		root := rebootRoot(t, true, "linux-base\nlibc6\nlinux-base\nlinux-image-6.8.0-149-generic\nlinux-base\n")

		pending, pkgs := debianRebootRequired(root)

		if !pending {
			t.Error("pending = false, want true")
		}
		want := []string{"libc6", "linux-base", "linux-image-6.8.0-149-generic"}
		if !slices.Equal(pkgs, want) {
			t.Errorf("pkgs = %q, want %q", pkgs, want)
		}
	})

	t.Run("no flag file: no reboot, a stale .pkgs is ignored", func(t *testing.T) {
		pending, pkgs := debianRebootRequired(rebootRoot(t, false, "libc6\n"))
		if pending || pkgs != nil {
			t.Errorf("got %v %q, want false and no packages", pending, pkgs)
		}
	})

	t.Run("flag without .pkgs", func(t *testing.T) {
		pending, pkgs := debianRebootRequired(rebootRoot(t, true, ""))
		if !pending || pkgs != nil {
			t.Errorf("got %v %q, want true and no packages", pending, pkgs)
		}
	})

	t.Run("a FIFO in place of .pkgs is not read", func(t *testing.T) {
		root := rebootRoot(t, true, "")
		if err := syscall.Mkfifo(filepath.Join(root, rebootRequiredPkgs), 0o600); err != nil {
			t.Fatal(err)
		}
		done := make(chan []string, 1)
		go func() {
			_, pkgs := debianRebootRequired(root)
			done <- pkgs
		}()
		select {
		case pkgs := <-done:
			if pkgs != nil {
				t.Errorf("pkgs = %q, want none", pkgs)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("reading a FIFO blocked")
		}
	})
}

func TestDebianRebootRequiredLargeFile(t *testing.T) {
	big := "libc6\n" + strings.Repeat("x", rebootPkgsLimit) + "\nsystemd\n"
	_, pkgs := debianRebootRequired(rebootRoot(t, true, big))
	if !slices.Equal(pkgs, []string{"libc6"}) {
		t.Errorf("got %q, want the names of the first %d bytes", pkgs, rebootPkgsLimit)
	}
}

func TestParseRebootPkgs(t *testing.T) {
	var many strings.Builder
	for i := range maxRebootPkgs + 10 {
		fmt.Fprintf(&many, "pkg%03d\n", i)
	}
	if got := parseRebootPkgs([]byte(many.String())); len(got) != maxRebootPkgs {
		t.Errorf("got %d names, want at most %d", len(got), maxRebootPkgs)
	}

	got := parseRebootPkgs([]byte("libc6\n\n  systemd  \nNot A Package\n" + strings.Repeat("a", maxRebootPkgName+1) + "\n$(reboot)\n"))
	if want := []string{"libc6", "systemd"}; !slices.Equal(got, want) {
		t.Errorf("got %q, want %q: odd lines are not sent", got, want)
	}
}
