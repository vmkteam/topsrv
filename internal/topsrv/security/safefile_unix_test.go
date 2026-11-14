//go:build unix

package security

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestReadFileSpecialFiles(t *testing.T) {
	t.Run("FIFO is refused without blocking", func(t *testing.T) {
		fifo := filepath.Join(t.TempDir(), "fifo")
		require.NoError(t, syscall.Mkfifo(fifo, 0o600))

		done := make(chan error, 1)
		go func() {
			_, err := readFile(fifo, 64)
			done <- err
		}()
		select {
		case err := <-done:
			require.ErrorIs(t, err, errNotRegular)
		case <-time.After(2 * time.Second):
			t.Fatal("reading a FIFO blocked")
		}
	})

	t.Run("device is refused", func(t *testing.T) {
		_, err := readFile("/dev/zero", 64)
		require.ErrorIs(t, err, errNotRegular)
	})
}

func TestReadFileSwappedForSpecialFile(t *testing.T) {
	cases := map[string]struct {
		noFollow bool
		swap     func(t *testing.T, path string)
	}{
		"regular file swapped for a FIFO": {swap: func(t *testing.T, path string) {
			require.NoError(t, os.Remove(path))
			require.NoError(t, syscall.Mkfifo(path, 0o600))
		}},
		"regular file swapped for a symlink, NoFollow": {noFollow: true, swap: func(t *testing.T, path string) {
			secret := filepath.Join(t.TempDir(), "secret")
			require.NoError(t, os.WriteFile(secret, []byte("SENTINEL"), 0o600))
			require.NoError(t, os.Remove(path))
			require.NoError(t, os.Symlink(secret, path))
		}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "file")
			require.NoError(t, os.WriteFile(path, []byte("ok"), 0o600))
			afterStat = func(p string) { tc.swap(t, p) }
			t.Cleanup(func() { afterStat = func(string) {} })

			done := make(chan error, 1)
			go func() {
				_, err := readLimited(path, 64, tc.noFollow)
				done <- err
			}()
			select {
			case err := <-done:
				require.Error(t, err, "the swapped file is never read")
			case <-time.After(2 * time.Second):
				t.Fatal("open blocked on the swapped FIFO")
			}
		})
	}
}
