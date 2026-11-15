//go:build unix

package security

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
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
		want     error // nil: any error
	}{
		// The FIFO may get the inode of the removed file (ext4 reuses it), so
		// (dev, ino) alone does not tell; the type check after open does.
		"regular file swapped for a FIFO": {want: errNotRegular, swap: func(t *testing.T, path string) {
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
				if tc.want != nil {
					require.ErrorIs(t, err, tc.want)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("open blocked on the swapped FIFO")
			}
		})
	}
}

func TestOpenFileClearsNonblock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(path, []byte("ok"), 0o600))

	f, err := openFile(path, false)
	require.NoError(t, err)
	t.Cleanup(func() { f.Close() })

	flags, err := unix.FcntlInt(f.Fd(), unix.F_GETFL, 0)
	require.NoError(t, err)
	assert.Zero(t, flags&unix.O_NONBLOCK, "reads block again once the file is checked")
}

func TestReadDirSpecialFiles(t *testing.T) {
	t.Run("FIFO in place of a directory is refused without blocking", func(t *testing.T) {
		fifo := filepath.Join(t.TempDir(), "dir")
		require.NoError(t, syscall.Mkfifo(fifo, 0o600))

		done := make(chan error, 1)
		go func() {
			_, err := readDir(fifo, false)
			done <- err
		}()
		select {
		case err := <-done:
			require.Error(t, err)
			assert.Equal(t, ReasonNotRegular, reasonOf(err))
		case <-time.After(2 * time.Second):
			t.Fatal("listing a FIFO blocked")
		}
	})

	t.Run("a symlink to a directory: followed by default, refused with noFollow", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "target")
		require.NoError(t, os.Mkdir(target, 0o700))
		require.NoError(t, os.WriteFile(filepath.Join(target, "f"), nil, 0o600))
		link := filepath.Join(dir, "link")
		require.NoError(t, os.Symlink(target, link))

		entries, err := readDir(link, false)
		require.NoError(t, err)
		require.Len(t, entries, 1)

		_, err = readDir(link, true)
		require.Error(t, err)
		assert.Equal(t, ReasonNotRegular, reasonOf(err))
	})
}
