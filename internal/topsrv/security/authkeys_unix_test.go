//go:build unix

package security

import (
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthorizedKeysSpecialFiles(t *testing.T) {
	// A FIFO in place of the file, and a symlink to a non-regular file
	// (/dev/zero in life, a FIFO here): refused, never opened for reading.
	sc := fixture(t, map[string]string{
		"proc/self/mountinfo":            authMountinfo,
		"home/alice/.ssh/":               "",
		"home/erin/.ssh/authorized_keys": "-> /dev/zero",
		"dev/":                           "",
	})
	require.NoError(t, syscall.Mkfifo(filepath.Join(sc.root, "home/alice/.ssh/authorized_keys"), 0o600))
	require.NoError(t, syscall.Mkfifo(filepath.Join(sc.root, "dev/zero"), 0o600))

	_, d := authKeysOf(t, sc, testSSHDResult())

	assert.Equal(t, keysIgnoredBySSHD, filesOf(t, d, "alice")["/home/alice/.ssh/authorized_keys"].Status)
	assert.Equal(t, keysIgnoredBySSHD, filesOf(t, d, "erin")["/home/erin/.ssh/authorized_keys"].Status)
}
