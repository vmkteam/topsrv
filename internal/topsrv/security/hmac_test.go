package security

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTokenKey(t *testing.T) {
	t.Run("created once with 0600, then reused", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "state")

		k, created, err := loadOrCreateKey(dir)
		require.NoError(t, err)
		assert.Regexp(t, `^[0-9a-f]{8}$`, k.id)
		assert.Equal(t, keyMissing, created)

		st, err := os.Stat(filepath.Join(dir, keyFile))
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), st.Mode().Perm())
		assert.EqualValues(t, keySize, st.Size())

		again, created, err := loadOrCreateKey(dir)
		require.NoError(t, err)
		assert.Empty(t, created, "loaded, not created")
		assert.Equal(t, k.id, again.id)
		assert.Equal(t, k.token("alice", "shadow"), again.token("alice", "shadow"))
	})

	t.Run("a key of the wrong size is replaced", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, keyFile), []byte("short"), 0o600))

		k, created, err := loadOrCreateKey(dir)
		require.NoError(t, err)
		assert.Equal(t, keyInvalid, created)
		b, err := os.ReadFile(filepath.Join(dir, keyFile))
		require.NoError(t, err)
		assert.Len(t, b, keySize)
		assert.Equal(t, keyID(b), k.id)
	})

	t.Run("a symlink in place of the key is replaced, its target untouched", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(t.TempDir(), "target")
		require.NoError(t, os.WriteFile(target, make([]byte, keySize), 0o600))
		require.NoError(t, os.Symlink(target, filepath.Join(dir, keyFile)))

		k, created, err := loadOrCreateKey(dir)
		require.NoError(t, err)
		assert.Equal(t, keyInvalid, created)
		assert.NotEqual(t, keyID(make([]byte, keySize)), k.id, "the link target is not used as the key")
		st, err := os.Lstat(filepath.Join(dir, keyFile))
		require.NoError(t, err)
		assert.True(t, st.Mode().IsRegular())
		b, err := os.ReadFile(target)
		require.NoError(t, err)
		assert.Equal(t, make([]byte, keySize), b)
	})

	t.Run("an existing key that cannot be read now is kept", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root reads a 0000 file")
		}
		dir := t.TempDir()
		path := filepath.Join(dir, keyFile)
		require.NoError(t, os.WriteFile(path, make([]byte, keySize), 0))

		_, _, err := loadOrCreateKey(dir)

		require.ErrorIs(t, err, fs.ErrPermission)
		require.NoError(t, os.Chmod(path, 0o600))
		b, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.Equal(t, make([]byte, keySize), b, "not overwritten")
	})

	t.Run("dry-run uses an ephemeral key and writes nothing", func(t *testing.T) {
		dir := t.TempDir()

		k := existingOrEphemeralKey(dir)

		assert.Equal(t, ephemeralKeyID, k.id)
		assert.NoFileExists(t, filepath.Join(dir, keyFile))
	})

	t.Run("dry-run uses the existing key", func(t *testing.T) {
		dir := t.TempDir()
		k, _, err := loadOrCreateKey(dir)
		require.NoError(t, err)

		assert.Equal(t, k.id, existingOrEphemeralKey(dir).id)
	})

	t.Run("a key others can read is replaced with a private one", func(t *testing.T) {
		for _, mode := range []os.FileMode{0o644, 0o640, 0o604, 0o660} {
			t.Run(mode.String(), func(t *testing.T) {
				dir := t.TempDir()
				path := filepath.Join(dir, keyFile)
				old := make([]byte, keySize)
				require.NoError(t, os.WriteFile(path, old, 0o600))
				require.NoError(t, os.Chmod(path, mode))

				k, created, err := loadOrCreateKey(dir)

				require.NoError(t, err)
				assert.Equal(t, keyUntrusted, created)
				assert.NotEqual(t, keyID(old), k.id, "a key others know is not used")
				st, err := os.Stat(path)
				require.NoError(t, err)
				assert.Equal(t, os.FileMode(0o600), st.Mode().Perm())
				b, err := os.ReadFile(path)
				require.NoError(t, err)
				assert.Equal(t, keyID(b), k.id)
			})
		}
	})

	t.Run("a key owned by another user is replaced", func(t *testing.T) {
		if os.Geteuid() != 0 {
			t.Skip("chown needs root")
		}
		dir := t.TempDir()
		path := filepath.Join(dir, keyFile)
		old := make([]byte, keySize)
		require.NoError(t, os.WriteFile(path, old, 0o600))
		require.NoError(t, os.Chown(path, 65534, 65534))

		k, created, err := loadOrCreateKey(dir)

		require.NoError(t, err)
		assert.Equal(t, keyUntrusted, created)
		assert.NotEqual(t, keyID(old), k.id)
	})

	t.Run("dry-run does not use a key others can read, and leaves it", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, keyFile)
		old := make([]byte, keySize)
		require.NoError(t, os.WriteFile(path, old, 0o600))
		require.NoError(t, os.Chmod(path, 0o644))

		k := existingOrEphemeralKey(dir)

		assert.Equal(t, ephemeralKeyID, k.id)
		b, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.Equal(t, old, b, "dry-run writes nothing")
	})
}

func TestToken(t *testing.T) {
	k := tokenKey{secret: make([]byte, keySize), id: "test"}

	tok := k.token("alice", "shadow")
	assert.Regexp(t, `^[0-9a-f]{16}$`, tok)
	assert.Equal(t, tok, k.token("alice", "shadow"))
	assert.NotEqual(t, tok, k.token("bob", "shadow"))
	assert.NotEqual(t, tok, k.token("alice", "gshadow"))
	assert.NotEqual(t, k.token("ab", "c"), k.token("a", "bc"), "user and field are separated")
}

func TestRandomKey(t *testing.T) {
	a, b := randomKey(), randomKey()
	assert.NotEqual(t, a.id, b.id, "each run gets its own id")
	assert.Equal(t, keyID(a.secret), a.id)
}
