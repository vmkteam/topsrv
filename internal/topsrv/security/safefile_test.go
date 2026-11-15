package security

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadFile(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	require.NoError(t, os.WriteFile(file, []byte("12345"), 0o600))
	link := filepath.Join(dir, "link")
	require.NoError(t, os.Symlink(file, link))

	t.Run("regular file within the limit", func(t *testing.T) {
		b, err := readFile(file, 5)
		require.NoError(t, err)
		assert.Equal(t, "12345", string(b))
	})

	t.Run("a byte over the limit", func(t *testing.T) {
		_, err := readFile(file, 4)
		require.ErrorIs(t, err, errTooLarge)
		assert.Equal(t, ReasonBudgetExceeded, reasonOf(err))
	})

	t.Run("symlink is followed by default", func(t *testing.T) {
		b, err := readFile(link, 5)
		require.NoError(t, err)
		assert.Equal(t, "12345", string(b))
	})

	t.Run("symlink is refused with NoFollow", func(t *testing.T) {
		_, err := readFileNoFollow(link, 5)
		require.ErrorIs(t, err, errNotRegular)
	})

	t.Run("directory is refused", func(t *testing.T) {
		_, err := readFile(dir, 5)
		require.ErrorIs(t, err, errNotRegular)
	})

	t.Run("missing file", func(t *testing.T) {
		_, err := readFile(filepath.Join(dir, "missing"), 5)
		assert.Equal(t, ReasonNotFound, reasonOf(err))
	})

	t.Run("file swapped between stat and open", func(t *testing.T) {
		other := filepath.Join(dir, "other")
		require.NoError(t, os.WriteFile(other, []byte("other"), 0o600))
		swapped := filepath.Join(dir, "swapped")
		require.NoError(t, os.WriteFile(swapped, []byte("before"), 0o600))
		afterStat = func(string) { require.NoError(t, os.Rename(other, swapped)) }
		t.Cleanup(func() { afterStat = func(string) {} })

		_, err := readFile(swapped, 64)
		require.ErrorIs(t, err, errNotRegular)
	})
}
