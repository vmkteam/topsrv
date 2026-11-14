package spool

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fill writes files named <name><Ext>, each holding its own name.
func fill(t *testing.T, d Dir, names ...string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(d.Path, 0o700))
	for _, n := range names {
		require.NoError(t, os.WriteFile(filepath.Join(d.Path, n+d.Ext), []byte(n), 0o600))
	}
}

// names returns base names of the spool files with the prefix, oldest first.
func names(d Dir, prefix string) []string {
	files := d.Files(prefix)
	out := make([]string, 0, len(files))
	for _, p := range files {
		out = append(out, filepath.Base(p))
	}
	return out
}

func TestDirWrite(t *testing.T) {
	d := Dir{Path: filepath.Join(t.TempDir(), "spool"), Ext: ".json"}

	require.NoError(t, d.Write("security-100", []byte(`{}`)))

	dirInfo, err := os.Stat(d.Path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), dirInfo.Mode().Perm(), "the directory is created 0700")

	path := filepath.Join(d.Path, "security-100.json")
	st, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), st.Mode().Perm())
	body, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, `{}`, string(body))

	tmps, err := filepath.Glob(filepath.Join(d.Path, "*.tmp"))
	require.NoError(t, err)
	assert.Empty(t, tmps, "the temp file is renamed into place")
}

// A link planted at the temp path the old Write used must not redirect the
// write: the agent may run as root.
func TestDirWriteDoesNotFollowPlantedTmp(t *testing.T) {
	d := Dir{Path: t.TempDir(), Ext: ".json"}
	secret := filepath.Join(t.TempDir(), "secret")
	require.NoError(t, os.WriteFile(secret, []byte("SENTINEL"), 0o600))
	require.NoError(t, os.Symlink(secret, filepath.Join(d.Path, "security-100.json.tmp")))

	require.NoError(t, d.Write("security-100", []byte(`{}`)))

	got, err := os.ReadFile(secret)
	require.NoError(t, err)
	assert.Equal(t, "SENTINEL", string(got), "the link target is left alone")
	path := filepath.Join(d.Path, "security-100.json")
	st, err := os.Lstat(path)
	require.NoError(t, err)
	assert.True(t, st.Mode().IsRegular(), "the spool file is a regular file, not the planted link")
}

func TestDirFiles(t *testing.T) {
	d := Dir{Path: t.TempDir(), Ext: ".gz"}
	fill(t, d, "300", "100", "200")
	require.NoError(t, os.WriteFile(filepath.Join(d.Path, "150.gz.tmp"), nil, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(d.Path, "120.json"), nil, 0o600))
	require.NoError(t, os.Mkdir(filepath.Join(d.Path, "inventory"), 0o700))

	assert.Equal(t, []string{"100.gz", "200.gz", "300.gz"}, names(d, ""), "oldest first, own extension only")
	assert.Equal(t, []string{"200.gz"}, names(d, "2"))
	assert.Empty(t, Dir{Path: filepath.Join(d.Path, "missing"), Ext: ".gz"}.Files(""))
}

func TestDirTrim(t *testing.T) {
	d := Dir{Path: t.TempDir(), Ext: ".json"}
	for i := range 25 {
		fill(t, d, fmt.Sprintf("packages-%03d", i))
	}
	fill(t, d, "security-000")

	assert.Equal(t, 5, d.Trim("packages-", 20))

	pkgs := names(d, "packages-")
	require.Len(t, pkgs, 20)
	assert.Equal(t, "packages-005.json", pkgs[0], "the oldest go first")
	assert.Len(t, names(d, "security-"), 1, "another prefix is untouched")
	assert.Zero(t, d.Trim("packages-", 20))
}

func TestDirTrimBytes(t *testing.T) {
	d := Dir{Path: t.TempDir(), Ext: ".ndjson.gz"}
	require.NoError(t, os.MkdirAll(d.Path, 0o700))
	for _, n := range []string{"100-a", "200-b", "300-c"} {
		require.NoError(t, os.WriteFile(filepath.Join(d.Path, n+d.Ext), make([]byte, 1024), 0o600))
	}

	assert.Equal(t, 1, d.TrimBytes(2048))
	assert.Equal(t, []string{"200-b.ndjson.gz", "300-c.ndjson.gz"}, names(d, ""))

	files, size := d.Usage()
	assert.Equal(t, 2, files)
	assert.Equal(t, int64(2048), size)
}

func TestDirCleanupTmp(t *testing.T) {
	d := Dir{Path: t.TempDir(), Ext: ".ndjson.gz"}
	fill(t, d, "100-a")
	require.NoError(t, os.WriteFile(filepath.Join(d.Path, "200-b.ndjson.gz.tmp"), []byte("half"), 0o600))

	assert.Equal(t, 1, d.CleanupTmp())
	assert.Equal(t, []string{"100-a.ndjson.gz"}, names(d, ""))
}

// recorder is a send func that answers from a per-name table (default nil)
// and records the names it was called with.
type recorder struct {
	answers map[string]error
	calls   []string
}

func (r *recorder) send(name string, body []byte) error {
	r.calls = append(r.calls, name)
	if name != string(body) {
		return fmt.Errorf("body %q does not match name %q", body, name)
	}
	return r.answers[name]
}

func TestReplay(t *testing.T) {
	retry := &StatusError{Code: http.StatusServiceUnavailable}
	reject := &StatusError{Code: http.StatusBadRequest}

	t.Run("delivered and rejected files are removed, oldest first", func(t *testing.T) {
		d := Dir{Path: t.TempDir(), Ext: ".json"}
		fill(t, d, "b-200", "a-100", "a-300")
		r := &recorder{answers: map[string]error{"a-300": reject}}

		res := d.Replay(Policy{}, r.send)

		assert.Equal(t, []string{"a-100", "a-300", "b-200"}, r.calls, "send gets the name without the extension")
		assert.Equal(t, Result{Sent: 2, Rejected: []Rejection{{Name: "a-300", Err: reject}}}, res)
		assert.Empty(t, d.Files(""))
	})

	t.Run("a retryable error keeps the file and ends the pass", func(t *testing.T) {
		d := Dir{Path: t.TempDir(), Ext: ".json"}
		fill(t, d, "100", "200", "300")
		r := &recorder{answers: map[string]error{"200": retry}}

		res := d.Replay(Policy{}, r.send)

		assert.Equal(t, []string{"100", "200"}, r.calls)
		assert.Equal(t, Result{Sent: 1}, res)
		assert.Equal(t, []string{"200.json", "300.json"}, names(d, ""))
	})

	t.Run("MaxTransient lets newer files past a stuck one", func(t *testing.T) {
		d := Dir{Path: t.TempDir(), Ext: ".json"}
		fill(t, d, "100", "200", "300", "400")
		r := &recorder{answers: map[string]error{"100": retry, "200": retry}}

		res := d.Replay(Policy{MaxTransient: 3}, r.send)

		assert.Equal(t, []string{"100", "200", "300", "400"}, r.calls)
		assert.Equal(t, Result{Sent: 2}, res)
		assert.Equal(t, []string{"100.json", "200.json"}, names(d, ""))
	})

	t.Run("MaxSends caps the requests of one pass", func(t *testing.T) {
		d := Dir{Path: t.TempDir(), Ext: ".json"}
		fill(t, d, "1", "2", "3", "4", "5", "6", "7")
		r := &recorder{}

		res := d.Replay(Policy{MaxSends: 5}, r.send)

		assert.Equal(t, []string{"1", "2", "3", "4", "5"}, r.calls)
		assert.Equal(t, Result{Sent: 5}, res)
		assert.Equal(t, []string{"6.json", "7.json"}, names(d, ""))
	})

	t.Run("files older than MaxAge are removed unsent and do not count as sends", func(t *testing.T) {
		d := Dir{Path: t.TempDir(), Ext: ".json"}
		fill(t, d, "100", "200", "300")
		old := time.Now().Add(-8 * 24 * time.Hour)
		require.NoError(t, os.Chtimes(filepath.Join(d.Path, "100.json"), old, old))
		r := &recorder{}

		res := d.Replay(Policy{MaxSends: 2, MaxAge: 7 * 24 * time.Hour}, r.send)

		assert.Equal(t, []string{"200", "300"}, r.calls)
		assert.Equal(t, Result{Sent: 2, Expired: 1}, res)
		assert.Empty(t, d.Files(""))
	})

	t.Run("files of another user are removed unsent", func(t *testing.T) {
		if os.Getuid() != 0 {
			t.Skip("chown to another user needs root")
		}
		d := Dir{Path: t.TempDir(), Ext: ".json"}
		fill(t, d, "100", "200")
		require.NoError(t, os.Chown(filepath.Join(d.Path, "100.json"), 65534, 65534)) // nobody
		r := &recorder{}

		res := d.Replay(Policy{}, r.send)

		assert.Equal(t, []string{"200"}, r.calls)
		assert.Equal(t, Result{Sent: 1, Dropped: 1}, res)
		assert.Empty(t, d.Files(""))
	})

	t.Run("symlinks are removed unsent and their target is left alone", func(t *testing.T) {
		d := Dir{Path: t.TempDir(), Ext: ".json"}
		fill(t, d, "200")
		secret := filepath.Join(t.TempDir(), "secret")
		require.NoError(t, os.WriteFile(secret, []byte("SENTINEL"), 0o600))
		require.NoError(t, os.Symlink(secret, filepath.Join(d.Path, "100.json")))
		r := &recorder{}

		res := d.Replay(Policy{}, r.send)

		assert.Equal(t, []string{"200"}, r.calls)
		assert.Equal(t, Result{Sent: 1, Dropped: 1}, res)
		assert.Empty(t, d.Files(""))
		assert.FileExists(t, secret)
	})
}

func TestRetryable(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"no error", nil, false},
		{"connection refused", &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}, true},
		{"timeout", context.DeadlineExceeded, true},
		{"plain error", errors.New("boom"), true},
		{"500", &StatusError{Code: http.StatusInternalServerError}, true},
		{"wrapped 503", fmt.Errorf("post: %w", &StatusError{Code: http.StatusServiceUnavailable}), true},
		{"408", &StatusError{Code: http.StatusRequestTimeout}, true},
		{"429", &StatusError{Code: http.StatusTooManyRequests}, true},
		{"401: token may be re-issued", &StatusError{Code: http.StatusUnauthorized}, true},
		{"403: token may be re-issued", &StatusError{Code: http.StatusForbidden}, true},
		{"400", &StatusError{Code: http.StatusBadRequest}, false},
		{"404", &StatusError{Code: http.StatusNotFound}, false},
		{"413", &StatusError{Code: http.StatusRequestEntityTooLarge}, false},
		{"422", &StatusError{Code: http.StatusUnprocessableEntity}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, Retryable(tc.err))
		})
	}
}

func TestStatusError(t *testing.T) {
	assert.Equal(t, "HTTP 500", (&StatusError{Code: 500}).Error(), "no body, no colon")
	assert.Equal(t, "HTTP 400: unknown kind", (&StatusError{Code: 400, Body: "unknown kind"}).Error())
}
