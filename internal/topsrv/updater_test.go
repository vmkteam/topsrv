package topsrv

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeriveUpdateEndpoint(t *testing.T) {
	tests := []struct {
		push string
		want string
	}{
		{"https://push.topsrv.io/v1/write", "https://push.topsrv.io/v1/update"},
		{"http://localhost:8076/v1/write", "http://localhost:8076/v1/update"},
		{"https://example.com/api/v1/write", "https://example.com/v1/update"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, deriveUpdateEndpoint(tt.push))
	}
}

func TestFetchUpdateNoUpdate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Contains(t, r.URL.Query().Get("version"), "1.0.0")
		json.NewEncoder(w).Encode(UpdateResponse{Update: false})
	}))
	defer srv.Close()

	u := &Updater{
		endpoint: srv.URL,
		version:  "1.0.0",
		client:   srv.Client(),
	}

	resp, err := u.fetchUpdate(t.Context())
	require.NoError(t, err)
	assert.False(t, resp.Update)
}

func TestFetchUpdateAvailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))
		json.NewEncoder(w).Encode(UpdateResponse{
			Update:   true,
			Version:  "1.1.0",
			URL:      "https://example.com/topsrv.tar.gz",
			Checksum: "sha256:abc123",
			Channel:  "stable",
		})
	}))
	defer srv.Close()

	u := &Updater{
		endpoint: srv.URL,
		version:  "1.0.0",
		token:    "test-token",
		client:   srv.Client(),
	}

	resp, err := u.fetchUpdate(t.Context())
	require.NoError(t, err)
	assert.True(t, resp.Update)
	assert.Equal(t, "1.1.0", resp.Version)
	assert.Equal(t, "sha256:abc123", resp.Checksum)
}

func TestVerifyChecksum(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "test.bin")

	content := []byte("hello topsrv")
	require.NoError(t, os.WriteFile(path, content, 0o644))

	h := sha256.Sum256(content)
	validChecksum := "sha256:" + hex.EncodeToString(h[:])

	// Valid checksum.
	require.NoError(t, verifyChecksum(path, validChecksum))

	// Invalid checksum.
	require.Error(t, verifyChecksum(path, "sha256:0000000000000000000000000000000000000000000000000000000000000000"))

	// Bad format.
	assert.Error(t, verifyChecksum(path, "md5:abc"))
}

func TestExtractBinary(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a tar.gz with a fake "topsrv" binary.
	tarPath := filepath.Join(tmpDir, "test.tar.gz")
	createTestTarGz(t, tarPath, "topsrv", []byte("#!/bin/sh\necho ok"))

	destPath := filepath.Join(tmpDir, "topsrv-extracted")
	require.NoError(t, extractBinary(tarPath, destPath))

	data, err := os.ReadFile(destPath)
	require.NoError(t, err)
	assert.Equal(t, "#!/bin/sh\necho ok", string(data))

	// Verify file is executable.
	info, err := os.Stat(destPath)
	require.NoError(t, err)
	assert.NotEqual(t, 0, info.Mode()&0o111, "binary should be executable")
}

func TestExtractBinaryNotFound(t *testing.T) {
	tmpDir := t.TempDir()
	tarPath := filepath.Join(tmpDir, "test.tar.gz")
	createTestTarGz(t, tarPath, "other-binary", []byte("data"))

	destPath := filepath.Join(tmpDir, "topsrv")
	err := extractBinary(tarPath, destPath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestBackupAndTrim(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a fake binary.
	binPath := filepath.Join(tmpDir, "topsrv")
	require.NoError(t, os.WriteFile(binPath, []byte("binary-v1"), 0o755))

	u := &Updater{
		version:   "1.0.0",
		binPath:   binPath,
		backupDir: filepath.Join(tmpDir, ".topsrv-backup"),
	}

	require.NoError(t, u.backup())

	backupPath := filepath.Join(u.backupDir, "topsrv-1.0.0")
	data, err := os.ReadFile(backupPath)
	require.NoError(t, err)
	assert.Equal(t, "binary-v1", string(data))

	// Create 6 more backups to test trim.
	for i := 1; i <= 6; i++ {
		path := filepath.Join(u.backupDir, "topsrv-0.0."+string(rune('0'+i)))
		require.NoError(t, os.WriteFile(path, []byte("old"), 0o755))
	}
	u.trimBackups()

	entries, err := os.ReadDir(u.backupDir)
	require.NoError(t, err)
	assert.LessOrEqual(t, len(entries), updateMaxBackups)
}

func TestStateLoadSave(t *testing.T) {
	tmpDir := t.TempDir()
	u := &Updater{stateDir: tmpDir}

	now := time.Now().Truncate(time.Second)
	state := updateState{
		LastUpdate:      now,
		PreviousVersion: "1.0.0",
		CurrentVersion:  "1.1.0",
		RestartCount:    2,
	}

	u.saveState(state)

	loaded, err := u.loadState()
	require.NoError(t, err)
	assert.Equal(t, state.PreviousVersion, loaded.PreviousVersion)
	assert.Equal(t, state.CurrentVersion, loaded.CurrentVersion)
	assert.Equal(t, state.RestartCount, loaded.RestartCount)
}

func TestStateLoadMissing(t *testing.T) {
	u := &Updater{stateDir: t.TempDir()}
	_, err := u.loadState()
	assert.Error(t, err)
}

func TestCompareVersionedNames(t *testing.T) {
	tests := []struct {
		a, b string
		want int // -1, 0, 1
	}{
		{"topsrv-0.0.9", "topsrv-0.0.10", -1},
		{"topsrv-0.0.10", "topsrv-0.0.9", 1},
		{"topsrv-0.0.9", "topsrv-0.0.9", 0},
		{"topsrv-1.0.0", "topsrv-0.9.99", 1},
		{"topsrv-v0.0.9", "topsrv-v0.0.10", -1},
	}
	for _, tt := range tests {
		got := compareVersionedNames(tt.a, tt.b)
		switch {
		case tt.want < 0:
			assert.Negative(t, got, "%s vs %s", tt.a, tt.b)
		case tt.want > 0:
			assert.Positive(t, got, "%s vs %s", tt.a, tt.b)
		default:
			assert.Zero(t, got, "%s vs %s", tt.a, tt.b)
		}
	}
}

func TestTrimBackupsVersionOrder(t *testing.T) {
	tmpDir := t.TempDir()
	backupDir := filepath.Join(tmpDir, "backups")
	require.NoError(t, os.MkdirAll(backupDir, 0o755))

	// Create backups with versions that sort differently lexicographically vs semantically.
	versions := []string{"0.0.8", "0.0.9", "0.0.10", "0.0.11", "0.0.12", "0.0.13"}
	for _, v := range versions {
		require.NoError(t, os.WriteFile(filepath.Join(backupDir, "topsrv-"+v), []byte(v), 0o755))
	}

	u := &Updater{backupDir: backupDir}
	u.trimBackups()

	entries, err := os.ReadDir(backupDir)
	require.NoError(t, err)
	assert.Len(t, entries, updateMaxBackups)

	// The oldest (0.0.8) should be removed, newest (0.0.13) must remain.
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	assert.NotContains(t, names, "topsrv-0.0.8", "oldest version should be removed")
	assert.Contains(t, names, "topsrv-0.0.13", "newest version must remain")
	assert.Contains(t, names, "topsrv-0.0.12", "second newest must remain")
}

// createTestTarGz creates a tar.gz archive with a single file.
func createTestTarGz(t *testing.T, tarPath, name string, content []byte) {
	t.Helper()

	f, err := os.Create(tarPath)
	require.NoError(t, err)
	defer f.Close()

	gz := gzip.NewWriter(f)
	defer gz.Close()

	tw := tar.NewWriter(gz)
	defer tw.Close()

	require.NoError(t, tw.WriteHeader(&tar.Header{
		Name: name,
		Mode: 0o755,
		Size: int64(len(content)),
	}))
	_, err = tw.Write(content)
	require.NoError(t, err)
}
