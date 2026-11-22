package topsrv

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

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

// TestCheckRollback_GracefulSkipsIncrement is the regression test for the
// "ручные рестарты считаются как crash" bug. SIGTERM-driven shutdowns mark
// the state graceful so the next start does not bump the counter.
func TestCheckRollback_GracefulSkipsIncrement(t *testing.T) {
	u := &Updater{stateDir: t.TempDir()}
	u.saveState(updateState{
		LastUpdate:   time.Now(),
		RestartCount: 2,
		Graceful:     true,
	})

	u.checkRollback()

	got, err := u.loadState()
	require.NoError(t, err)
	assert.Equal(t, 2, got.RestartCount, "graceful exit must not bump RestartCount")
	assert.False(t, got.Graceful, "flag is consumed so a later real crash counts")
}

func TestCheckRollback_CrashWithinWindowIncrements(t *testing.T) {
	u := &Updater{stateDir: t.TempDir()}
	u.saveState(updateState{
		LastUpdate:   time.Now(),
		RestartCount: 1,
	})

	u.checkRollback()

	got, err := u.loadState()
	require.NoError(t, err)
	assert.Equal(t, 2, got.RestartCount)
}

func TestCheckRollback_OutsideWindowResets(t *testing.T) {
	u := &Updater{stateDir: t.TempDir()}
	u.saveState(updateState{
		LastUpdate:      time.Now().Add(-2 * updateCrashWindow),
		PreviousVersion: "1.0.0",
		RestartCount:    2,
		Graceful:        true,
	})

	u.checkRollback()

	got, err := u.loadState()
	require.NoError(t, err)
	assert.Equal(t, 0, got.RestartCount, "stale counter is cleared")
	assert.False(t, got.Graceful, "stale graceful flag is cleared")
	assert.Equal(t, "1.0.0", got.PreviousVersion, "other fields are preserved")
}

func TestCheckRollback_MissingStateNoop(t *testing.T) {
	u := &Updater{stateDir: t.TempDir()}
	assert.NotPanics(t, u.checkRollback, "missing state file must be tolerated")
	_, err := u.loadState()
	assert.Error(t, err, "checkRollback must not create state when there isn't one")
}

// TestCheckRollback_ThresholdAttemptsRollback drives the counter to the
// threshold and verifies rollback is attempted. Backup is intentionally
// absent so rollback exits via Errorf before reaching os.Exit — the
// observable effect is that the counter reached updateMaxRestarts.
func TestCheckRollback_ThresholdAttemptsRollback(t *testing.T) {
	tmp := t.TempDir()
	u := &Updater{
		stateDir:  tmp,
		backupDir: filepath.Join(tmp, "missing-backups"),
	}
	u.saveState(updateState{
		LastUpdate:      time.Now(),
		RestartCount:    updateMaxRestarts - 1,
		PreviousVersion: "1.0.0",
	})

	u.checkRollback()

	got, err := u.loadState()
	require.NoError(t, err)
	assert.GreaterOrEqual(t, got.RestartCount, updateMaxRestarts,
		"counter must reach the threshold so the rollback branch is taken")
}

func TestMarkGracefulSetsFlag(t *testing.T) {
	u := &Updater{stateDir: t.TempDir()}
	u.saveState(updateState{LastUpdate: time.Now(), RestartCount: 1})

	u.markGraceful()

	got, err := u.loadState()
	require.NoError(t, err)
	assert.True(t, got.Graceful)
	assert.Equal(t, 1, got.RestartCount, "markGraceful must not touch the counter")
}

// TestMarkGracefulIfCancelled_PanicLeavesFlagFalse is the panic-safety
// regression: Run's defer must distinguish "ctx cancelled (real graceful
// shutdown)" from "panic unwinding (real crash)". Without the ctx.Err()
// guard, a panic in Run would write Graceful=true and mask itself from
// crash-loop detection on the next start.
func TestMarkGracefulIfCancelled_PanicLeavesFlagFalse(t *testing.T) {
	u := &Updater{stateDir: t.TempDir()}
	u.saveState(updateState{LastUpdate: time.Now()})

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	// Live ctx — simulates panic-unwinding path where defer fires but ctx
	// was never cancelled. Must NOT mark graceful.
	u.markGracefulIfCancelled(ctx)
	got, err := u.loadState()
	require.NoError(t, err)
	assert.False(t, got.Graceful, "live ctx must not mark graceful (panic case)")

	// Now cancel and call again — must mark graceful.
	cancel()
	u.markGracefulIfCancelled(ctx)
	got, err = u.loadState()
	require.NoError(t, err)
	assert.True(t, got.Graceful, "cancelled ctx marks graceful")
}

func TestAttemptRollback_MissingBackup(t *testing.T) {
	tmp := t.TempDir()
	u := &Updater{
		stateDir:  tmp,
		backupDir: filepath.Join(tmp, "missing"),
	}
	u.saveState(updateState{LastUpdate: time.Now(), RestartCount: updateMaxRestarts})

	err := u.attemptRollback("1.0.0")
	require.ErrorIs(t, err, os.ErrNotExist, "missing backup must surface as not-exist for callers")

	got, err := u.loadState()
	require.NoError(t, err)
	assert.Equal(t, updateMaxRestarts, got.RestartCount,
		"failed rollback must not touch state — operator needs the original counters for diagnosis")
}

func TestAttemptRollback_SuccessClosesWindow(t *testing.T) {
	tmp := t.TempDir()
	binPath := filepath.Join(tmp, "topsrv")
	require.NoError(t, os.WriteFile(binPath, []byte("current"), 0o755))
	backupDir := filepath.Join(tmp, "backups")
	require.NoError(t, os.MkdirAll(backupDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(backupDir, "topsrv-1.0.0"), []byte("previous"), 0o755))

	u := &Updater{
		stateDir:  tmp,
		backupDir: backupDir,
		binPath:   binPath,
	}
	u.saveState(updateState{
		LastUpdate:      time.Now(),
		PreviousVersion: "1.0.0",
		CurrentVersion:  "1.1.0",
		RestartCount:    updateMaxRestarts,
		Graceful:        true,
	})

	require.NoError(t, u.attemptRollback("1.0.0"))

	// Binary replaced.
	data, err := os.ReadFile(binPath)
	require.NoError(t, err)
	assert.Equal(t, "previous", string(data))

	// State cleared enough to keep checkRollback out of the window on the
	// next supervisor restart, but version history is preserved for
	// post-mortem.
	got, err := u.loadState()
	require.NoError(t, err)
	assert.True(t, got.LastUpdate.IsZero(), "window closed")
	assert.Equal(t, 0, got.RestartCount)
	assert.False(t, got.Graceful)
	assert.Equal(t, "1.0.0", got.PreviousVersion, "version history preserved")
	assert.Equal(t, "1.1.0", got.CurrentVersion)
}

func TestMarkStableAfterResetsCounter(t *testing.T) {
	u := &Updater{stateDir: t.TempDir()}
	u.saveState(updateState{LastUpdate: time.Now(), RestartCount: 2})

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	done := make(chan struct{})
	go func() {
		u.markStableAfter(ctx, 10*time.Millisecond)
		close(done)
	}()
	<-done

	got, err := u.loadState()
	require.NoError(t, err)
	assert.Equal(t, 0, got.RestartCount, "uptime threshold resets counter")
}

func TestMarkStableAfterCancelled(t *testing.T) {
	u := &Updater{stateDir: t.TempDir()}
	u.saveState(updateState{LastUpdate: time.Now(), RestartCount: 2})

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	u.markStableAfter(ctx, time.Hour) // returns immediately via ctx

	got, err := u.loadState()
	require.NoError(t, err)
	assert.Equal(t, 2, got.RestartCount, "cancelled threshold must not reset")
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

func TestStateDir(t *testing.T) {
	assert.Equal(t, "/var/lib/topsrv", StateDir(""))
	assert.Equal(t, "/var/lib/topsrv", StateDir("/var/lib/topsrv/spool"))
	assert.Equal(t, "spool", StateDir("spool"), "a bare relative dir is its own state dir")
}

// testRelease is a release archive with script as the topsrv binary, and its checksum.
func testRelease(t *testing.T, script string) ([]byte, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "topsrv.tar.gz")
	createTestTarGz(t, path, "topsrv", []byte(script))
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	h := sha256.Sum256(data)
	return data, "sha256:" + hex.EncodeToString(h[:])
}

// newTestUpdater is an Updater whose binary, an old script, is in binDir.
func newTestUpdater(t *testing.T, binDir string, client *http.Client) *Updater {
	t.Helper()
	binPath := filepath.Join(binDir, "topsrv")
	require.NoError(t, os.WriteFile(binPath, []byte(oldTestBinary), 0o755))
	return &Updater{
		version:   "1.0.0",
		binPath:   binPath,
		backupDir: filepath.Join(binDir, ".topsrv-backup"),
		stateDir:  t.TempDir(),
		client:    client,
	}
}

const oldTestBinary = "#!/bin/sh\necho old\n"

// stagingDirs lists the update staging directories in dir.
func stagingDirs(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	assert.NoError(t, err)
	var out []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), updateDirPrefix) {
			out = append(out, e.Name())
		}
	}
	return out
}

func TestApplyStagesNextToBinary(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the test binary is a shell script")
	}
	const newBinary = "#!/bin/sh\nexit 0\n"
	release, checksum := testRelease(t, newBinary)
	binDir := t.TempDir()
	staged := make(chan []string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		staged <- stagingDirs(t, binDir)
		w.Write(release)
	}))
	defer srv.Close()
	u := newTestUpdater(t, binDir, srv.Client())
	stale := updateDirPrefix + "killed"
	require.NoError(t, os.MkdirAll(filepath.Join(binDir, stale, "sub"), 0o750))

	stage, err := u.apply(t.Context(), &UpdateResponse{Update: true, Version: "1.1.0", URL: srv.URL, Checksum: checksum})
	require.NoError(t, err, stage)

	inFlight := <-staged
	assert.Len(t, inFlight, 1, "the download goes to a staging directory next to the binary")
	assert.NotContains(t, inFlight, stale, "a directory left by a killed agent is removed")
	assert.Empty(t, stagingDirs(t, binDir), "the staging directory is removed after the update")

	got, err := os.ReadFile(u.binPath)
	require.NoError(t, err)
	assert.Equal(t, newBinary, string(got))
	assert.FileExists(t, filepath.Join(u.backupDir, "topsrv-1.0.0"))
	state, err := u.loadState()
	require.NoError(t, err)
	assert.Equal(t, "1.1.0", state.CurrentVersion)
}

func TestApplyFailedStage(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the test binary is a shell script")
	}
	cases := []struct {
		name        string
		script      string
		status      int
		badChecksum bool
		stage       string
	}{
		{name: "release not found", script: "#!/bin/sh\nexit 0\n", status: http.StatusNotFound, stage: "download"},
		{name: "checksum mismatch", script: "#!/bin/sh\nexit 0\n", badChecksum: true, stage: "checksum"},
		{name: "new binary does not run", script: "#!/bin/sh\nexit 3\n", stage: "verify"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			release, checksum := testRelease(t, tc.script)
			if tc.badChecksum {
				checksum = "sha256:" + strings.Repeat("0", 64)
			}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.status != 0 {
					w.WriteHeader(tc.status)
					return
				}
				w.Write(release)
			}))
			defer srv.Close()
			binDir := t.TempDir()
			u := newTestUpdater(t, binDir, srv.Client())

			stage, err := u.apply(t.Context(), &UpdateResponse{Update: true, Version: "1.1.0", URL: srv.URL, Checksum: checksum})
			require.Error(t, err)
			assert.Equal(t, tc.stage, stage)
			assert.Empty(t, stagingDirs(t, binDir), "the staging directory is removed on failure")
			assert.NoDirExists(t, u.backupDir, "nothing is backed up before the new binary runs")
			got, err := os.ReadFile(u.binPath)
			require.NoError(t, err)
			assert.Equal(t, oldTestBinary, string(got), "the binary is not replaced")
		})
	}
}

func TestCheckReportsLastError(t *testing.T) {
	var offer atomic.Bool
	offer.Store(true)
	queries := make(chan url.Values, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/update", func(w http.ResponseWriter, r *http.Request) {
		queries <- r.URL.Query()
		json.NewEncoder(w).Encode(UpdateResponse{Update: offer.Load(), Version: "1.1.0",
			URL: "http://" + r.Host + "/release.tar.gz", Checksum: "sha256:" + strings.Repeat("0", 64)})
	})
	mux.HandleFunc("/release.tar.gz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNotFound) })
	srv := httptest.NewServer(mux)
	defer srv.Close()
	u := newTestUpdater(t, t.TempDir(), srv.Client())
	u.endpoint = srv.URL + "/v1/update"
	const want = "download: download HTTP 404"

	u.check(t.Context())
	assert.False(t, (<-queries).Has("lastError"), "nothing failed before the first check")
	assert.Equal(t, want, u.lastError)

	u.check(t.Context())
	assert.Equal(t, want, (<-queries).Get("lastError"), "the failure goes with the next check")

	offer.Store(false)
	u.check(t.Context())
	assert.Equal(t, want, (<-queries).Get("lastError"))
	assert.Empty(t, u.lastError, "a withdrawn offer clears the error")

	u.check(t.Context())
	assert.False(t, (<-queries).Has("lastError"))
}

func TestUpdateErrorText(t *testing.T) {
	cases := []struct {
		name  string
		stage string
		err   error
		want  string
	}{
		{"exec from a noexec mount", "verify",
			&os.PathError{Op: "fork/exec", Path: "/tmp/topsrv-update-123/topsrv", Err: fs.ErrPermission},
			"verify: fork/exec topsrv: permission denied"},
		{"wrapped path error", "backup",
			fmt.Errorf("copy: %w", &os.PathError{Op: "open", Path: "/usr/local/bin/.topsrv-backup/topsrv-1.0.0", Err: fs.ErrPermission}),
			"backup: open topsrv-1.0.0: permission denied"},
		{"rename", "replace",
			&os.LinkError{Op: "rename", Old: "/usr/local/bin/topsrv.new", New: "/usr/local/bin/topsrv", Err: fs.ErrPermission},
			"replace: rename topsrv: permission denied"},
		{"request without its URL", "download",
			&url.Error{Op: "Get", URL: "https://example.com/topsrv_1.1.0_linux_amd64.tar.gz", Err: io.ErrUnexpectedEOF},
			"download: Get: unexpected EOF"},
		{"plain error", "download", errors.New("download HTTP 404"), "download: download HTTP 404"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, updateErrorText(tc.stage, tc.err))
		})
	}

	t.Run("at most updateErrorMax runes", func(t *testing.T) {
		got := updateErrorText("download", errors.New(strings.Repeat("ошибка ", 40)))
		assert.Equal(t, updateErrorMax, utf8.RuneCountInString(got))
		assert.True(t, utf8.ValidString(got))
	})
}
