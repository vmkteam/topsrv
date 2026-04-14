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
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v4/host"
	"github.com/vmkteam/appkit"
	"github.com/vmkteam/embedlog"
)

const (
	updateTimeout    = 60 * time.Second
	updateMaxBackups = 5
	updateExitCode   = 42
	updateStateFile  = "update-state.json"
)

// UpdateConfig contains auto-update settings.
type UpdateConfig struct {
	Enabled  bool
	Interval string // default "15m"
	Channel  string // default "stable"
}

// UpdateResponse is the JSON response from gatesrv /v1/update.
type UpdateResponse struct {
	Update    bool   `json:"update"`
	Version   string `json:"version,omitempty"`
	URL       string `json:"url,omitempty"`
	Checksum  string `json:"checksum,omitempty"`
	Channel   string `json:"channel,omitempty"`
	Mandatory bool   `json:"mandatory,omitempty"`
}

type updateState struct {
	LastUpdate      time.Time `json:"last_update"`
	PreviousVersion string    `json:"previous_version"`
	CurrentVersion  string    `json:"current_version"`
	RestartCount    int       `json:"restart_count"`
}

// Updater checks for new agent versions and performs self-update.
type Updater struct {
	embedlog.Logger

	cfg       UpdateConfig
	endpoint  string // derived from push endpoint: base + /v1/update
	token     string
	version   string
	binPath   string // os.Executable()
	backupDir string // <binDir>/.topsrv-backup/
	stateDir  string // from push SpoolDir parent or /var/lib/topsrv
	client    *http.Client
	interval  time.Duration
	hostname  string
}

// NewUpdater creates a new auto-updater. Endpoint is derived from pushCfg.Endpoint.
func NewUpdater(logger embedlog.Logger, appName, version string, cfg UpdateConfig, pushCfg PushConfig) *Updater {
	interval, err := time.ParseDuration(cfg.Interval)
	if err != nil || interval < time.Minute {
		interval = 15 * time.Minute
	}

	if cfg.Channel == "" {
		cfg.Channel = "stable"
	}

	endpoint := deriveUpdateEndpoint(pushCfg.Endpoint)

	binPath, _ := os.Executable()
	binPath, _ = filepath.EvalSymlinks(binPath)

	backupDir := filepath.Join(filepath.Dir(binPath), ".topsrv-backup")

	stateDir := "/var/lib/topsrv"
	if pushCfg.SpoolDir != "" {
		stateDir = filepath.Dir(pushCfg.SpoolDir)
		if stateDir == "." {
			stateDir = pushCfg.SpoolDir
		}
	}

	hostname := ""
	if info, err := host.Info(); err == nil {
		hostname = info.Hostname
	}

	return &Updater{
		Logger:    logger,
		cfg:       cfg,
		endpoint:  endpoint,
		token:     pushCfg.Token,
		version:   version,
		binPath:   binPath,
		backupDir: backupDir,
		stateDir:  stateDir,
		client:    appkit.NewHTTPClient(appName, version, updateTimeout),
		interval:  interval,
		hostname:  hostname,
	}
}

// deriveUpdateEndpoint replaces /v1/write with /v1/update in the push endpoint URL.
func deriveUpdateEndpoint(pushEndpoint string) string {
	u, err := url.Parse(pushEndpoint)
	if err != nil {
		return ""
	}
	u.Path = "/v1/update"
	return u.String()
}

// Run starts the update check loop. Blocks until ctx is cancelled.
func (u *Updater) Run(ctx context.Context) {
	u.checkRollback()

	jitter := time.Duration(rand.IntN(60)) * time.Second
	u.Printf("update: started, endpoint=%s, interval=%s, jitter=%s", u.endpoint, u.interval, jitter)

	select {
	case <-time.After(jitter):
	case <-ctx.Done():
		return
	}

	u.check(ctx)

	ticker := time.NewTicker(u.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			u.Printf("update: stopped")
			return
		case <-ticker.C:
			u.check(ctx)
		}
	}
}

func (u *Updater) check(ctx context.Context) {
	resp, err := u.fetchUpdate(ctx)
	if err != nil {
		u.Errorf("update: check failed: %v", err)
		return
	}
	if !resp.Update {
		return
	}

	u.Printf("update: available %s → %s", u.version, resp.Version)

	tmpDir, err := os.MkdirTemp("", "topsrv-update-*")
	if err != nil {
		u.Errorf("update: mktemp failed: %v", err)
		return
	}
	cleanup := func() { _ = os.RemoveAll(tmpDir) }
	defer cleanup()

	tarPath := filepath.Join(tmpDir, "topsrv.tar.gz")
	if err := u.download(ctx, resp.URL, tarPath); err != nil {
		u.Errorf("update: download failed: %v", err)
		return
	}

	if err := verifyChecksum(tarPath, resp.Checksum); err != nil {
		u.Errorf("update: checksum failed: %v", err)
		return
	}

	newBinPath := filepath.Join(tmpDir, "topsrv")
	if err := extractBinary(tarPath, newBinPath); err != nil {
		u.Errorf("update: extract failed: %v", err)
		return
	}

	if err := verifyBinary(ctx, newBinPath); err != nil {
		u.Errorf("update: verify binary failed: %v", err)
		return
	}

	if err := u.backup(); err != nil {
		u.Errorf("update: backup failed: %v", err)
		return
	}

	u.saveState(updateState{
		LastUpdate:      time.Now(),
		PreviousVersion: u.version,
		CurrentVersion:  resp.Version,
		RestartCount:    0,
	})

	if err := u.replace(newBinPath); err != nil {
		u.Errorf("update: replace failed: %v", err)
		return
	}

	u.Printf("update: replaced %s → %s, restarting", u.version, resp.Version)
	cleanup()
	os.Exit(updateExitCode) //nolint:gocritic // cleanup called explicitly above
}

func (u *Updater) fetchUpdate(ctx context.Context) (*UpdateResponse, error) {
	reqURL := fmt.Sprintf("%s?version=%s&os=%s&arch=%s&channel=%s",
		u.endpoint, url.QueryEscape(u.version), runtime.GOOS, runtime.GOARCH, u.cfg.Channel)

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}
	if u.token != "" {
		req.Header.Set("Authorization", "Bearer "+u.token)
	}
	if u.hostname != "" {
		req.Header.Set("X-Hostname", u.hostname)
	}

	resp, err := u.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	var result UpdateResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	return &result, nil
}

func (u *Updater) download(ctx context.Context, dlURL, dest string) error {
	ctx, cancel := context.WithTimeout(ctx, updateTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, dlURL, nil)
	if err != nil {
		return err
	}

	resp, err := u.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download HTTP %d", resp.StatusCode)
	}

	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := io.Copy(f, resp.Body); err != nil {
		return err
	}
	return f.Close()
}

// verifyChecksum compares file's SHA256 with expected "sha256:<hex>" string.
func verifyChecksum(path, expected string) error {
	expectedHex := strings.TrimPrefix(expected, "sha256:")
	if expectedHex == "" || expectedHex == expected {
		return fmt.Errorf("invalid checksum format: %q", expected)
	}

	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}

	actual := hex.EncodeToString(h.Sum(nil))
	if actual != expectedHex {
		return fmt.Errorf("checksum mismatch: got %s, want %s", actual, expectedHex)
	}
	return nil
}

// extractBinary extracts the "topsrv" binary from a tar.gz archive.
func extractBinary(tarPath, destPath string) error {
	f, err := os.Open(tarPath)
	if err != nil {
		return err
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}

		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		// GoReleaser puts binary as "topsrv" in the archive root.
		name := filepath.Base(hdr.Name)
		if name != "topsrv" {
			continue
		}

		out, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, tr); err != nil {
			out.Close()
			return err
		}
		return out.Close()
	}
	return errors.New("binary 'topsrv' not found in archive")
}

// verifyBinary runs the new binary with --version to check it executes.
func verifyBinary(ctx context.Context, binPath string) error {
	cmd := exec.CommandContext(ctx, binPath, "--version")
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	return cmd.Run()
}

func (u *Updater) backup() error {
	if err := os.MkdirAll(u.backupDir, 0o750); err != nil {
		return err
	}

	dest := filepath.Join(u.backupDir, "topsrv-"+u.version)
	src, err := os.Open(u.binPath)
	if err != nil {
		return err
	}
	defer src.Close()

	dst, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(dst, src); err != nil {
		dst.Close()
		return err
	}
	if err := dst.Close(); err != nil {
		return err
	}

	u.Printf("update: backed up %s → %s", u.version, dest)
	u.trimBackups()
	return nil
}

func (u *Updater) trimBackups() {
	entries, err := os.ReadDir(u.backupDir)
	if err != nil || len(entries) <= updateMaxBackups {
		return
	}

	// Sort by version (semantic), remove oldest.
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Slice(names, func(i, j int) bool {
		return compareVersionedNames(names[i], names[j]) < 0
	})

	for _, name := range names[:len(names)-updateMaxBackups] {
		os.Remove(filepath.Join(u.backupDir, name))
	}
}

// compareVersionedNames compares backup filenames like "topsrv-0.0.9" and "topsrv-0.0.10"
// using numeric segment comparison to ensure correct ordering.
func compareVersionedNames(a, b string) int {
	va := extractVersion(a)
	vb := extractVersion(b)
	if va == "" || vb == "" {
		return strings.Compare(a, b)
	}

	partsA := strings.Split(va, ".")
	partsB := strings.Split(vb, ".")

	for i := 0; i < len(partsA) && i < len(partsB); i++ {
		na, _ := strconv.Atoi(partsA[i])
		nb, _ := strconv.Atoi(partsB[i])
		if na != nb {
			return na - nb
		}
	}
	return len(partsA) - len(partsB)
}

// extractVersion extracts version string from backup filename like "topsrv-0.0.9" or "topsrv-v0.0.9".
func extractVersion(name string) string {
	_, after, ok := strings.Cut(name, "topsrv-")
	if !ok {
		return ""
	}
	return strings.TrimPrefix(after, "v")
}

// replace copies new binary to same filesystem, then atomic rename.
func (u *Updater) replace(newBinPath string) error {
	tmpPath := u.binPath + ".new"

	src, err := os.Open(newBinPath)
	if err != nil {
		return err
	}
	defer src.Close()

	dst, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(dst, src); err != nil {
		dst.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := dst.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}

	return os.Rename(tmpPath, u.binPath)
}

// checkRollback detects crash-loop after update and rolls back.
func (u *Updater) checkRollback() {
	state, err := u.loadState()
	if err != nil {
		return
	}

	if time.Since(state.LastUpdate) < 5*time.Minute {
		state.RestartCount++
		u.saveState(state)

		if state.RestartCount >= 3 {
			u.Printf("update: crash-loop detected (%d restarts in %s), rolling back to %s",
				state.RestartCount, time.Since(state.LastUpdate).Round(time.Second), state.PreviousVersion)
			u.rollback(state.PreviousVersion)
		}
	} else if state.RestartCount > 0 {
		// Stable — reset counter.
		state.RestartCount = 0
		u.saveState(state)
	}
}

func (u *Updater) rollback(version string) {
	backupPath := filepath.Join(u.backupDir, "topsrv-"+version)
	if _, err := os.Stat(backupPath); err != nil {
		u.Errorf("update: rollback failed, backup not found: %s", backupPath)
		return
	}

	if err := u.replace(backupPath); err != nil {
		u.Errorf("update: rollback replace failed: %v", err)
		return
	}

	u.Printf("update: rolled back to %s, restarting", version)
	os.Exit(updateExitCode)
}

func (u *Updater) loadState() (updateState, error) {
	path := filepath.Join(u.stateDir, updateStateFile)
	data, err := os.ReadFile(path)
	if err != nil {
		return updateState{}, err
	}
	var s updateState
	err = json.Unmarshal(data, &s)
	return s, err
}

func (u *Updater) saveState(s updateState) {
	if err := os.MkdirAll(u.stateDir, 0o750); err != nil {
		return
	}
	data, err := json.Marshal(s)
	if err != nil {
		return
	}
	path := filepath.Join(u.stateDir, updateStateFile)
	_ = os.WriteFile(path, data, 0o640)
}
