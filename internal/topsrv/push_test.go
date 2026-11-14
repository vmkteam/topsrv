package topsrv

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vmkteam/topsrv/internal/topsrv/inventory"
	"github.com/vmkteam/topsrv/internal/topsrv/spool"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vmkteam/embedlog"
)

func TestPusherGather(t *testing.T) {
	reg := prometheus.NewRegistry()
	g := prometheus.NewGauge(prometheus.GaugeOpts{Name: "test_metric", Help: "test"})
	g.Set(42)
	reg.MustRegister(g)

	p := NewPusher(embedlog.Logger{}, "topsrv", "test", PushConfig{Endpoint: "http://localhost", Interval: "1s"}, reg)
	data, err := p.gather()
	require.NoError(t, err)
	assert.NotEmpty(t, data)

	// Decompress and verify content.
	gz, err := gzip.NewReader(bytes.NewReader(data))
	require.NoError(t, err)
	text, err := io.ReadAll(gz)
	require.NoError(t, err)
	assert.Contains(t, string(text), "test_metric 42")
}

func TestPusherSend(t *testing.T) {
	var received atomic.Int64
	var lastEncoding, lastAuth string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastEncoding = r.Header.Get("Content-Encoding")
		lastAuth = r.Header.Get("Authorization")
		received.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	reg := prometheus.NewRegistry()
	reg.MustRegister(prometheus.NewGauge(prometheus.GaugeOpts{Name: "test_push", Help: "t"}))

	p := NewPusher(embedlog.Logger{}, "topsrv", "test", PushConfig{
		Endpoint: srv.URL,
		Token:    "test-token",
		Interval: "1s",
	}, reg)

	// Direct push, not via ticker.
	p.push(context.Background())

	assert.Equal(t, int64(1), received.Load())
	assert.Equal(t, "gzip", lastEncoding)
	assert.Equal(t, "Bearer test-token", lastAuth)
}

func TestPusherSpool(t *testing.T) {
	dir := t.TempDir()
	var calls atomic.Int64

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if n <= 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	reg := prometheus.NewRegistry()
	reg.MustRegister(prometheus.NewGauge(prometheus.GaugeOpts{Name: "test_spool", Help: "t"}))

	p := NewPusher(embedlog.Logger{}, "topsrv", "test", PushConfig{
		Endpoint: srv.URL,
		Interval: "100ms",
		SpoolDir: dir,
	}, reg)

	ctx, cancel := context.WithTimeout(context.Background(), 600*time.Millisecond)
	defer cancel()
	p.Run(ctx)

	// Spool should have at most 1 file (the final flush snapshot).
	// Previously spooled files from failed sends must be drained by retries.
	files, _ := filepath.Glob(filepath.Join(dir, "*.gz"))
	assert.LessOrEqual(t, len(files), 1, "spool should be drained except for final flush")
}

func TestPusherSpoolTrim(t *testing.T) {
	dir := t.TempDir()
	for i := range pushMaxSpoolSize + 20 {
		os.WriteFile(filepath.Join(dir, fmt.Sprintf("%013d.gz", i)), []byte("data"), 0640)
	}

	p := NewPusher(embedlog.Logger{}, "topsrv", "test", PushConfig{SpoolDir: dir}, nil)
	// One more file, then a trim down to pushMaxSpoolSize.
	p.spoolWrite(context.Background(), p.metricsSpool, "", pushMaxSpoolSize, []byte("data"))

	files, _ := filepath.Glob(filepath.Join(dir, "*.gz"))
	assert.Len(t, files, pushMaxSpoolSize)
}

// inventoryBackend stands in for the backend: metric pushes always succeed,
// /v1/inventory answers with the current status and records every snapshot
// it received, accepted or not.
type inventoryBackend struct {
	*httptest.Server

	status atomic.Int64

	mu       sync.Mutex
	received []inventory.Payload
}

func newInventoryBackend(t *testing.T, status int) *inventoryBackend {
	t.Helper()
	b := &inventoryBackend{}
	b.status.Store(int64(status))
	b.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/inventory" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		var p inventory.Payload
		_ = json.NewDecoder(r.Body).Decode(&p) // a broken body shows up as an empty Kind in assertions
		b.mu.Lock()
		b.received = append(b.received, p)
		b.mu.Unlock()
		w.WriteHeader(int(b.status.Load()))
	}))
	t.Cleanup(b.Close)
	return b
}

func (b *inventoryBackend) got() []inventory.Payload {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]inventory.Payload(nil), b.received...)
}

// fakeInventory hands out queued snapshots once, like the real providers, and
// records acknowledgements. Called only from the test goroutine via push().
type fakeInventory struct {
	pending []inventory.Payload
	acked   []string
}

func (f *fakeInventory) Inventory() []inventory.Payload {
	out := f.pending
	f.pending = nil
	return out
}

func (f *fakeInventory) OnInventoryPushed(kind string) { f.acked = append(f.acked, kind) }

func newInventoryPusher(t *testing.T, b *inventoryBackend, spoolDir string) (*Pusher, *fakeInventory) {
	t.Helper()
	p := NewPusher(embedlog.Logger{}, "topsrv", "test", PushConfig{
		Endpoint: b.URL + "/v1/write",
		Interval: "1s",
		SpoolDir: spoolDir,
	}, prometheus.NewRegistry())
	src := &fakeInventory{}
	p.AddInventoryProvider(src)
	return p, src
}

func testPayload(kind string, scannedAt time.Time) inventory.Payload {
	return inventory.Payload{
		Kind:      kind,
		ScannedAt: scannedAt,
		Host:      inventory.HostMeta{OsID: "debian", OsVersionID: "12", PackageManager: inventory.ManagerDpkg},
	}
}

// inventorySpool is the pusher's inventory spool under spoolDir.
func inventorySpool(spoolDir string) spool.Dir {
	return spool.Dir{Path: filepath.Join(spoolDir, inventorySpoolDir), Ext: ".json"}
}

// writeSpooled puts a snapshot into the inventory spool the way an earlier
// failed send would have, named after scannedAt so order is deterministic.
func writeSpooled(t *testing.T, spoolDir, kind string, scannedAt time.Time) string {
	t.Helper()
	body, err := json.Marshal(testPayload(kind, scannedAt))
	require.NoError(t, err)
	name := fmt.Sprintf("%s-%d", kind, scannedAt.UnixMilli())
	d := inventorySpool(spoolDir)
	require.NoError(t, d.Write(name, body))
	return filepath.Join(d.Path, name+d.Ext)
}

// spooledFiles lists base names in the inventory spool with the prefix, oldest first.
func spooledFiles(spoolDir, prefix string) []string {
	files := inventorySpool(spoolDir).Files(prefix)
	names := make([]string, 0, len(files))
	for _, f := range files {
		names = append(names, filepath.Base(f))
	}
	return names
}

func scannedMillis(payloads []inventory.Payload) []int64 {
	out := make([]int64, 0, len(payloads))
	for _, p := range payloads {
		out = append(out, p.ScannedAt.UnixMilli())
	}
	return out
}

func TestPusherInventory(t *testing.T) {
	// An hour back keeps fixture names older than anything spooled during the test.
	t0 := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)

	t.Run("4xx is not spooled and is logged once per hour per kind", func(t *testing.T) {
		b := newInventoryBackend(t, http.StatusBadRequest)
		dir := t.TempDir()
		p, src := newInventoryPusher(t, b, dir)

		src.pending = []inventory.Payload{testPayload("security", t0)}
		p.push(t.Context())
		first, ok := p.rejectLoggedAt["security"]
		require.True(t, ok, "the first 400 is logged")
		src.pending = []inventory.Payload{testPayload("security", t0.Add(time.Minute))}
		p.push(t.Context())

		assert.Len(t, b.got(), 2)
		assert.Empty(t, spooledFiles(dir, ""), "4xx must not be spooled")
		assert.Empty(t, src.acked)
		assert.Equal(t, first, p.rejectLoggedAt["security"], "second 400 within the hour is not logged")

		src.pending = []inventory.Payload{testPayload("packages", t0)}
		p.push(t.Context())
		assert.Contains(t, p.rejectLoggedAt, "packages", "another kind has its own limit")

		hourAgo := time.Now().Add(-time.Hour)
		p.rejectLoggedAt["security"] = hourAgo
		src.pending = []inventory.Payload{testPayload("security", t0.Add(2*time.Minute))}
		p.push(t.Context())
		assert.True(t, p.rejectLoggedAt["security"].After(hourAgo), "logged again after an hour")
	})

	t.Run("5xx is spooled and resent before the fresh snapshot", func(t *testing.T) {
		b := newInventoryBackend(t, http.StatusServiceUnavailable)
		dir := t.TempDir()
		p, src := newInventoryPusher(t, b, dir)

		src.pending = []inventory.Payload{testPayload("security", t0)}
		p.push(t.Context())

		files := spooledFiles(dir, "")
		require.Len(t, files, 1)
		assert.True(t, strings.HasPrefix(files[0], "security-"), files[0])
		assert.Empty(t, src.acked)

		b.status.Store(http.StatusOK)
		src.pending = []inventory.Payload{testPayload("security", t0.Add(time.Minute))}
		p.push(t.Context())

		want := []int64{t0.UnixMilli(), t0.UnixMilli(), t0.Add(time.Minute).UnixMilli()}
		assert.Equal(t, want, scannedMillis(b.got()), "503, then spool resend, then the fresh snapshot")
		assert.Empty(t, spooledFiles(dir, ""))
		assert.Equal(t, []string{"security"}, src.acked, "only the live send is acknowledged")
	})

	t.Run("401 is spooled until the token is fixed", func(t *testing.T) {
		b := newInventoryBackend(t, http.StatusUnauthorized)
		dir := t.TempDir()
		p, src := newInventoryPusher(t, b, dir)

		src.pending = []inventory.Payload{testPayload("security", t0)}
		p.push(t.Context())
		p.push(t.Context()) // the resend hits 401 again and keeps the file

		assert.Len(t, b.got(), 2)
		assert.Len(t, spooledFiles(dir, ""), 1)
		assert.Empty(t, p.rejectLoggedAt, "401 is not a rejection")

		b.status.Store(http.StatusOK)
		p.push(t.Context())

		assert.Equal(t, []int64{t0.UnixMilli(), t0.UnixMilli(), t0.UnixMilli()}, scannedMillis(b.got()))
		assert.Empty(t, spooledFiles(dir, ""))
	})

	t.Run("4xx on resend drops the spooled file", func(t *testing.T) {
		b := newInventoryBackend(t, http.StatusBadRequest)
		dir := t.TempDir()
		p, _ := newInventoryPusher(t, b, dir)
		writeSpooled(t, dir, "packages", t0)

		p.push(t.Context())

		assert.Len(t, b.got(), 1)
		assert.Empty(t, spooledFiles(dir, ""))
	})

	t.Run("retryable failure on resend keeps files and stops the pass", func(t *testing.T) {
		b := newInventoryBackend(t, http.StatusTooManyRequests)
		dir := t.TempDir()
		p, _ := newInventoryPusher(t, b, dir)
		writeSpooled(t, dir, "security", t0)
		writeSpooled(t, dir, "security", t0.Add(time.Minute))

		p.push(t.Context())

		assert.Len(t, b.got(), 1, "the pass stops at the first retryable failure")
		assert.Len(t, spooledFiles(dir, ""), 2)
	})

	t.Run("at most 5 spooled files per tick, oldest first", func(t *testing.T) {
		b := newInventoryBackend(t, http.StatusOK)
		dir := t.TempDir()
		p, _ := newInventoryPusher(t, b, dir)
		want := make([]int64, 0, 7)
		for i := range 7 {
			at := t0.Add(time.Duration(i) * time.Minute)
			writeSpooled(t, dir, "security", at)
			want = append(want, at.UnixMilli())
		}

		p.push(t.Context())
		assert.Equal(t, want[:5], scannedMillis(b.got()))
		assert.Len(t, spooledFiles(dir, ""), 2)

		p.push(t.Context())
		assert.Equal(t, want, scannedMillis(b.got()))
		assert.Empty(t, spooledFiles(dir, ""))
	})

	t.Run("files older than 7 days are dropped without a request", func(t *testing.T) {
		b := newInventoryBackend(t, http.StatusOK)
		dir := t.TempDir()
		p, _ := newInventoryPusher(t, b, dir)
		old := writeSpooled(t, dir, "packages", t0)
		eightDaysAgo := time.Now().Add(-8 * 24 * time.Hour)
		require.NoError(t, os.Chtimes(old, eightDaysAgo, eightDaysAgo))
		writeSpooled(t, dir, "security", t0)

		p.push(t.Context())

		got := b.got()
		require.Len(t, got, 1)
		assert.Equal(t, "security", got[0].Kind)
		assert.Empty(t, spooledFiles(dir, ""))
	})

	t.Run("spool keeps at most 20 files per kind", func(t *testing.T) {
		dir := t.TempDir()
		for i := range 25 {
			writeSpooled(t, dir, "packages", t0.Add(time.Duration(i)*time.Minute))
		}
		writeSpooled(t, dir, "security", t0)
		p := NewPusher(embedlog.Logger{}, "topsrv", "test", PushConfig{SpoolDir: dir}, nil)

		p.spoolWrite(t.Context(), p.inventorySpool, "packages-", inventoryMaxSpoolPerKind, []byte(`{}`))

		pkgs := spooledFiles(dir, "packages-")
		require.Len(t, pkgs, inventoryMaxSpoolPerKind)
		// 25 + 1 new → the 6 oldest go.
		assert.Equal(t, fmt.Sprintf("packages-%d.json", t0.Add(6*time.Minute).UnixMilli()), pkgs[0])
		assert.Len(t, spooledFiles(dir, "security-"), 1, "another kind is not trimmed")
	})
}

func TestPusherMetricsSpool(t *testing.T) {
	// statusServer answers /v1/write with the given statuses in turn, the last
	// one repeating, and counts the calls.
	statusServer := func(t *testing.T, statuses ...int) (*httptest.Server, *atomic.Int64) {
		t.Helper()
		var calls atomic.Int64
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			n := int(calls.Add(1))
			w.WriteHeader(statuses[min(n, len(statuses))-1])
		}))
		t.Cleanup(srv.Close)
		return srv, &calls
	}
	newPusher := func(srv *httptest.Server, dir string) *Pusher {
		return NewPusher(embedlog.Logger{}, "topsrv", "test", PushConfig{
			Endpoint: srv.URL + "/v1/write",
			Interval: "1s",
			SpoolDir: dir,
		}, prometheus.NewRegistry())
	}
	t.Run("400 drops the payload, 401 spools it", func(t *testing.T) {
		dir := t.TempDir()
		srv, _ := statusServer(t, http.StatusBadRequest, http.StatusUnauthorized)
		p := newPusher(srv, dir)

		p.push(t.Context())
		assert.Empty(t, p.metricsSpool.Files(""), "a rejected payload is not spooled")

		p.push(t.Context())
		assert.Len(t, p.metricsSpool.Files(""), 1, "401: the token may be re-issued")
	})

	t.Run("a spooled payload rejected on resend is dropped and the pass goes on", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "100.gz"), []byte("a"), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "200.gz"), []byte("b"), 0o600))
		srv, calls := statusServer(t, http.StatusBadRequest, http.StatusNoContent)
		p := newPusher(srv, dir)

		p.push(t.Context())

		assert.Equal(t, int64(3), calls.Load(), "100 rejected, 200 resent, fresh payload sent")
		assert.Empty(t, p.metricsSpool.Files(""))
	})
}

func TestPostJSONErrors(t *testing.T) {
	t.Run("status and body preview", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnprocessableEntity)
			_, _ = io.WriteString(w, "unknown kind"+strings.Repeat("x", 500))
		}))
		defer srv.Close()
		p := NewPusher(embedlog.Logger{}, "topsrv", "test", PushConfig{Endpoint: srv.URL}, nil)

		err := p.postJSON(t.Context(), srv.URL, []byte(`{}`))

		var se *spool.StatusError
		require.ErrorAs(t, err, &se)
		assert.Equal(t, http.StatusUnprocessableEntity, se.Code)
		assert.True(t, strings.HasPrefix(se.Body, "unknown kind"), se.Body)
		assert.Len(t, se.Body, 200)
		assert.False(t, spool.Retryable(err))
	})

	t.Run("unreachable endpoint is retryable", func(t *testing.T) {
		srv := httptest.NewServer(http.NotFoundHandler())
		url := srv.URL
		srv.Close()
		p := NewPusher(embedlog.Logger{}, "topsrv", "test", PushConfig{Endpoint: url}, nil)

		err := p.postJSON(t.Context(), url, []byte(`{}`))

		require.Error(t, err)
		assert.NotErrorAs(t, err, new(*spool.StatusError))
		assert.True(t, spool.Retryable(err))
	})
}
