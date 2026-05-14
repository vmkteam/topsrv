package topsrv

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

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
	// spool() writes one more file then trims down to pushMaxSpoolSize.
	p.spool(context.Background(), []byte("data"))

	files, _ := filepath.Glob(filepath.Join(dir, "*.gz"))
	assert.Len(t, files, pushMaxSpoolSize)
}
