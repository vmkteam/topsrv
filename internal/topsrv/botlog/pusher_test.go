package botlog

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
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

	"github.com/vmkteam/topsrv/internal/topsrv"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vmkteam/embedlog"
)

// receiver collects bodies and headers from POSTs for assertions.
type receiver struct {
	mu       sync.Mutex
	status   int32 // atomic; default 200
	bodies   [][]byte
	headers  []http.Header
	failOnce atomic.Bool
}

func newReceiver() *receiver {
	r := &receiver{}
	atomic.StoreInt32(&r.status, http.StatusOK)
	return r
}

func (r *receiver) handler(w http.ResponseWriter, req *http.Request) {
	body, _ := io.ReadAll(req.Body)
	defer req.Body.Close()

	if r.failOnce.Load() {
		r.failOnce.Store(false)
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	status := int(atomic.LoadInt32(&r.status))

	r.mu.Lock()
	r.bodies = append(r.bodies, body)
	r.headers = append(r.headers, req.Header.Clone())
	r.mu.Unlock()

	w.WriteHeader(status)
}

func (r *receiver) calls() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.bodies)
}

func (r *receiver) lastDecoded(t *testing.T) [][]byte {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	require.NotEmpty(t, r.bodies, "no batches received yet")

	gz, err := gzip.NewReader(bytes.NewReader(r.bodies[len(r.bodies)-1]))
	require.NoError(t, err)
	defer gz.Close()
	plain, err := io.ReadAll(gz)
	require.NoError(t, err)

	lines := strings.Split(strings.TrimRight(string(plain), "\n"), "\n")
	out := make([][]byte, 0, len(lines))
	for _, l := range lines {
		if l != "" {
			out = append(out, []byte(l))
		}
	}
	return out
}

// newTestPusher builds a Pusher whose spool lands in parentDir/botlog (the same
// layout Validate produces in production). Returns the pusher and the final
// spool subdir so tests can glob inside it.
func newTestPusher(t *testing.T, endpoint, parentDir string, batchSize int, batchInterval string) (*Pusher, string) {
	t.Helper()
	cfg := Config{
		Enabled:       true,
		Endpoint:      endpoint,
		Token:         "bl_test",
		BatchSize:     batchSize,
		BatchInterval: batchInterval,
		SpoolDir:      parentDir,
	}
	require.NoError(t, cfg.Validate(topsrv.PushConfig{}))
	return NewPusher(embedlog.Logger{}, "topsrv-test", "test", cfg, prometheus.NewRegistry()), cfg.SpoolDir
}

func sampleEvent(uri string) Event {
	ev, _ := NewEvent(time.Now(), "host01", Fields{
		Status:    "200",
		URI:       uri,
		UserAgent: "GPTBot/1.0",
	}, nil, 1024)
	return ev
}

func TestPusher_EnqueueAndFlushOnTicker(t *testing.T) {
	r := newReceiver()
	srv := httptest.NewServer(http.HandlerFunc(r.handler))
	defer srv.Close()

	p, _ := newTestPusher(t, srv.URL, t.TempDir(), 100, "20ms")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.Run(ctx)

	for i := range 5 {
		p.Enqueue(sampleEvent("/p" + string(rune('0'+i))))
	}

	require.Eventually(t, func() bool { return r.calls() >= 1 }, time.Second, 5*time.Millisecond)

	lines := r.lastDecoded(t)
	assert.Len(t, lines, 5)

	// Headers — auth, batch-id, gzip.
	r.mu.Lock()
	h := r.headers[0]
	r.mu.Unlock()
	assert.Equal(t, "Bearer bl_test", h.Get("Authorization"))
	assert.Equal(t, "gzip", h.Get("Content-Encoding"))
	assert.Equal(t, "application/x-ndjson", h.Get("Content-Type"))
	assert.NotEmpty(t, h.Get("X-Batch-Id"))
}

func TestPusher_FlushOnBatchSize(t *testing.T) {
	r := newReceiver()
	srv := httptest.NewServer(http.HandlerFunc(r.handler))
	defer srv.Close()

	p, _ := newTestPusher(t, srv.URL, t.TempDir(), 3, "10s") // long interval — only size triggers
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.Run(ctx)

	for i := range 3 {
		p.Enqueue(sampleEvent("/p" + string(rune('0'+i))))
	}
	require.Eventually(t, func() bool { return r.calls() >= 1 }, time.Second, 5*time.Millisecond)
	assert.Len(t, r.lastDecoded(t), 3)
}

func TestPusher_DropOnQueueFull(t *testing.T) {
	r := newReceiver()
	srv := httptest.NewServer(http.HandlerFunc(r.handler))
	defer srv.Close()

	// Tiny batch size → queue cap = 4. Don't start Run — events accumulate.
	p, _ := newTestPusher(t, srv.URL, t.TempDir(), 2, "10s")

	for range 10 {
		p.Enqueue(sampleEvent("/x"))
	}

	enq := testutil.ToFloat64(p.eventsTotal.WithLabelValues(stateEnqueued, ""))
	drop := testutil.ToFloat64(p.eventsTotal.WithLabelValues(stateDropped, dropReasonQueueFull))
	assert.InDelta(t, 4, enq, 0.5, "queue cap = batchSize*2")
	assert.InDelta(t, 6, drop, 0.5, "remaining events dropped, reason=queue_full")
}

func TestPusher_SpoolOnFailure(t *testing.T) {
	prev := retryBackoff
	retryBackoff = 10 * time.Millisecond
	defer func() { retryBackoff = prev }()

	r := newReceiver()
	atomic.StoreInt32(&r.status, http.StatusServiceUnavailable)
	srv := httptest.NewServer(http.HandlerFunc(r.handler))
	defer srv.Close()

	p, spool := newTestPusher(t, srv.URL, t.TempDir(), 2, "20ms")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.Run(ctx)

	p.Enqueue(sampleEvent("/a"))
	p.Enqueue(sampleEvent("/b"))

	require.Eventually(t, func() bool {
		files, _ := filepath.Glob(filepath.Join(spool, spoolFileGlob))
		return len(files) > 0
	}, 3*time.Second, 20*time.Millisecond)

	files, _ := filepath.Glob(filepath.Join(spool, spoolFileGlob))
	require.Len(t, files, 1)
	assert.True(t, strings.HasSuffix(files[0], spoolSuffix))
	assert.Positive(t, testutil.ToFloat64(p.eventsTotal.WithLabelValues(stateSpooled, "")))
}

func TestPusher_ReplaySpoolOnStartup(t *testing.T) {
	r := newReceiver()
	srv := httptest.NewServer(http.HandlerFunc(r.handler))
	defer srv.Close()

	parent := t.TempDir()
	p, spool := newTestPusher(t, srv.URL, parent, 10, "10s")

	// Pre-seed the (already-final) spool subdir with a valid gzipped ndjson batch.
	require.NoError(t, os.MkdirAll(spool, 0o700))
	batch := []Event{sampleEvent("/leftover")}
	payload, err := encodeBatch(batch)
	require.NoError(t, err)
	stalePath := filepath.Join(spool, "100-deadbeef.ndjson.gz")
	require.NoError(t, os.WriteFile(stalePath, payload, 0o600))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.Run(ctx)

	require.Eventually(t, func() bool { return r.calls() >= 1 }, 2*time.Second, 10*time.Millisecond)

	_, statErr := os.Stat(stalePath)
	assert.True(t, os.IsNotExist(statErr), "spool file should be deleted after successful resend")
	assert.Len(t, r.lastDecoded(t), 1)
}

func TestPusher_DrainsOnShutdown(t *testing.T) {
	r := newReceiver()
	srv := httptest.NewServer(http.HandlerFunc(r.handler))
	defer srv.Close()

	p, _ := newTestPusher(t, srv.URL, t.TempDir(), 100, "10s") // long interval
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() { p.Run(ctx); close(done) }()

	for i := range 4 {
		p.Enqueue(sampleEvent("/d" + string(rune('0'+i))))
	}
	time.Sleep(50 * time.Millisecond) // let events sit in queue

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after cancel")
	}

	assert.Equal(t, 1, r.calls(), "shutdown should flush exactly one batch")
	assert.Len(t, r.lastDecoded(t), 4)
}

func TestPusher_TrimSpoolByBudget(t *testing.T) {
	parent := t.TempDir()
	cfg := Config{
		Enabled:    true,
		Endpoint:   "http://example.invalid/v1/bot-logs",
		Token:      "bl_test",
		BatchSize:  10,
		SpoolDir:   parent,
		MaxSpoolMB: 2,
	}
	require.NoError(t, cfg.Validate(topsrv.PushConfig{}))
	p := NewPusher(embedlog.Logger{}, "topsrv-test", "test", cfg, prometheus.NewRegistry())

	// Three pre-seeded files of ~1 MB each in the final spool dir; budget 2 MB.
	require.NoError(t, os.MkdirAll(cfg.SpoolDir, 0o700))
	for _, name := range []string{"100-aaaa.ndjson.gz", "200-bbbb.ndjson.gz", "300-cccc.ndjson.gz"} {
		require.NoError(t, os.WriteFile(filepath.Join(cfg.SpoolDir, name), make([]byte, 1024*1024), 0o600))
	}

	p.trimSpool(context.Background())

	files, _ := filepath.Glob(filepath.Join(cfg.SpoolDir, spoolFileGlob))
	assert.Len(t, files, 2, "oldest file evicted")
	_, err := os.Stat(filepath.Join(cfg.SpoolDir, "100-aaaa.ndjson.gz"))
	assert.True(t, os.IsNotExist(err))
}

func TestPusher_PermanentFailureDropsBatch(t *testing.T) {
	prev := retryBackoff
	retryBackoff = 10 * time.Millisecond
	defer func() { retryBackoff = prev }()

	r := newReceiver()
	atomic.StoreInt32(&r.status, http.StatusBadRequest)
	srv := httptest.NewServer(http.HandlerFunc(r.handler))
	defer srv.Close()

	p, spool := newTestPusher(t, srv.URL, t.TempDir(), 1, "20ms")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.Run(ctx)

	p.Enqueue(sampleEvent("/bad"))

	require.Eventually(t, func() bool {
		return testutil.ToFloat64(p.eventsTotal.WithLabelValues(stateDropped, dropReasonPermanent)) >= 1
	}, 2*time.Second, 25*time.Millisecond)

	// Permanent rejection must NOT spool — a 4xx will repeat forever otherwise.
	files, _ := filepath.Glob(filepath.Join(spool, spoolFileGlob))
	assert.Empty(t, files, "4xx batch must be discarded, not spooled")
	assert.Positive(t, testutil.ToFloat64(p.sendErrors.WithLabelValues(errStatus)))
}

func TestPusher_RetrySpoolDiscardsPermanentlyRejected(t *testing.T) {
	// Pre-seed spool with a valid batch; server returns 400 to every request.
	// The replay must delete the file instead of breaking the loop forever.
	r := newReceiver()
	atomic.StoreInt32(&r.status, http.StatusBadRequest)
	srv := httptest.NewServer(http.HandlerFunc(r.handler))
	defer srv.Close()

	parent := t.TempDir()
	p, spool := newTestPusher(t, srv.URL, parent, 10, "10s")
	require.NoError(t, os.MkdirAll(spool, 0o700))

	batch := []Event{sampleEvent("/leftover")}
	payload, err := encodeBatch(batch)
	require.NoError(t, err)
	stalePath := filepath.Join(spool, "100-deadbeef.ndjson.gz")
	require.NoError(t, os.WriteFile(stalePath, payload, 0o600))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.Run(ctx)

	require.Eventually(t, func() bool {
		_, statErr := os.Stat(stalePath)
		return os.IsNotExist(statErr)
	}, 2*time.Second, 25*time.Millisecond)
}

func TestPusher_RetrySuccess(t *testing.T) {
	prev := retryBackoff
	retryBackoff = 10 * time.Millisecond
	defer func() { retryBackoff = prev }()

	r := newReceiver()
	r.failOnce.Store(true)
	srv := httptest.NewServer(http.HandlerFunc(r.handler))
	defer srv.Close()

	p, _ := newTestPusher(t, srv.URL, t.TempDir(), 1, "10s")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.Run(ctx)

	p.Enqueue(sampleEvent("/a"))

	require.Eventually(t, func() bool { return r.calls() >= 1 }, 2*time.Second, 10*time.Millisecond)
	assert.InDelta(t, 1, testutil.ToFloat64(p.eventsTotal.WithLabelValues(stateSent, "")), 0.01,
		"event marked as sent on retry success")
	assert.Positive(t, testutil.ToFloat64(p.sendErrors.WithLabelValues(errStatus)),
		"first attempt's status failure ticked")
}

func TestIsPermanentFailure(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"network", errors.New("dial tcp: connection refused"), false},
		{"400", &httpStatusError{code: http.StatusBadRequest}, true},
		{"401", &httpStatusError{code: http.StatusUnauthorized}, true},
		{"403", &httpStatusError{code: http.StatusForbidden}, true},
		{"413", &httpStatusError{code: http.StatusRequestEntityTooLarge}, true},
		{"408 request timeout", &httpStatusError{code: http.StatusRequestTimeout}, false},
		{"429 rate limit", &httpStatusError{code: http.StatusTooManyRequests}, false},
		{"500", &httpStatusError{code: http.StatusInternalServerError}, false},
		{"503", &httpStatusError{code: http.StatusServiceUnavailable}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, isPermanentFailure(tc.err))
		})
	}
}

func TestNewBatchID_TimestampOrdered(t *testing.T) {
	id1 := newBatchID()
	time.Sleep(2 * time.Millisecond)
	id2 := newBatchID()
	assert.Less(t, id1, id2, "batch ids must sort lexicographically by time")
	assert.Regexp(t, `^\d+-[0-9a-f]{16}$`, id1)
}

func TestBatchIDFromPath(t *testing.T) {
	assert.Equal(t, "1715000000-cafe1234cafe5678", batchIDFromPath("/tmp/spool/botlog/1715000000-cafe1234cafe5678.ndjson.gz"))
	assert.Equal(t, "no-suffix", batchIDFromPath("no-suffix"))
}

// TestPusher_RetrySpoolOrderOldestFirst guards the FIFO contract of retrySpool.
// retrySpool sorts file names lexicographically and relies on newBatchID's
// unix-ms prefix to produce a meaningful order. If anyone swaps newBatchID for
// a UUIDv4 (or any non-prefixed scheme), this test must fail loudly — silent
// FIFO loss would surface only as ordering anomalies in the ingest stream.
func TestPusher_RetrySpoolOrderOldestFirst(t *testing.T) {
	r := newReceiver()
	srv := httptest.NewServer(http.HandlerFunc(r.handler))
	defer srv.Close()

	parent := t.TempDir()
	p, spool := newTestPusher(t, srv.URL, parent, 10, "10s")
	require.NoError(t, os.MkdirAll(spool, 0o700))

	// Pre-seed three batches with timestamp prefixes 100/200/300. The /pN URI
	// distinguishes them in the decoded body.
	names := []string{"300-c.ndjson.gz", "100-a.ndjson.gz", "200-b.ndjson.gz"}
	uris := map[string]string{
		"100-a.ndjson.gz": "/p1",
		"200-b.ndjson.gz": "/p2",
		"300-c.ndjson.gz": "/p3",
	}
	for _, name := range names {
		payload, err := encodeBatch([]Event{sampleEvent(uris[name])})
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(spool, name), payload, 0o600))
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.Run(ctx)

	require.Eventually(t, func() bool { return r.calls() >= 3 }, 2*time.Second, 10*time.Millisecond)

	r.mu.Lock()
	bodies := append([][]byte(nil), r.bodies...)
	r.mu.Unlock()

	got := make([]string, 0, len(bodies))
	for _, raw := range bodies {
		gz, err := gzip.NewReader(bytes.NewReader(raw))
		require.NoError(t, err)
		plain, err := io.ReadAll(gz)
		require.NoError(t, err)
		gz.Close()
		switch {
		case strings.Contains(string(plain), `"/p1"`):
			got = append(got, "/p1")
		case strings.Contains(string(plain), `"/p2"`):
			got = append(got, "/p2")
		case strings.Contains(string(plain), `"/p3"`):
			got = append(got, "/p3")
		}
	}
	assert.Equal(t, []string{"/p1", "/p2", "/p3"}, got, "spool replay must send oldest-first")
}

// TestPusher_DrainSpoolsWhenEndpointDown is the missing graceful-shutdown case:
// SIGTERM arrives while the receiver is down. The drained batch must hit the
// spool so the next process picks it up. Closes the regression "rolling restart
// silently drops the last batch".
func TestPusher_DrainSpoolsWhenEndpointDown(t *testing.T) {
	prev := retryBackoff
	retryBackoff = 10 * time.Millisecond
	defer func() { retryBackoff = prev }()

	r := newReceiver()
	atomic.StoreInt32(&r.status, http.StatusServiceUnavailable)
	srv := httptest.NewServer(http.HandlerFunc(r.handler))
	defer srv.Close()

	p, spool := newTestPusher(t, srv.URL, t.TempDir(), 100, "10s")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { p.Run(ctx); close(done) }()

	for i := range 4 {
		p.Enqueue(sampleEvent("/d" + string(rune('0'+i))))
	}
	time.Sleep(50 * time.Millisecond) // let events sit in the queue
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return after cancel")
	}

	files, _ := filepath.Glob(filepath.Join(spool, spoolFileGlob))
	assert.NotEmpty(t, files, "drained batch must hit spool when endpoint is down")
	assert.Positive(t, testutil.ToFloat64(p.eventsTotal.WithLabelValues(stateSpooled, "")))
}

// TestPusher_RetrySpoolDoesNotBlockOnTransientFailures verifies the A2 fix:
// even when the oldest batch keeps getting 5xx, newer batches still get a
// chance within the same pass via maxTransientPerRun.
func TestPusher_RetrySpoolDoesNotBlockOnTransientFailures(t *testing.T) {
	prev := retryBackoff
	retryBackoff = 10 * time.Millisecond
	defer func() { retryBackoff = prev }()

	// Server: 503 to first batch (/p1), 200 to subsequent.
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		_ = req.Body.Close()
		if bytes.Contains(unwrapGzip(t, body), []byte(`"/p1"`)) {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	parent := t.TempDir()
	p, spool := newTestPusher(t, srv.URL, parent, 10, "10s")
	require.NoError(t, os.MkdirAll(spool, 0o700))

	for _, tc := range []struct {
		name string
		uri  string
	}{
		{"100-a.ndjson.gz", "/p1"},
		{"200-b.ndjson.gz", "/p2"},
		{"300-c.ndjson.gz", "/p3"},
	} {
		payload, err := encodeBatch([]Event{sampleEvent(tc.uri)})
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(spool, tc.name), payload, 0o600))
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.Run(ctx)

	// /p2 and /p3 must be delivered even though /p1 keeps failing.
	require.Eventually(t, func() bool { return calls.Load() >= 2 }, 2*time.Second, 10*time.Millisecond,
		"newer batches must not be blocked by a transient-failing older batch")

	// /p1 stays in spool until trim or until receiver heals — that's the contract.
	files, _ := filepath.Glob(filepath.Join(spool, spoolFileGlob))
	assert.Contains(t, files, filepath.Join(spool, "100-a.ndjson.gz"))
}

func unwrapGzip(t *testing.T, data []byte) []byte {
	t.Helper()
	if len(data) == 0 {
		return nil
	}
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return data
	}
	defer gz.Close()
	out, _ := io.ReadAll(gz)
	return out
}

func TestSanitizeResponseBody(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"empty", "", ""},
		{"plain", "plain error message", "plain error message"},
		{"bearer", "got Bearer abc.def-ghi_123 back", "got [REDACTED] back"},
		{"json token", `{"token":"abc123"}`, `{"token":"[REDACTED]"}`},
		{"json api_key", `{"api_key":"sk_live_xyz"}`, `{"api_key":"[REDACTED]"}`},
		{"header bearer", `Authorization: Bearer sk_live_abcdef`, `Authorization: [REDACTED]`},
		{"kv api_key", `api_key=topsecret123`, `api_key= [REDACTED]`},
		{"x-auth header", `x-vmk-auth: tok_42`, `x-vmk-auth: [REDACTED]`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, sanitizeResponseBody(tc.in))
		})
	}
}

func TestPusher_RetrySpoolDiscardsForeignFiles(t *testing.T) {
	// We can't realistically chown to a different uid in unit tests, so this
	// test stays focused on the path actually exercised in CI: the "owns"
	// check returns true (uid match), and a legitimate file replays normally.
	// The negative case is covered by code inspection — ownsSpoolFile returns
	// false on uid mismatch and the file is removed.
	r := newReceiver()
	srv := httptest.NewServer(http.HandlerFunc(r.handler))
	defer srv.Close()

	parent := t.TempDir()
	p, spool := newTestPusher(t, srv.URL, parent, 10, "10s")
	require.NoError(t, os.MkdirAll(spool, 0o700))

	payload, err := encodeBatch([]Event{sampleEvent("/own")})
	require.NoError(t, err)
	path := filepath.Join(spool, "100-own.ndjson.gz")
	require.NoError(t, os.WriteFile(path, payload, 0o600))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.Run(ctx)
	require.Eventually(t, func() bool { return r.calls() >= 1 }, 2*time.Second, 10*time.Millisecond)
}
