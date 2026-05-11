package botlog

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/vmkteam/appkit"
	"github.com/vmkteam/embedlog"
)

const (
	sendTimeout   = 10 * time.Second
	spoolFileGlob = "*.ndjson.gz"
	spoolSuffix   = ".ndjson.gz"

	// maxTransientPerRun caps how many transient send failures retrySpool
	// tolerates in a single pass. Without a cap the oldest poison batch would
	// re-fail on every wakeup and block every newer batch behind it until
	// trimSpool evicted the old file by budget. The remaining files get a chance
	// on the next ticker tick.
	maxTransientPerRun = 3

	// eventsTotal state labels.
	stateEnqueued = "enqueued"
	stateSent     = "sent"
	stateSpooled  = "spooled"
	stateDropped  = "dropped"

	// eventsTotal{state="dropped"} reason labels. Splitting reasons lets ops
	// turn rate(events_total{state="dropped"}) alerts into actionable signals —
	// queue_full (raise BatchSize) vs permanent (fix payload) vs spool_write
	// (disk gone) vs spool_evict (raise MaxSpoolMB) are different pagers.
	dropReasonQueueFull  = "queue_full"
	dropReasonPermanent  = "permanent"
	dropReasonSpoolWrite = "spool_write"
	dropReasonSpoolEvict = "spool_evict"

	// sendErrors kind labels.
	errConnect = "connect"
	errTimeout = "timeout"
	errStatus  = "status"
)

// retryBackoff is overridable in tests; control-plane reloads are typically
// sub-second but a 5s backoff smooths systemd-restart windows without piling
// up retries.
var retryBackoff = 5 * time.Second

// httpStatusError carries the HTTP status code so callers can distinguish
// permanent failures (4xx — bad payload, bad token) from transient ones
// (5xx, network, timeout) that warrant retry. body is already sanitized:
// receivers can echo arbitrary request bytes back in errors, and that body
// will surface in logs through Error("...", "error", err) — see sanitizeResponseBody.
type httpStatusError struct {
	code int
	body string
}

func (e *httpStatusError) Error() string {
	return fmt.Sprintf("HTTP %d: %s", e.code, e.body)
}

// sanitizeResponseBody masks Bearer tokens and inline "token"/"authorization"
// values so that a misbehaving receiver echoing the request back into the
// response body cannot leak credentials into centralized logs (Loki/Kibana).
// Matches are conservative — the goal is to scrub the most common token shapes
// before they reach Error("...", "error", err), not to be a general PII scrubber.
var (
	// "Bearer xxx" anywhere — covers Authorization: Bearer xxx style headers
	// echoed back into a response. Replaced with the literal [REDACTED] so the
	// subsequent header/json regexes don't double-mask it.
	reBearerToken = regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9._\-+/=]+`)
	// JSON-style "token":"xxx" and friends. Captures the key so we can keep it.
	reJSONTokenKV = regexp.MustCompile(`(?i)"(token|api[_-]?key|authorization)"\s*:\s*"[^"]*"`)
	// Header- and querystring-style key=value / key: value. Value stops at the
	// first whitespace or structural delimiter. Skipped when the value is the
	// literal sentinel left by reBearerToken or reJSONTokenKV.
	reHeaderTokenKV = regexp.MustCompile(`(?i)(token|api[_-]?key|x-[a-z-]*auth[a-z-]*)\s*([:=])\s*([^\s,;}"]+)`)
)

func sanitizeResponseBody(body string) string {
	if body == "" {
		return body
	}
	body = reBearerToken.ReplaceAllString(body, "[REDACTED]")
	body = reJSONTokenKV.ReplaceAllString(body, `"$1":"[REDACTED]"`)
	body = reHeaderTokenKV.ReplaceAllStringFunc(body, func(m string) string {
		groups := reHeaderTokenKV.FindStringSubmatch(m)
		if len(groups) < 4 {
			return m
		}
		// Already scrubbed — don't double-mask.
		if groups[3] == "[REDACTED]" {
			return m
		}
		return groups[1] + groups[2] + " [REDACTED]"
	})
	return body
}

// isPermanentFailure reports whether the receiver explicitly rejected the
// batch and retrying would not change the outcome. 408 (request timeout) and
// 429 (rate limit) are 4xx but transient, so we retry those.
func isPermanentFailure(err error) bool {
	var se *httpStatusError
	if !errors.As(err, &se) {
		return false
	}
	if se.code < 400 || se.code >= 500 {
		return false
	}
	return se.code != http.StatusRequestTimeout && se.code != http.StatusTooManyRequests
}

// gzipPool reuses gzip writers across flushes — gzip.NewWriter allocates ~256 KB
// of internal buffers, which adds up at 5s flush cadence.
var gzipPool = sync.Pool{
	New: func() any { return gzip.NewWriter(io.Discard) },
}

// bufPool reuses raw and compressed buffers between flushes.
var bufPool = sync.Pool{
	New: func() any { return new(bytes.Buffer) },
}

// Pusher batches bot-log events and ships them as gzipped ndjson to the
// topsrv.io ingest endpoint.
// On send failure the batch is written to SpoolDir/botlog/ for retry — see
// retrySpool. The pusher runs as a single goroutine started by Run.
//
// Per-event memory: an Event header is ~16 string headers + numeric fields
// (~200 B), plus referenced string contents (URI/UA/Referer). With realistic
// payloads ~800 B/event; queue cap of BatchSize*2 keeps ≤ ~8 MB resident at
// the 5000-event default.
type Pusher struct {
	embedlog.Logger

	cfg    Config
	client *http.Client
	queue  chan Event

	eventsTotal *prometheus.CounterVec // state=enqueued|sent|spooled|dropped, reason=queue_full|permanent|spool_write|spool_evict|""
	matchTotal  *prometheus.CounterVec // family
	sendErrors  *prometheus.CounterVec // kind=connect|timeout|status
	batchDur    prometheus.Histogram
	spoolFiles  prometheus.Gauge
	spoolBytes  prometheus.Gauge
	queueDepth  prometheus.GaugeFunc
}

// NewPusher constructs a Pusher with metrics registered against reg. cfg must
// already be Validate'd.
func NewPusher(logger embedlog.Logger, appName, version string, cfg Config, reg prometheus.Registerer) *Pusher {
	p := &Pusher{
		Logger: logger,
		cfg:    cfg,
		client: appkit.NewHTTPClient(appName, version, sendTimeout),
		queue:  make(chan Event, cfg.BatchSize*2),

		eventsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "topsrv_botlog_events_total",
			Help: "Bot-log events by lifecycle state and (for dropped) reason. " +
				"Reasons: queue_full|permanent|spool_write|spool_evict. Other states emit reason=\"\".",
		}, []string{"state", "reason"}),
		matchTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "topsrv_botlog_match_total",
			Help: "Bot-log UA matches by family — incremented as observer sees a line.",
		}, []string{"family"}),
		sendErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "topsrv_botlog_send_errors_total",
			Help: "Failed bot-log ingest requests by kind.",
		}, []string{"kind"}),
		batchDur: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "topsrv_botlog_batch_duration_seconds",
			Help:    "End-to-end batch flush latency (encode + send).",
			Buckets: prometheus.DefBuckets,
		}),
		spoolFiles: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "topsrv_botlog_spool_files",
			Help: "Pending spool files awaiting retry.",
		}),
		spoolBytes: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "topsrv_botlog_spool_bytes",
			Help: "Disk bytes used by the spool subdir.",
		}),
	}
	// queueDepth reads len(queue) at scrape time. Closing over p so the gauge
	// stays in sync with channel state without a periodic sampler. Useful as an
	// early backpressure signal — alert on depth > 0.7 * cap to predict drops.
	p.queueDepth = prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "topsrv_botlog_queue_depth",
		Help: "Current number of events buffered in the send queue.",
	}, func() float64 { return float64(len(p.queue)) })
	reg.MustRegister(p.eventsTotal, p.matchTotal, p.sendErrors, p.batchDur, p.spoolFiles, p.spoolBytes, p.queueDepth)
	return p
}

// RecordMatch ticks topsrv_botlog_match_total{family=...}. Called by the observer
// once per UA match. Keeps the CounterVec encapsulated.
func (p *Pusher) RecordMatch(family string) {
	p.matchTotal.WithLabelValues(family).Inc()
}

// Enqueue adds ev to the send queue. Non-blocking: when the queue is full the
// event is dropped and topsrv_botlog_events_total{state="dropped"} ticks.
// Drop-newest is intentional — we prefer to keep older events that may already
// be in a partially-formed batch over the newer ones that would block a tail
// goroutine.
func (p *Pusher) Enqueue(ev Event) {
	select {
	case p.queue <- ev:
		p.eventsTotal.WithLabelValues(stateEnqueued, "").Inc()
	default:
		p.eventsTotal.WithLabelValues(stateDropped, dropReasonQueueFull).Inc()
	}
}

// Run pumps the queue: flushes whenever the batch hits BatchSize or interval
// fires. Replays any spooled payloads on startup. Blocks until ctx is cancelled,
// then drains the queue and flushes one last time.
func (p *Pusher) Run(ctx context.Context) {
	interval := p.cfg.ParsedBatchInterval()
	p.Print(ctx, "botlog: started", "endpoint", p.cfg.Endpoint, "interval", interval, "batchSize", p.cfg.BatchSize)
	p.refreshSpoolMetrics()
	p.retrySpool(ctx)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	batch := make([]Event, 0, p.cfg.BatchSize)

	for {
		select {
		case <-ctx.Done():
			batch = p.drainQueue(batch)
			p.flush(context.Background(), batch)
			p.Print(context.Background(), "botlog: stopped", "drained", len(batch))
			return
		case ev := <-p.queue:
			batch = append(batch, ev)
			if len(batch) >= p.cfg.BatchSize {
				p.flush(ctx, batch)
				batch = batch[:0]
			}
		case <-ticker.C:
			p.retrySpool(ctx)
			if len(batch) > 0 {
				p.flush(ctx, batch)
				batch = batch[:0]
			}
		}
	}
}

// drainQueue appends every event still buffered in the queue.
func (p *Pusher) drainQueue(batch []Event) []Event {
	for {
		select {
		case ev := <-p.queue:
			batch = append(batch, ev)
		default:
			return batch
		}
	}
}

func (p *Pusher) flush(ctx context.Context, batch []Event) {
	if len(batch) == 0 {
		return
	}
	start := time.Now()
	defer func() { p.batchDur.Observe(time.Since(start).Seconds()) }()

	payload, err := encodeBatch(batch)
	if err != nil {
		p.Error(ctx, "botlog: encode failed", "error", err, "events", len(batch))
		return
	}

	batchID := newBatchID()
	if err := p.sendWithRetry(ctx, payload, batchID); err != nil {
		if isPermanentFailure(err) {
			p.Error(ctx, "botlog: batch permanently rejected, dropping", "error", err, "events", len(batch), "batchId", batchID)
			p.eventsTotal.WithLabelValues(stateDropped, dropReasonPermanent).Add(float64(len(batch)))
			return
		}
		p.Error(ctx, "botlog: send failed, spooling", "error", err, "events", len(batch), "batchId", batchID)
		p.spool(ctx, payload, batchID)
		return
	}
	p.eventsTotal.WithLabelValues(stateSent, "").Add(float64(len(batch)))
}

func (p *Pusher) sendWithRetry(ctx context.Context, payload []byte, batchID string) error {
	err := p.send(ctx, payload, batchID)
	if err == nil {
		return nil
	}
	if isPermanentFailure(err) {
		return err // retry would only repeat the same 4xx
	}
	// One retry with a fixed backoff — the server could be momentarily reloading.
	t := time.NewTimer(retryBackoff)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return err
	case <-t.C:
	}
	return p.send(ctx, payload, batchID)
}

func (p *Pusher) send(ctx context.Context, payload []byte, batchID string) error {
	ctx, cancel := context.WithTimeout(ctx, sendTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.cfg.Endpoint, bytes.NewReader(payload))
	if err != nil {
		p.sendErrors.WithLabelValues(errConnect).Inc()
		return err
	}
	req.Header.Set("Content-Type", "application/x-ndjson")
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("Authorization", "Bearer "+p.cfg.Token)
	req.Header.Set("X-Batch-Id", batchID)

	resp, err := p.client.Do(req)
	if err != nil {
		p.sendErrors.WithLabelValues(classifyErr(err)).Inc()
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		p.sendErrors.WithLabelValues(errStatus).Inc()
		// Sanitize before storing: the error chain ends up in centralized logs,
		// and a misbehaving receiver could echo Authorization bytes back.
		return &httpStatusError{code: resp.StatusCode, body: sanitizeResponseBody(string(body))}
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

// spool persists a failed batch under SpoolDir/<batchID>.ndjson.gz. The subdir
// is created lazily so a host without WAL configured silently drops on failure.
//
// Permissions: 0o700 on the directory and 0o600 on each batch file. Tight by
// design — retrySpool replays anything matching the glob with a valid Bearer
// token, so an attacker with write access to SpoolDir could otherwise forge
// ingest events for this host. Document the requirement in your deployment:
// the SpoolDir parent and the directory itself should both be owned by the
// topsrv user and not world-writable.
func (p *Pusher) spool(ctx context.Context, payload []byte, batchID string) {
	if p.cfg.SpoolDir == "" {
		p.eventsTotal.WithLabelValues(stateDropped, dropReasonSpoolWrite).Inc()
		return
	}
	if err := os.MkdirAll(p.cfg.SpoolDir, 0o700); err != nil {
		p.Error(ctx, "botlog: spool mkdir failed", "dir", p.cfg.SpoolDir, "error", err)
		p.eventsTotal.WithLabelValues(stateDropped, dropReasonSpoolWrite).Inc()
		return
	}

	path := filepath.Join(p.cfg.SpoolDir, batchID+spoolSuffix)
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		p.Error(ctx, "botlog: spool write failed", "path", path, "error", err)
		p.eventsTotal.WithLabelValues(stateDropped, dropReasonSpoolWrite).Inc()
		return
	}

	p.eventsTotal.WithLabelValues(stateSpooled, "").Inc()
	p.trimSpool(ctx)
}

// retrySpool replays spooled batches oldest-first.
//
//   - Transient failures (5xx, network, timeout) skip the file and continue —
//     capped at maxTransientPerRun per pass so a flapping receiver isn't hammered
//     while newer batches still get a chance. Without this cap a poison batch
//     repeatedly rejected by the receiver would block every newer batch behind
//     it until trimSpool evicted the old file by budget.
//   - Permanent failures (4xx) delete the file and continue — otherwise one
//     corrupted batch would block the queue until trim evicts it.
//   - Unreadable files and files not owned by the current process user are
//     removed: the second case prevents a local attacker who can write into
//     SpoolDir from forging ingest events under this host's Bearer token.
func (p *Pusher) retrySpool(ctx context.Context) {
	if p.cfg.SpoolDir == "" {
		return
	}
	files, err := filepath.Glob(filepath.Join(p.cfg.SpoolDir, spoolFileGlob))
	if err != nil || len(files) == 0 {
		return
	}
	sort.Strings(files) // names are unix-ms-prefixed → ascending == oldest first

	sent, transientFails := 0, 0
	for _, path := range files {
		if transientFails >= maxTransientPerRun {
			break
		}
		if !p.ownsSpoolFile(ctx, path) {
			// Foreign file in our spool: someone else wrote it. Refuse to forward
			// arbitrary content with our token and remove it so the alert chain
			// fires (spool_evict ticks, files gauge stays accurate).
			_ = os.Remove(path)
			p.eventsTotal.WithLabelValues(stateDropped, dropReasonSpoolEvict).Inc()
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			_ = os.Remove(path)
			continue
		}
		batchID := batchIDFromPath(path)
		if err := p.send(ctx, data, batchID); err != nil {
			if isPermanentFailure(err) {
				p.Error(ctx, "botlog: spooled batch rejected, discarding", "path", path, "error", err)
				_ = os.Remove(path)
				continue
			}
			transientFails++
			continue // transient — skip but try the next file
		}
		_ = os.Remove(path)
		sent++
	}
	if sent > 0 {
		p.Print(ctx, "botlog: resent spooled batches", "count", sent)
	}
	p.refreshSpoolMetrics()
}

// scanSpool returns the spool files sorted oldest-first along with their sizes
// and total disk usage. Single os.Stat pass shared by trim and metric refresh.
func (p *Pusher) scanSpool() (files []string, sizes []int64, total int64) {
	if p.cfg.SpoolDir == "" {
		return nil, nil, 0
	}
	matched, err := filepath.Glob(filepath.Join(p.cfg.SpoolDir, spoolFileGlob))
	if err != nil || len(matched) == 0 {
		return nil, nil, 0
	}
	sort.Strings(matched)
	sizes = make([]int64, len(matched))
	for i, f := range matched {
		if st, err := os.Stat(f); err == nil {
			sizes[i] = st.Size()
			total += st.Size()
		}
	}
	return matched, sizes, total
}

func (p *Pusher) setSpoolGauges(files []string, total int64) {
	p.spoolFiles.Set(float64(len(files)))
	p.spoolBytes.Set(float64(total))
}

// trimSpool removes oldest files until disk usage <= MaxSpoolMB.
func (p *Pusher) trimSpool(ctx context.Context) {
	files, sizes, total := p.scanSpool()
	budget := int64(p.cfg.MaxSpoolMB) * 1024 * 1024
	if total <= budget {
		p.setSpoolGauges(files, total)
		return
	}
	for i, f := range files {
		if total <= budget {
			break
		}
		if err := os.Remove(f); err != nil {
			continue
		}
		total -= sizes[i]
		// One increment per evicted file, not per event — exact event count is
		// unknown without re-reading the gzip. Operators alerting on
		// {reason="spool_evict"} should treat the rate as "files evicted".
		p.eventsTotal.WithLabelValues(stateDropped, dropReasonSpoolEvict).Inc()
	}
	p.Print(ctx, "botlog: spool trimmed", "remainingBytes", total, "budget", budget)

	// Re-scan: file count shifted; sizes already accounted for so we only need
	// the gauges in sync with the post-trim directory.
	post, _, postTotal := p.scanSpool()
	p.setSpoolGauges(post, postTotal)
}

func (p *Pusher) refreshSpoolMetrics() {
	files, _, total := p.scanSpool()
	p.setSpoolGauges(files, total)
}

// encodeBatch serializes events as gzipped ndjson. One JSON object per line,
// trailing newline included so partial reads on the receiver are easy.
// gzip writer and the output buffer come from pools — at default 5s flush
// cadence the per-batch allocation dominates the steady-state heap otherwise.
func encodeBatch(batch []Event) ([]byte, error) {
	out, _ := bufPool.Get().(*bytes.Buffer)
	out.Reset()
	defer bufPool.Put(out)

	gz, _ := gzipPool.Get().(*gzip.Writer)
	gz.Reset(out)
	defer gzipPool.Put(gz)

	for i := range batch {
		line, err := json.Marshal(&batch[i])
		if err != nil {
			return nil, fmt.Errorf("marshal: %w", err)
		}
		if _, err := gz.Write(line); err != nil {
			return nil, fmt.Errorf("gzip: %w", err)
		}
		if _, err := gz.Write([]byte{'\n'}); err != nil {
			return nil, fmt.Errorf("gzip: %w", err)
		}
	}
	if err := gz.Close(); err != nil {
		return nil, fmt.Errorf("gzip close: %w", err)
	}

	// Copy out so the caller owns the bytes after the buffer goes back to the pool.
	payload := make([]byte, out.Len())
	copy(payload, out.Bytes())
	return payload, nil
}

// newBatchID is "<unix-ms>-<8 random hex bytes>" — timestamp-ordered for stable
// spool replay, random suffix prevents collisions when multiple flushes happen
// in the same millisecond. Avoids pulling in google/uuid.
func newBatchID() string {
	var rnd [8]byte
	_, _ = rand.Read(rnd[:])
	return fmt.Sprintf("%d-%s", time.Now().UnixMilli(), hex.EncodeToString(rnd[:]))
}

func batchIDFromPath(path string) string {
	return strings.TrimSuffix(filepath.Base(path), spoolSuffix)
}

func classifyErr(err error) string {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "timeout"
	}
	return "connect"
}

// ownsSpoolFile reports whether path is owned by the current process user.
// Used by retrySpool to refuse forwarding foreign files under the agent's
// Bearer token — a local attacker with write access to SpoolDir could
// otherwise stage arbitrary gzipped ndjson and have it ingested as if it came
// from this host. Errors and unknown platforms fail closed (return false): we
// prefer to drop a possibly-legitimate batch over leaking the token's trust.
func (p *Pusher) ownsSpoolFile(ctx context.Context, path string) bool {
	fi, err := os.Stat(path)
	if err != nil {
		return false
	}
	uid, ok := fileUID(fi)
	if !ok {
		// Platforms without a usable Stat_t (e.g. Windows): we have no cheap
		// way to enforce ownership, so trust the directory's filesystem perms.
		return true
	}
	if uid == os.Getuid() {
		return true
	}
	p.Error(ctx, "botlog: spool file not owned by agent user, discarding", "path", path, "fileUID", uid, "agentUID", os.Getuid())
	return false
}
