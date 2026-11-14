package shipper

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
	"sync"
	"time"

	"github.com/vmkteam/topsrv/internal/topsrv/spool"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/vmkteam/appkit"
	"github.com/vmkteam/embedlog"
)

// Delivery defaults, applied by NewPusher when a stream leaves them zero.
const (
	DefaultBatchSize     = 5000
	DefaultBatchInterval = 30 * time.Second
	DefaultMaxSpoolMB    = 200
)

const (
	// Single-attempt deadline for one HTTP send. The shutdown path uses
	// flushFinal which performs exactly one send, so the relevant invariant is
	// app.shutdownTimeout ≥ shutdownDrainBudget + slack. Steady-state retries
	// are bounded by sendWithRetry (sendTimeout + retryBackoff + sendTimeout)
	// and must not run on shutdown — see flushFinal.
	sendTimeout = 10 * time.Second

	// Total budget for draining the queue on shutdown. With queue cap =
	// BatchSize*2 the drain loop can call flushFinal twice; each first send
	// is bounded by sendTimeout. 12s leaves ~3s margin within
	// app.shutdownTimeout (15s) for spool writes and closers.
	shutdownDrainBudget = 12 * time.Second

	spoolExt = ".ndjson.gz"

	// errBodyDrainCap bounds the bytes we discard from a 4xx/5xx response body.
	// Reads up to this many bytes to keep the connection eligible for keep-alive
	// reuse, then drops the rest by closing the connection.
	errBodyDrainCap = 64 * 1024

	// eventsTotal state labels.
	stateEnqueued = "enqueued"
	stateSent     = "sent"
	stateSpooled  = "spooled"
	stateDropped  = "dropped"

	// eventsTotal{state="dropped"} reason labels. Distinct reasons keep
	// rate(...{state="dropped"}) alerts actionable: queue_full → raise BatchSize,
	// permanent → fix payload, spool_write → disk, spool_evict → raise MaxSpoolMB.
	dropReasonQueueFull  = "queue_full"
	dropReasonPermanent  = "permanent"
	dropReasonSpoolWrite = "spool_write"
	dropReasonSpoolEvict = "spool_evict"

	// sendErrors kind labels.
	errConnect = "connect"
	errTimeout = "timeout"
	errStatus  = "status"
)

// defaultRetryBackoff smooths receiver restart windows. Tests shorten it per
// Pusher rather than package-wide: a Pusher outlives the test that built it
// until its Run goroutine is joined, so a shared variable is read by one
// test's flush while the next test writes it.
const defaultRetryBackoff = 5 * time.Second

// maxTransientPerRun caps how many spool replays may fail transiently in one
// retrySpool pass — without it, a poison oldest file blocks every newer batch
// until trim evicts it.
const maxTransientPerRun = 3

// gzipPool reuses gzip writers across flushes — gzip.NewWriter allocates ~256 KB
// of internal buffers, which adds up at the default flush cadence.
var gzipPool = sync.Pool{
	New: func() any { return gzip.NewWriter(io.Discard) },
}

// bufPool reuses raw and compressed buffers between flushes.
var bufPool = sync.Pool{
	New: func() any { return new(bytes.Buffer) },
}

// Options carries the delivery parameters. The stream owning a Pusher supplies
// them; everything else in its config (UA patterns, field aliases, log paths)
// is none of the shipper's business.
//
// MetricPrefix is what makes two streams coexist in one process: prometheus
// refuses duplicate metric names, and the bot-log names are load-bearing for
// existing dashboards, so they must stay byte-for-byte as they were. It names
// the stream in log lines too — a spool failure has to say which stream lost
// its batch, and with one shipper serving both, a hardcoded name would put
// every web-log failure under the bot stream.
type Options struct {
	MetricPrefix  string // "topsrv_botlog" | "topsrv_weblog"
	MetricSubject string // human-readable subject for Help strings, e.g. "Bot-log"
	Endpoint      string
	Token         string
	BatchSize     int
	BatchInterval time.Duration
	SpoolDir      string // already includes the per-stream subdirectory
	MaxSpoolMB    int
}

// Pusher batches events of one stream and ships them as gzipped ndjson to the
// topsrv.io ingest endpoint.
// On send failure the batch is written to SpoolDir for retry — see
// retrySpool. The pusher runs as a single goroutine started by Run.
//
// Per-event memory: an Event header is ~16 string headers + numeric fields
// (~200 B), plus referenced string contents (URI/UA/Referer). With realistic
// payloads ~800 B/event; queue cap of BatchSize*2 keeps ≤ ~8 MB resident at
// the 5000-event default.
type Pusher struct {
	embedlog.Logger

	cfg    Options
	client *http.Client
	queue  chan Event
	dir    spool.Dir // SpoolDir, <batchID>.ndjson.gz

	// Fixed at construction; only tests give it another value.
	retryBackoff time.Duration

	eventsTotal *prometheus.CounterVec
	sendErrors  *prometheus.CounterVec // kind=connect|timeout|status
	batchDur    prometheus.Histogram
	spoolFiles  prometheus.Gauge
	spoolBytes  prometheus.Gauge

	// Pre-resolved at construction so call sites avoid the WithLabelValues
	// lookup (RLock + hash + map probe). Kept symmetric across all states/reasons
	// so adding a new event point doesn't reintroduce string literals.
	cEnqueued, cSent, cSpooled                                  prometheus.Counter
	cDropQueueFull, cDropPermanent, cDropSpoolWrite, cDropEvict prometheus.Counter
}

// NewPusher constructs a Pusher with metrics registered against reg. cfg must
// already be Validate'd.
func NewPusher(logger embedlog.Logger, appName, version string, cfg Options, reg prometheus.Registerer) *Pusher {
	// Delivery defaults belong to delivery: a stream that omits them gets a
	// working shipper, not a silently disabled spool (MaxSpoolMB = 0 evicts
	// every file it just wrote) or a zero-capacity queue.
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = DefaultBatchSize
	}
	if cfg.BatchInterval <= 0 {
		cfg.BatchInterval = DefaultBatchInterval
	}
	if cfg.MaxSpoolMB <= 0 {
		cfg.MaxSpoolMB = DefaultMaxSpoolMB
	}

	p := &Pusher{
		Logger: logger,
		cfg:    cfg,
		client: appkit.NewHTTPClient(appName, version, sendTimeout),
		queue:  make(chan Event, cfg.BatchSize*2),
		dir:    spool.Dir{Path: cfg.SpoolDir, Ext: spoolExt},

		retryBackoff: defaultRetryBackoff,

		eventsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: cfg.MetricPrefix + "_events_total",
			Help: cfg.MetricSubject + " events by lifecycle state. " +
				"For state=dropped, reason ∈ {queue_full, permanent, spool_write, spool_evict}; otherwise reason=\"\".",
		}, []string{"state", "reason"}),
		sendErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: cfg.MetricPrefix + "_send_errors_total",
			Help: "Failed " + cfg.MetricSubject + " ingest requests by kind.",
		}, []string{"kind"}),
		batchDur: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    cfg.MetricPrefix + "_batch_duration_seconds",
			Help:    "End-to-end batch flush latency (encode + send).",
			Buckets: prometheus.DefBuckets,
		}),
		spoolFiles: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: cfg.MetricPrefix + "_spool_files",
			Help: "Pending spool files awaiting retry.",
		}),
		spoolBytes: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: cfg.MetricPrefix + "_spool_bytes",
			Help: "Disk bytes used by the spool subdir.",
		}),
	}
	p.cEnqueued = p.eventsTotal.WithLabelValues(stateEnqueued, "")
	p.cSent = p.eventsTotal.WithLabelValues(stateSent, "")
	p.cSpooled = p.eventsTotal.WithLabelValues(stateSpooled, "")
	p.cDropQueueFull = p.eventsTotal.WithLabelValues(stateDropped, dropReasonQueueFull)
	p.cDropPermanent = p.eventsTotal.WithLabelValues(stateDropped, dropReasonPermanent)
	p.cDropSpoolWrite = p.eventsTotal.WithLabelValues(stateDropped, dropReasonSpoolWrite)
	p.cDropEvict = p.eventsTotal.WithLabelValues(stateDropped, dropReasonSpoolEvict)

	queueDepth := prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: cfg.MetricPrefix + "_queue_depth",
		Help: "Current number of events buffered in the send queue. Alert on depth > 0.7*cap to predict drops.",
	}, func() float64 { return float64(len(p.queue)) })
	reg.MustRegister(p.eventsTotal, p.sendErrors, p.batchDur, p.spoolFiles, p.spoolBytes, queueDepth)
	return p
}

// Enqueue adds ev to the send queue. Non-blocking: when the queue is full the
// event is dropped and topsrv_botlog_events_total{state="dropped"} ticks.
// Drop-newest is intentional — we prefer to keep older events that may already
// be in a partially-formed batch over the newer ones that would block a tail
// goroutine.
func (p *Pusher) Enqueue(ev Event) {
	select {
	case p.queue <- ev:
		p.cEnqueued.Inc()
	default:
		p.cDropQueueFull.Inc()
	}
}

// Run pumps the queue: flushes whenever the batch hits BatchSize or interval
// fires. Replays any spooled payloads on startup. Blocks until ctx is cancelled,
// then drains the queue and flushes one last time.
func (p *Pusher) Run(ctx context.Context) {
	interval := p.cfg.BatchInterval
	p.Print(ctx, p.cfg.MetricPrefix+": shipper started",
		"endpoint", p.cfg.Endpoint, "interval", interval, "batchSize", p.cfg.BatchSize)
	if n := p.dir.CleanupTmp(); n > 0 {
		p.Print(ctx, p.cfg.MetricPrefix+": cleaned up stale spool tmp files", "count", n)
	}
	p.refreshSpoolMetrics()
	p.retrySpool(ctx)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	batch := make([]Event, 0, p.cfg.BatchSize)

	for {
		select {
		case <-ctx.Done():
			total := p.drainAndFlushAll(batch)
			p.Print(context.Background(), p.cfg.MetricPrefix+": stopped", "drained", total)
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

// drainQueue appends queued events into batch up to BatchSize. Capping at
// BatchSize preserves the per-batch contract on shutdown — without it the
// queue (cap BatchSize*2) could overflow a receiver-side hard limit.
func (p *Pusher) drainQueue(batch []Event) []Event {
	for len(batch) < p.cfg.BatchSize {
		select {
		case ev := <-p.queue:
			batch = append(batch, ev)
		default:
			return batch
		}
	}
	return batch
}

func (p *Pusher) flush(ctx context.Context, batch []Event) {
	if len(batch) == 0 {
		return
	}
	start := time.Now()
	defer func() { p.batchDur.Observe(time.Since(start).Seconds()) }()

	payload, err := encodeBatch(batch)
	if err != nil {
		p.Error(ctx, p.cfg.MetricPrefix+": encode failed", "error", err, "events", len(batch))
		return
	}

	batchID := newBatchID()
	if err := p.sendWithRetry(ctx, payload, batchID); err != nil {
		if !spool.Retryable(err) {
			p.Error(ctx, p.cfg.MetricPrefix+": batch permanently rejected, dropping", "error", err, "events", len(batch), "batchId", batchID)
			p.cDropPermanent.Add(float64(len(batch)))
			return
		}
		p.Error(ctx, p.cfg.MetricPrefix+": send failed, spooling", "error", err, "events", len(batch), "batchId", batchID)
		p.spool(ctx, payload, batchID)
		return
	}
	p.cSent.Add(float64(len(batch)))
}

// drainAndFlushAll is the shutdown path: pull every queued event out and ship
// it through flushFinal in BatchSize-sized chunks so a receiver-side per-batch
// cap is respected. A single shutdownDrainBudget is shared across all chunks;
// after it elapses, flushFinal sends nothing and spools directly.
func (p *Pusher) drainAndFlushAll(batch []Event) int {
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownDrainBudget)
	defer cancel()

	total := 0
	for {
		batch = p.drainQueue(batch)
		if len(batch) == 0 {
			return total
		}
		total += len(batch)
		p.flushFinal(shutdownCtx, batch)
		batch = batch[:0]
	}
}

// flushFinal is flush without retry: one send under shutdownCtx, otherwise
// spool. shutdownCtx is shared across the drain loop so once it elapses,
// remaining batches skip the send and go straight to spool with a fresh ctx.
func (p *Pusher) flushFinal(shutdownCtx context.Context, batch []Event) {
	if len(batch) == 0 {
		return
	}
	start := time.Now()
	defer func() { p.batchDur.Observe(time.Since(start).Seconds()) }()

	payload, err := encodeBatch(batch)
	if err != nil {
		p.Error(context.Background(), p.cfg.MetricPrefix+": encode failed", "error", err, "events", len(batch))
		return
	}
	batchID := newBatchID()

	if shutdownCtx.Err() != nil {
		p.spool(context.Background(), payload, batchID)
		return
	}
	sendCtx, cancel := context.WithTimeout(shutdownCtx, sendTimeout)
	err = p.send(sendCtx, payload, batchID)
	cancel()
	if err == nil {
		p.cSent.Add(float64(len(batch)))
		return
	}
	if !spool.Retryable(err) {
		p.Error(shutdownCtx, p.cfg.MetricPrefix+": shutdown batch permanently rejected, dropping", "error", err, "events", len(batch), "batchId", batchID)
		p.cDropPermanent.Add(float64(len(batch)))
		return
	}
	p.Error(shutdownCtx, p.cfg.MetricPrefix+": shutdown send failed, spooling", "error", err, "events", len(batch), "batchId", batchID)
	p.spool(context.Background(), payload, batchID)
}

func (p *Pusher) sendWithRetry(ctx context.Context, payload []byte, batchID string) error {
	err := p.send(ctx, payload, batchID)
	if err == nil {
		return nil
	}
	if !spool.Retryable(err) || authFailed(err) {
		// A rejection would only repeat the same 4xx. A token problem lasts
		// until the config is fixed and the agent restarted — the token is
		// read once at startup — so waiting here would only stall the queue.
		return err
	}
	// One retry with a fixed backoff — the server could be momentarily reloading.
	t := time.NewTimer(p.retryBackoff)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return err
	case <-t.C:
	}
	return p.send(ctx, payload, batchID)
}

// authFailed reports a 401/403. The batch belongs in the spool, but an
// immediate retry with the same token cannot succeed.
func authFailed(err error) bool {
	var se *spool.StatusError
	return errors.As(err, &se) && (se.Code == http.StatusUnauthorized || se.Code == http.StatusForbidden)
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
		// Cap the discarded read so a hostile receiver can't make us pull MBs.
		// Anything past the cap is fine to leave for the keep-alive teardown —
		// Go's transport will close the connection rather than reuse it.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, errBodyDrainCap))
		p.sendErrors.WithLabelValues(errStatus).Inc()
		// No body in the error: a misbehaving receiver could echo credentials
		// back, and they would surface in centralized logs.
		return &spool.StatusError{Code: resp.StatusCode}
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

// spool persists a failed batch as SpoolDir/<batchID>.ndjson.gz.
func (p *Pusher) spool(ctx context.Context, payload []byte, batchID string) {
	if p.cfg.SpoolDir == "" {
		p.cDropSpoolWrite.Inc()
		return
	}
	if err := p.dir.Write(batchID, payload); err != nil {
		p.Error(ctx, p.cfg.MetricPrefix+": spool write failed", "dir", p.cfg.SpoolDir, "batchId", batchID, "error", err)
		p.cDropSpoolWrite.Inc()
		return
	}
	p.cSpooled.Inc()
	p.trimSpool(ctx)
}

// retrySpool replays spooled batches oldest first. Up to maxTransientPerRun
// transient failures are skipped per pass, so a poison oldest batch can't
// stall newer ones until trim evicts it. Rejected batches are discarded;
// entries that are not regular files of the agent's user are removed unsent
// rather than forwarded under our Bearer token.
func (p *Pusher) retrySpool(ctx context.Context) {
	res := p.dir.Replay(spool.Policy{MaxTransient: maxTransientPerRun}, func(batchID string, payload []byte) error {
		return p.send(ctx, payload, batchID)
	})
	for _, r := range res.Rejected {
		p.Error(ctx, p.cfg.MetricPrefix+": spooled batch rejected, discarding", "batchId", r.Name, "error", r.Err)
	}
	if res.Dropped > 0 {
		p.Error(ctx, p.cfg.MetricPrefix+": removed unsent spool entries that are foreign or unreadable", "count", res.Dropped)
		p.cDropEvict.Add(float64(res.Dropped))
	}
	if res.Sent > 0 {
		p.Print(ctx, p.cfg.MetricPrefix+": resent spooled batches", "count", res.Sent)
	}
	if res.Sent+len(res.Rejected)+res.Dropped > 0 { // the spool shrank
		p.refreshSpoolMetrics()
	}
}

// trimSpool removes the oldest files until disk usage fits MaxSpoolMB.
func (p *Pusher) trimSpool(ctx context.Context) {
	budget := int64(p.cfg.MaxSpoolMB) * 1024 * 1024
	if n := p.dir.TrimBytes(budget); n > 0 {
		// One increment per evicted file, not per event — exact event count is
		// unknown without re-reading the gzip. Operators alerting on
		// {reason="spool_evict"} should treat the rate as "files evicted".
		p.cDropEvict.Add(float64(n))
		p.Print(ctx, p.cfg.MetricPrefix+": spool trimmed", "evicted", n, "budget", budget)
	}
	p.refreshSpoolMetrics()
}

func (p *Pusher) refreshSpoolMetrics() {
	files, size := p.dir.Usage()
	p.spoolFiles.Set(float64(files))
	p.spoolBytes.Set(float64(size))
}

// encodeBatch serializes events as gzipped ndjson. One JSON object per line,
// trailing newline included so partial reads on the receiver are easy.
// newline separates ndjson records. Package-level so the write does not
// allocate a one-byte slice per event.
var newline = []byte{'\n'} //nolint:gochecknoglobals // immutable

// gzip writer and the output buffer come from pools — at default 5s flush
// cadence the per-batch allocation dominates the steady-state heap otherwise.
func encodeBatch(batch []Event) ([]byte, error) {
	out, _ := bufPool.Get().(*bytes.Buffer)
	out.Reset()
	defer bufPool.Put(out)

	gz, _ := gzipPool.Get().(*gzip.Writer)
	gz.Reset(out)
	defer gzipPool.Put(gz)

	// MarshalWrite streams straight into the gzip writer. Marshal + Write would
	// allocate a throwaway []byte per event — at one event per request that is
	// ~10k allocations and 3.5 MB of garbage for a single default-sized batch.
	for i := range batch {
		if err := json.MarshalWrite(gz, &batch[i]); err != nil {
			return nil, fmt.Errorf("marshal: %w", err)
		}
		if _, err := gz.Write(newline); err != nil {
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

func classifyErr(err error) string {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "timeout"
	}
	return "connect"
}
