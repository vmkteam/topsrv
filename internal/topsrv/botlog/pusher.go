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
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/vmkteam/appkit"
	"github.com/vmkteam/embedlog"
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

	spoolFileGlob = "*.ndjson.gz"
	spoolSuffix   = ".ndjson.gz"
	spoolTmpGlob  = "*" + spoolSuffix + ".tmp"

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

// retryBackoff is overridable in tests; production smooths restart windows.
var retryBackoff = 5 * time.Second

// maxTransientPerRun caps how many spool replays may fail transiently in one
// retrySpool pass — without it, a poison oldest file blocks every newer batch
// until trim evicts it.
const maxTransientPerRun = 3

// httpStatusError lets callers distinguish permanent (4xx) from transient
// (5xx, net, timeout) failures. Body content is intentionally omitted —
// a misbehaving receiver could echo credentials back and they would surface
// in centralized logs. The receiver-side log is the source of truth for body.
type httpStatusError struct {
	code    int
	bodyLen int
}

func (e *httpStatusError) Error() string {
	return fmt.Sprintf("HTTP %d (body %d bytes)", e.code, e.bodyLen)
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

	eventsTotal *prometheus.CounterVec
	matchTotal  *prometheus.CounterVec // family
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
func NewPusher(logger embedlog.Logger, appName, version string, cfg Config, reg prometheus.Registerer) *Pusher {
	p := &Pusher{
		Logger: logger,
		cfg:    cfg,
		client: appkit.NewHTTPClient(appName, version, sendTimeout),
		queue:  make(chan Event, cfg.BatchSize*2),

		eventsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "topsrv_botlog_events_total",
			Help: "Bot-log events by lifecycle state. " +
				"For state=dropped, reason ∈ {queue_full, permanent, spool_write, spool_evict}; otherwise reason=\"\".",
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
	p.cEnqueued = p.eventsTotal.WithLabelValues(stateEnqueued, "")
	p.cSent = p.eventsTotal.WithLabelValues(stateSent, "")
	p.cSpooled = p.eventsTotal.WithLabelValues(stateSpooled, "")
	p.cDropQueueFull = p.eventsTotal.WithLabelValues(stateDropped, dropReasonQueueFull)
	p.cDropPermanent = p.eventsTotal.WithLabelValues(stateDropped, dropReasonPermanent)
	p.cDropSpoolWrite = p.eventsTotal.WithLabelValues(stateDropped, dropReasonSpoolWrite)
	p.cDropEvict = p.eventsTotal.WithLabelValues(stateDropped, dropReasonSpoolEvict)

	queueDepth := prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "topsrv_botlog_queue_depth",
		Help: "Current number of events buffered in the send queue. Alert on depth > 0.7*cap to predict drops.",
	}, func() float64 { return float64(len(p.queue)) })
	reg.MustRegister(p.eventsTotal, p.matchTotal, p.sendErrors, p.batchDur, p.spoolFiles, p.spoolBytes, queueDepth)
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
		p.cEnqueued.Inc()
	default:
		p.cDropQueueFull.Inc()
	}
}

// Run pumps the queue: flushes whenever the batch hits BatchSize or interval
// fires. Replays any spooled payloads on startup. Blocks until ctx is cancelled,
// then drains the queue and flushes one last time.
func (p *Pusher) Run(ctx context.Context) {
	interval := p.cfg.ParsedBatchInterval()
	p.Print(ctx, "botlog: started", "endpoint", p.cfg.Endpoint, "interval", interval, "batchSize", p.cfg.BatchSize)
	p.cleanupSpoolTmp(ctx)
	p.refreshSpoolMetrics()
	p.retrySpool(ctx)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	batch := make([]Event, 0, p.cfg.BatchSize)

	for {
		select {
		case <-ctx.Done():
			total := p.drainAndFlushAll(batch)
			p.Print(context.Background(), "botlog: stopped", "drained", total)
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
		p.Error(ctx, "botlog: encode failed", "error", err, "events", len(batch))
		return
	}

	batchID := newBatchID()
	if err := p.sendWithRetry(ctx, payload, batchID); err != nil {
		if isPermanentFailure(err) {
			p.Error(ctx, "botlog: batch permanently rejected, dropping", "error", err, "events", len(batch), "batchId", batchID)
			p.cDropPermanent.Add(float64(len(batch)))
			return
		}
		p.Error(ctx, "botlog: send failed, spooling", "error", err, "events", len(batch), "batchId", batchID)
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
		p.Error(context.Background(), "botlog: encode failed", "error", err, "events", len(batch))
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
	if isPermanentFailure(err) {
		p.Error(shutdownCtx, "botlog: shutdown batch permanently rejected, dropping", "error", err, "events", len(batch), "batchId", batchID)
		p.cDropPermanent.Add(float64(len(batch)))
		return
	}
	p.Error(shutdownCtx, "botlog: shutdown send failed, spooling", "error", err, "events", len(batch), "batchId", batchID)
	p.spool(context.Background(), payload, batchID)
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
		// Cap the discarded read so a hostile receiver can't make us pull MBs.
		// Anything past the cap is fine to leave for the keep-alive teardown —
		// Go's transport will close the connection rather than reuse it.
		n, _ := io.Copy(io.Discard, io.LimitReader(resp.Body, errBodyDrainCap))
		p.sendErrors.WithLabelValues(errStatus).Inc()
		return &httpStatusError{code: resp.StatusCode, bodyLen: int(n)}
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

// spool persists a failed batch under SpoolDir/<batchID>.ndjson.gz, writing
// to a .tmp and renaming for atomicity (so a SIGKILL mid-write doesn't leave
// half a gzip that retrySpool would forward). Dir/files are 0o700/0o600 to
// keep retrySpool from forwarding foreign content under our Bearer token.
// Orphan .tmp files from a previous crash are removed by cleanupSpoolTmp.
func (p *Pusher) spool(ctx context.Context, payload []byte, batchID string) {
	if p.cfg.SpoolDir == "" {
		p.cDropSpoolWrite.Inc()
		return
	}
	if err := os.MkdirAll(p.cfg.SpoolDir, 0o700); err != nil {
		p.Error(ctx, "botlog: spool mkdir failed", "dir", p.cfg.SpoolDir, "error", err)
		p.cDropSpoolWrite.Inc()
		return
	}

	path := filepath.Join(p.cfg.SpoolDir, batchID+spoolSuffix)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, payload, 0o600); err != nil {
		p.Error(ctx, "botlog: spool write failed", "path", tmp, "error", err)
		p.cDropSpoolWrite.Inc()
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		p.Error(ctx, "botlog: spool rename failed", "tmp", tmp, "path", path, "error", err)
		_ = os.Remove(tmp)
		p.cDropSpoolWrite.Inc()
		return
	}

	p.cSpooled.Inc()
	p.trimSpool(ctx)
}

// replayResult is what replayOne reports back to retrySpool: whether the file
// was successfully forwarded, and whether the failure (if any) was transient.
type replayResult struct{ sent, transient bool }

// replayOne attempts to forward a single spool file. The file is removed
// unless the failure is transient — those are kept and retried on the next
// tick. Foreign-owned files are removed without forwarding (we refuse to
// ship arbitrary content under our Bearer token).
func (p *Pusher) replayOne(ctx context.Context, path string) replayResult {
	if !p.ownsSpoolFile(ctx, path) {
		_ = os.Remove(path)
		p.cDropEvict.Inc()
		return replayResult{}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		_ = os.Remove(path)
		return replayResult{}
	}
	if err := p.send(ctx, data, batchIDFromPath(path)); err != nil {
		if isPermanentFailure(err) {
			p.Error(ctx, "botlog: spooled batch rejected, discarding", "path", path, "error", err)
			_ = os.Remove(path)
			return replayResult{}
		}
		return replayResult{transient: true}
	}
	_ = os.Remove(path)
	return replayResult{sent: true}
}

// retrySpool replays spooled batches oldest-first. Transient failures are
// capped per pass by maxTransientPerRun so a poison oldest batch can't stall
// newer ones until trim evicts it.
func (p *Pusher) retrySpool(ctx context.Context) {
	if p.cfg.SpoolDir == "" {
		return
	}
	files, err := filepath.Glob(filepath.Join(p.cfg.SpoolDir, spoolFileGlob))
	if err != nil || len(files) == 0 {
		return
	}
	sort.Strings(files) // unix-ms-prefixed names → ascending = oldest first.

	sent, transientFails := 0, 0
	for _, path := range files {
		if transientFails >= maxTransientPerRun {
			break
		}
		r := p.replayOne(ctx, path)
		if r.sent {
			sent++
		}
		if r.transient {
			transientFails++
		}
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
		p.cDropEvict.Inc()
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

// cleanupSpoolTmp removes any *.tmp leftovers from a previous process that
// crashed between spool's WriteFile and Rename. retrySpool's glob skips them,
// but they'd accumulate in disk usage if never cleaned.
func (p *Pusher) cleanupSpoolTmp(ctx context.Context) {
	if p.cfg.SpoolDir == "" {
		return
	}
	tmps, err := filepath.Glob(filepath.Join(p.cfg.SpoolDir, spoolTmpGlob))
	if err != nil || len(tmps) == 0 {
		return
	}
	for _, t := range tmps {
		_ = os.Remove(t)
	}
	p.Print(ctx, "botlog: cleaned up stale spool tmp files", "count", len(tmps))
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

// ownsSpoolFile is defence-in-depth against SpoolDir perms drift — rejects
// foreign UIDs and symlinks. Non-unix (no Stat_t) trusts directory perms.
func (p *Pusher) ownsSpoolFile(ctx context.Context, path string) bool {
	fi, err := os.Lstat(path)
	if err != nil {
		return false
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		p.Error(ctx, "botlog: spool entry is a symlink, discarding", "path", path)
		return false
	}
	uid, ok := fileUID(fi)
	if !ok {
		return true
	}
	if uid == os.Getuid() {
		return true
	}
	p.Error(ctx, "botlog: spool file not owned by agent user, discarding", "path", path, "fileUID", uid, "agentUID", os.Getuid())
	return false
}
