package topsrv

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/vmkteam/topsrv/internal/topsrv/inventory"
	"github.com/vmkteam/topsrv/internal/topsrv/postgres"
	"github.com/vmkteam/topsrv/internal/topsrv/spool"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/expfmt"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/vmkteam/appkit"
	"github.com/vmkteam/embedlog"
)

const (
	pushTimeout      = 10 * time.Second
	pushMaxSpoolSize = 100      // max metric payloads in spool dir
	respDrainCap     = 64 << 10 // response bytes read before closing, to keep the connection reusable

	inventorySpoolDir        = "inventory"        // SpoolDir subdirectory for /v1/inventory
	inventoryMaxSpoolPerKind = 20                 // spooled snapshots kept per kind
	inventoryResendPerTick   = 5                  // spooled snapshots resent per push tick
	inventorySpoolMaxAge     = 7 * 24 * time.Hour // older spooled snapshots are dropped unsent
	inventoryRejectLogEvery  = time.Hour          // rejections from /v1/inventory logged once per kind per period
)

// PushConfig holds the push client settings.
type PushConfig struct {
	Endpoint string
	Token    string
	Interval string // parsed as time.Duration
	SpoolDir string // directory for buffering on failures (optional)
}

// Pusher sends metrics to a control plane / VictoriaMetrics.
// Format: Prometheus text, gzip, POST.
type Pusher struct {
	embedlog.Logger

	cfg                PushConfig
	registry           *prometheus.Registry
	client             *http.Client
	interval           time.Duration
	hostname           string
	metaProviders      []QueryMetaProvider
	inventoryProviders []InventoryProvider
	metaEndpoint       string    // derived: /v1/write → /v1/meta
	inventoryEndpoint  string    // derived: /v1/write → /v1/inventory
	metricsSpool       spool.Dir // <SpoolDir>/<unixms>.gz
	inventorySpool     spool.Dir // <SpoolDir>/inventory/<kind>-<unixms>.json

	// rejectLoggedAt rate-limits logging of 4xx inventory responses per kind.
	// Only the Run goroutine touches it (push → inventory send and resend).
	rejectLoggedAt map[string]time.Time
}

func NewPusher(logger embedlog.Logger, appName, version string, cfg PushConfig, registry *prometheus.Registry) *Pusher {
	interval, err := time.ParseDuration(cfg.Interval)
	if err != nil || interval < time.Second {
		interval = 30 * time.Second
	}

	hostname := ""
	if info, err := host.Info(); err == nil {
		hostname = info.Hostname
	}

	p := &Pusher{
		Logger:            logger,
		cfg:               cfg,
		registry:          registry,
		client:            appkit.NewHTTPClient(appName, version, pushTimeout),
		interval:          interval,
		hostname:          hostname,
		metaEndpoint:      deriveEndpoint(cfg.Endpoint, "/v1/meta"),
		inventoryEndpoint: deriveEndpoint(cfg.Endpoint, "/v1/inventory"),
		metricsSpool:      spool.Dir{Path: cfg.SpoolDir, Ext: ".gz"},
		inventorySpool:    spool.Dir{Ext: ".json"},
		rejectLoggedAt:    make(map[string]time.Time),
	}
	if cfg.SpoolDir != "" { // Join("", dir) would be a path relative to the working directory
		p.inventorySpool.Path = filepath.Join(cfg.SpoolDir, inventorySpoolDir)
	}
	return p
}

// Run starts the push loop. Blocks until the context is cancelled.
func (p *Pusher) Run(ctx context.Context) {
	p.Print(ctx, "push: started", "endpoint", p.cfg.Endpoint, "interval", p.interval)

	// Send spooled data first.
	p.metricsSpool.CleanupTmp()
	p.inventorySpool.CleanupTmp()
	p.retrySpool(ctx)

	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			p.Flush()
			p.Print(ctx, "push: stopped")
			return
		case <-ticker.C:
			p.push(ctx)
		}
	}
}

// AddMetaProvider registers a provider for query metadata push.
func (p *Pusher) AddMetaProvider(mp QueryMetaProvider) {
	p.metaProviders = append(p.metaProviders, mp)
}

// AddInventoryProvider registers a provider for /v1/inventory snapshot push.
func (p *Pusher) AddInventoryProvider(ip InventoryProvider) {
	p.inventoryProviders = append(p.inventoryProviders, ip)
}

// Flush performs a final gather and attempts to send metrics.
// If the send fails, data is spooled to disk for retry on next startup.
func (p *Pusher) Flush() {
	ctx, cancel := context.WithTimeout(context.Background(), pushTimeout)
	defer cancel()

	// Drain any previously spooled data first.
	p.retrySpool(ctx)

	data, err := p.gather()
	if err != nil {
		p.Error(ctx, "push: flush gather failed", "error", err)
		return
	}

	if err := p.deliverMetrics(ctx, data); err == nil {
		p.Print(ctx, "push: flush ok", "size", len(data))
	}
}

func (p *Pusher) push(ctx context.Context) {
	// Retry spooled data before new push.
	p.retrySpool(ctx)

	start := time.Now()
	data, err := p.gather()
	gatherMs := time.Since(start).Milliseconds()
	if err != nil {
		p.Error(ctx, "push: gather failed", "error", err)
		return
	}

	if err := p.deliverMetrics(ctx, data); err == nil {
		totalMs := time.Since(start).Milliseconds()
		p.Print(ctx, "push: ok", "size", len(data), "gatherMs", gatherMs, "totalMs", totalMs)
	}

	if len(p.metaProviders) > 0 {
		p.sendMeta(ctx)
	}

	if len(p.inventoryProviders) > 0 && p.inventoryEndpoint != "" {
		p.retryInventorySpool(ctx)
		p.sendInventory(ctx)
	}
}

// gather collects metrics and encodes as gzipped Prometheus text format.
// Timestamps are set explicitly so that spooled/resent payloads land at the correct time.
func (p *Pusher) gather() ([]byte, error) {
	mfs, err := p.registry.Gather()
	if err != nil {
		return nil, fmt.Errorf("gather: %w", err)
	}

	// Stamp every metric with current time so spool/resend preserves original timestamps.
	now := time.Now().UnixMilli()
	for _, mf := range mfs {
		for _, m := range mf.GetMetric() {
			m.TimestampMs = &now
		}
	}

	var text bytes.Buffer
	enc := expfmt.NewEncoder(&text, expfmt.NewFormat(expfmt.TypeTextPlain))
	for _, mf := range mfs {
		if err := enc.Encode(mf); err != nil {
			return nil, fmt.Errorf("encode: %w", err)
		}
	}

	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	if _, err := gz.Write(text.Bytes()); err != nil {
		return nil, fmt.Errorf("gzip: %w", err)
	}
	if err := gz.Close(); err != nil {
		return nil, fmt.Errorf("gzip close: %w", err)
	}

	return compressed.Bytes(), nil
}

// deliverMetrics sends data. A retryable failure spools it; a rejection drops
// it, since resending the same payload would be rejected again.
func (p *Pusher) deliverMetrics(ctx context.Context, data []byte) error {
	err := p.send(ctx, data)
	switch {
	case err == nil:
	case spool.Retryable(err):
		p.Error(ctx, "push: send failed, spooling", "error", err)
		p.spoolWrite(ctx, p.metricsSpool, "", pushMaxSpoolSize, data)
	default:
		p.Error(ctx, "push: rejected by the backend, dropping", "error", err)
	}
	return err
}

// send POSTs gzipped metrics to the endpoint.
func (p *Pusher) send(ctx context.Context, data []byte) error {
	return p.post(ctx, p.cfg.Endpoint, "text/plain; charset=utf-8", "gzip", data)
}

// postJSON POSTs a JSON body to url. Common path for both /v1/meta and
// /v1/inventory pushes.
func (p *Pusher) postJSON(ctx context.Context, url string, body []byte) error {
	return p.post(ctx, url, "application/json", "", body)
}

// post POSTs body to url with the agent's auth and hostname headers. On status
// >= 400 it returns *spool.StatusError with the first 200 bytes of the body,
// so operators can see the backend's validation message; transport failures
// come back as is.
func (p *Pusher) post(ctx context.Context, url, contentType, contentEncoding string, body []byte) error {
	ctx, cancel := context.WithTimeout(ctx, pushTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", contentType)
	if contentEncoding != "" {
		req.Header.Set("Content-Encoding", contentEncoding)
	}
	if p.cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+p.cfg.Token)
	}
	if p.hostname != "" {
		req.Header.Set("X-Hostname", p.hostname)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		// A bounded drain keeps the connection reusable without letting a
		// misbehaving backend make us read megabytes.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, respDrainCap))
		resp.Body.Close()
	}()

	if resp.StatusCode >= 400 {
		preview, _ := io.ReadAll(io.LimitReader(resp.Body, 200))
		return &spool.StatusError{Code: resp.StatusCode, Body: string(preview)}
	}
	return nil
}

// retrySpool resends spooled metrics oldest first until the first retryable
// failure. Rejected payloads are dropped.
func (p *Pusher) retrySpool(ctx context.Context) {
	res := p.metricsSpool.Replay(spool.Policy{}, func(_ string, body []byte) error {
		return p.send(ctx, body)
	})
	if res.Sent > 0 {
		p.Print(ctx, "push: resent spooled payloads", "count", res.Sent)
	}
	if n := len(res.Rejected); n > 0 {
		p.Error(ctx, "push: spooled payloads rejected by the backend, dropped", "count", n, "error", res.Rejected[n-1].Err)
	}
	p.logSpoolDropped(ctx, p.metricsSpool, res.Dropped)
}

// deriveEndpoint replaces the push endpoint's path with `path` (e.g. /v1/meta
// or /v1/inventory) while preserving scheme/host/credentials.
func deriveEndpoint(pushEndpoint, path string) string {
	u, err := url.Parse(pushEndpoint)
	if err != nil {
		return ""
	}
	u.Path = path
	return u.String()
}

type metaPayload struct {
	Queries []postgres.QueryMeta `json:"queries"`
}

// sendMeta pushes query metadata from all providers to /v1/meta.
func (p *Pusher) sendMeta(ctx context.Context) {
	if p.metaEndpoint == "" {
		return
	}

	var all []postgres.QueryMeta
	for _, mp := range p.metaProviders {
		all = append(all, mp.QueryMeta()...)
	}
	if len(all) == 0 {
		return
	}

	body, err := json.Marshal(metaPayload{Queries: all})
	if err != nil {
		return
	}

	if err := p.postJSON(ctx, p.metaEndpoint, body); err != nil {
		p.Error(ctx, "meta: send failed", "error", err)
	}
}

// sendInventory pushes inventory snapshots from all providers to
// /v1/inventory. Each Payload is sent as a separate request — the backend
// routes by `kind`. Providers return nil/empty when there's nothing fresh.
//
// On 2xx the provider's optional OnInventoryPushed is invoked. A retryable
// failure (spool.Retryable) spools the snapshot to SpoolDir/inventory/; a
// rejection drops it, since resending the same body would be rejected again.
func (p *Pusher) sendInventory(ctx context.Context) {
	for _, ip := range p.inventoryProviders {
		for _, payload := range ip.Inventory() {
			p.sendOneInventory(ctx, ip, payload)
		}
	}
}

func (p *Pusher) sendOneInventory(ctx context.Context, ip InventoryProvider, payload inventory.Payload) {
	body, err := json.Marshal(payload)
	if err != nil {
		p.Error(ctx, "inventory: marshal failed", "kind", payload.Kind, "error", err)
		return
	}

	if err := p.postJSON(ctx, p.inventoryEndpoint, body); err != nil {
		if !spool.Retryable(err) {
			p.logRejected(ctx, payload.Kind, err)
			return
		}
		p.Error(ctx, "inventory: send failed", "kind", payload.Kind, "error", err)
		// The cap is per kind, so large packages snapshots never push out other kinds.
		p.spoolWrite(ctx, p.inventorySpool, payload.Kind+"-", inventoryMaxSpoolPerKind, body)
		return
	}

	if ack, ok := ip.(InventoryAckReceiver); ok {
		ack.OnInventoryPushed(payload.Kind)
	}
}

// logRejected logs a rejection from /v1/inventory at most once per
// inventoryRejectLogEvery per kind: an unknown kind or a schema mismatch
// repeats on every snapshot until the backend or the agent is updated.
func (p *Pusher) logRejected(ctx context.Context, kind string, err error) {
	now := time.Now()
	if last, ok := p.rejectLoggedAt[kind]; ok && now.Sub(last) < inventoryRejectLogEvery {
		return
	}
	p.rejectLoggedAt[kind] = now
	p.Error(ctx, "inventory: rejected by the backend", "kind", kind, "error", err)
}

// retryInventorySpool resends spooled snapshots ahead of fresh ones, oldest
// first within a kind. It makes at most inventoryResendPerTick requests per
// call: after an upgrade a host may hold dozens of large packages snapshots.
// Files older than inventorySpoolMaxAge are dropped unsent. Success or a
// rejection removes the file; a retryable error ends the pass until the next
// tick. Providers are not acknowledged — their last-push metrics track live
// sends only.
func (p *Pusher) retryInventorySpool(ctx context.Context) {
	policy := spool.Policy{MaxSends: inventoryResendPerTick, MaxAge: inventorySpoolMaxAge}
	res := p.inventorySpool.Replay(policy, func(_ string, body []byte) error {
		return p.postJSON(ctx, p.inventoryEndpoint, body)
	})
	for _, r := range res.Rejected {
		kind, _, _ := strings.Cut(r.Name, "-") // <kind>-<unixms>
		p.logRejected(ctx, kind, r.Err)
	}
	if res.Sent+len(res.Rejected)+res.Expired > 0 {
		p.Print(ctx, "inventory: spool processed", "sent", res.Sent, "rejected", len(res.Rejected), "expired", res.Expired)
	}
	p.logSpoolDropped(ctx, p.inventorySpool, res.Dropped)
}

// spoolWrite stores body as <prefix><unixms> in d and keeps at most limit
// files with that prefix. No-op without SpoolDir.
func (p *Pusher) spoolWrite(ctx context.Context, d spool.Dir, prefix string, limit int, body []byte) {
	if p.cfg.SpoolDir == "" {
		return
	}
	name := prefix + strconv.FormatInt(time.Now().UnixMilli(), 10)
	if err := d.Write(name, body); err != nil {
		p.Error(ctx, "spool: write failed", "dir", d.Path, "error", err)
		return
	}
	if n := d.Trim(prefix, limit); n > 0 {
		p.Print(ctx, "spool: dropped oldest", "dir", d.Path, "dropped", n, "kept", limit)
	}
	p.Print(ctx, "spool: queued", "dir", d.Path, "name", name, "pending", len(d.Files(prefix)))
}

// logSpoolDropped reports spool entries Replay removed unsent: not regular
// files of the agent's user, or unreadable.
func (p *Pusher) logSpoolDropped(ctx context.Context, d spool.Dir, n int) {
	if n > 0 {
		p.Error(ctx, "spool: removed unsent entries that are foreign or unreadable", "dir", d.Path, "count", n)
	}
}
