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
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/vmkteam/topsrv/internal/topsrv/postgres"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/expfmt"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/vmkteam/appkit"
	"github.com/vmkteam/embedlog"
)

const (
	pushTimeout      = 10 * time.Second
	pushRetryBackoff = 5 * time.Second
	pushMaxSpoolSize = 100 // max files in spool dir
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

	cfg           PushConfig
	registry      *prometheus.Registry
	client        *http.Client
	interval      time.Duration
	hostname      string
	metaProviders []QueryMetaProvider
	metaEndpoint  string // derived: /v1/write → /v1/meta
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

	return &Pusher{
		Logger:       logger,
		cfg:          cfg,
		registry:     registry,
		client:       appkit.NewHTTPClient(appName, version, pushTimeout),
		interval:     interval,
		hostname:     hostname,
		metaEndpoint: deriveMetaEndpoint(cfg.Endpoint),
	}
}

// Run starts the push loop. Blocks until the context is cancelled.
func (p *Pusher) Run(ctx context.Context) {
	p.Print(ctx, "push: started", "endpoint", p.cfg.Endpoint, "interval", p.interval)

	// Send spooled data first.
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

	if err := p.send(ctx, data); err != nil {
		p.Print(ctx, "push: flush send failed, spooling", "error", err)
		p.spool(ctx, data)
	} else {
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

	if err := p.send(ctx, data); err != nil {
		p.Error(ctx, "push: send failed", "error", err)
		p.spool(ctx, data)
	} else {
		totalMs := time.Since(start).Milliseconds()
		p.Print(ctx, "push: ok", "size", len(data), "gatherMs", gatherMs, "totalMs", totalMs)
	}

	if len(p.metaProviders) > 0 {
		p.sendMeta(ctx)
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

// send POSTs gzipped metrics to the endpoint.
func (p *Pusher) send(ctx context.Context, data []byte) error {
	ctx, cancel := context.WithTimeout(ctx, pushTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.cfg.Endpoint, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "text/plain; charset=utf-8")
	req.Header.Set("Content-Encoding", "gzip")
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
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		preview := string(body)
		if len(preview) > 200 {
			preview = preview[:200]
		}
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, preview)
	}

	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

// spool saves failed payload to disk for later retry.
func (p *Pusher) spool(ctx context.Context, data []byte) {
	if p.cfg.SpoolDir == "" {
		return
	}
	if err := os.MkdirAll(p.cfg.SpoolDir, 0o750); err != nil {
		p.Error(ctx, "push: spool mkdir failed", "error", err)
		return
	}

	name := fmt.Sprintf("%d.gz", time.Now().UnixMilli())
	path := filepath.Join(p.cfg.SpoolDir, name)
	if err := os.WriteFile(path, data, 0o640); err != nil {
		p.Error(ctx, "push: spool write failed", "error", err)
		return
	}

	files, _ := filepath.Glob(filepath.Join(p.cfg.SpoolDir, "*.gz"))
	p.Print(ctx, "push: spooled", "name", name, "pending", len(files))

	// Trim old files if spool is too large.
	p.trimSpool()
}

// retrySpool sends buffered payloads from spool dir (oldest first).
func (p *Pusher) retrySpool(ctx context.Context) {
	if p.cfg.SpoolDir == "" {
		return
	}

	files, err := filepath.Glob(filepath.Join(p.cfg.SpoolDir, "*.gz"))
	if err != nil || len(files) == 0 {
		return
	}
	sort.Strings(files)

	sent := 0
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			os.Remove(path)
			continue
		}
		if err := p.send(ctx, data); err != nil {
			break // endpoint still down, stop retrying
		}
		os.Remove(path)
		sent++
	}
	if sent > 0 {
		p.Print(ctx, "push: resent spooled payloads", "count", sent)
	}
}

// deriveMetaEndpoint replaces /v1/write with /v1/meta in the push endpoint URL.
func deriveMetaEndpoint(pushEndpoint string) string {
	u, err := url.Parse(pushEndpoint)
	if err != nil {
		return ""
	}
	u.Path = "/v1/meta"
	return u.String()
}

type metaPayload struct {
	Queries []postgres.QueryMeta `json:"queries"`
}

// sendMeta pushes query metadata from all providers to gatesrv.
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

	ctx, cancel := context.WithTimeout(ctx, pushTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.metaEndpoint, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if p.cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+p.cfg.Token)
	}
	if p.hostname != "" {
		req.Header.Set("X-Hostname", p.hostname)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		p.Error(ctx, "meta: send failed", "error", err)
		return
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode >= 400 {
		p.Error(ctx, "meta: HTTP error", "status", resp.StatusCode)
	}
}

// trimSpool removes oldest files if spool exceeds max size.
func (p *Pusher) trimSpool() {
	files, err := filepath.Glob(filepath.Join(p.cfg.SpoolDir, "*.gz"))
	if err != nil || len(files) <= pushMaxSpoolSize {
		return
	}
	sort.Strings(files)
	for _, path := range files[:len(files)-pushMaxSpoolSize] {
		os.Remove(path)
	}
}
