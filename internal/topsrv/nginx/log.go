package nginx

import (
	"context"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/vmkteam/topsrv/internal/topsrv"

	"github.com/nxadm/tail"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/satyrius/gonx"
	"github.com/vmkteam/embedlog"
)

var _ topsrv.Collector = (*LogCollector)(nil)

// Default histogram buckets include 0.5 and 1.0 for traffic-light semaphore (green/yellow/red).
var defaultHTTPBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

// DefaultLogFormat — combined + request_time + upstream_response_time.
const DefaultLogFormat = `$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" $request_time $upstream_response_time`

const maxCardinalityURI = 1000 // cap uri5xx map to prevent unbounded growth
const maxPathDepth = 3         // collapse URI segments beyond this depth to :rest

var (
	// numericSegment matches path segments that are pure digits.
	numericSegment = regexp.MustCompile(`/\d+`)
	// hexHash matches 32-char hex strings (md5 hashes in media URLs).
	hexHash = regexp.MustCompile(`[a-f0-9]{32}`)
	// slugWithID matches slug-style segments ending with digits (e.g. "tommy-brewster-6401345").
	slugWithID = regexp.MustCompile(`/[a-z][\w-]*-\d{4,}/`)
	// longSlug matches long hyphenated slugs with 3+ hyphens (article/product URLs).
	longSlug = regexp.MustCompile(`/[a-z][a-z0-9]*(?:-[a-z0-9]+){3,}`)
)

// LogCollector parses nginx access logs and collects metrics.
// Supports custom labels from log fields via ExtraLabels.
type LogCollector struct {
	embedlog.Logger

	defaultParser *gonx.Parser
	parsers       map[string]*gonx.Parser // path → parser (for multi-format)
	extraFields   []string                // nginx variable names to use as extra labels

	reqDuration      *prometheus.Desc
	upstreamDuration *prometheus.Desc
	httpRequests     *prometheus.Desc
	responseBytes    *prometheus.Desc
	cacheRequests    *prometheus.Desc
	http5xxRequests  *prometheus.Desc
	http4xxRequests  *prometheus.Desc
	responseByteURI  *prometheus.Desc

	mu           sync.Mutex
	reqBuckets   []uint64
	reqSum       float64
	reqCount     uint64
	upBuckets    []uint64
	upSum        float64
	upCount      uint64
	statusCounts map[string]uint64          // status → count (no extra labels)
	taggedCounts map[taggedStatusKey]uint64 // status+labels → count
	cacheCounts  map[string]uint64
	uri5xx       map[statusURI]uint64
	uri4xx       map[statusURI]uint64
	bytesByURI   map[string]uint64
	bytesTotal   atomic.Int64
}

type statusURI struct {
	status string
	uri    string
}

type taggedStatusKey struct {
	status string
	extra  [4]string // extra label values (fixed-size array, max 4 labels)
	n      int       // number of used extra labels
}

// LogConfig holds parameters for creating a LogCollector.
type LogConfig struct {
	LogPaths    []string          // multiple log files tailed into one collector
	LogFormat   string            // default format for all logs
	LogFormats  map[string]string // path → format override (from discovery)
	ExtraLabels []string          // nginx variable names: ["server_name", "http_platform", "http_version"]
}

func NewLogCollector(logger embedlog.Logger, cfg LogConfig) *LogCollector {
	if cfg.LogFormat == "" {
		cfg.LogFormat = DefaultLogFormat
	}

	// Labels for httpRequests: "status" + extra labels.
	reqLabels := append([]string{"status"}, cfg.ExtraLabels...)

	// Build per-path parsers if multiple formats provided.
	parsers := make(map[string]*gonx.Parser, len(cfg.LogFormats))
	for path, format := range cfg.LogFormats {
		parsers[path] = gonx.NewParser(format)
	}

	return &LogCollector{
		Logger:        logger,
		defaultParser: gonx.NewParser(cfg.LogFormat),
		parsers:       parsers,
		extraFields:   cfg.ExtraLabels,

		reqDuration:      prometheus.NewDesc("topsrv_nginx_request_duration_seconds", "Nginx request duration histogram.", nil, nil),
		upstreamDuration: prometheus.NewDesc("topsrv_nginx_upstream_duration_seconds", "Nginx upstream response time histogram.", nil, nil),
		httpRequests:     prometheus.NewDesc("topsrv_nginx_http_requests_total", "HTTP requests by status code.", reqLabels, nil),
		responseBytes:    prometheus.NewDesc("topsrv_nginx_response_bytes_total", "Total response bytes.", nil, nil),
		cacheRequests:    prometheus.NewDesc("topsrv_nginx_cache_requests_total", "Requests by upstream cache status.", []string{"status"}, nil),
		http5xxRequests:  prometheus.NewDesc("topsrv_nginx_5xx_requests_total", "5xx requests by status and normalized URI.", []string{"status", "uri"}, nil),
		http4xxRequests:  prometheus.NewDesc("topsrv_nginx_4xx_requests_total", "4xx requests by status and normalized URI.", []string{"status", "uri"}, nil),
		responseByteURI:  prometheus.NewDesc("topsrv_nginx_response_bytes_by_uri_total", "Response bytes by normalized URI.", []string{"uri"}, nil),

		reqBuckets:   make([]uint64, len(defaultHTTPBuckets)+1),
		upBuckets:    make([]uint64, len(defaultHTTPBuckets)+1),
		statusCounts: make(map[string]uint64),
		taggedCounts: make(map[taggedStatusKey]uint64),
		cacheCounts:  make(map[string]uint64),
		uri5xx:       make(map[statusURI]uint64),
		uri4xx:       make(map[statusURI]uint64),
		bytesByURI:   make(map[string]uint64),
	}
}

func (c *LogCollector) Name() string { return "nginx-log" }

func (c *LogCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.reqDuration
	ch <- c.upstreamDuration
	ch <- c.httpRequests
	ch <- c.responseBytes
	ch <- c.cacheRequests
	ch <- c.http5xxRequests
	ch <- c.http4xxRequests
	ch <- c.responseByteURI
}

func (c *LogCollector) Collect(ch chan<- prometheus.Metric) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.reqCount > 0 {
		ch <- prometheus.MustNewConstHistogram(c.reqDuration, c.reqCount, c.reqSum, cumulativeBuckets(defaultHTTPBuckets, c.reqBuckets))
	}

	if c.upCount > 0 {
		ch <- prometheus.MustNewConstHistogram(c.upstreamDuration, c.upCount, c.upSum, cumulativeBuckets(defaultHTTPBuckets, c.upBuckets))
	}

	if len(c.extraFields) == 0 {
		for status, count := range c.statusCounts {
			ch <- prometheus.MustNewConstMetric(c.httpRequests, prometheus.CounterValue, float64(count), status)
		}
	} else {
		for key, count := range c.taggedCounts {
			vals := make([]string, 0, 1+key.n)
			vals = append(vals, key.status)
			vals = append(vals, key.extra[:key.n]...)
			ch <- prometheus.MustNewConstMetric(c.httpRequests, prometheus.CounterValue, float64(count), vals...)
		}
	}

	ch <- prometheus.MustNewConstMetric(c.responseBytes, prometheus.CounterValue, float64(c.bytesTotal.Load()))

	for status, count := range c.cacheCounts {
		ch <- prometheus.MustNewConstMetric(c.cacheRequests, prometheus.CounterValue, float64(count), status)
	}

	for key, count := range c.uri5xx {
		ch <- prometheus.MustNewConstMetric(c.http5xxRequests, prometheus.CounterValue, float64(count), key.status, key.uri)
	}

	for key, count := range c.uri4xx {
		ch <- prometheus.MustNewConstMetric(c.http4xxRequests, prometheus.CounterValue, float64(count), key.status, key.uri)
	}

	for uri, bytes := range c.bytesByURI {
		ch <- prometheus.MustNewConstMetric(c.responseByteURI, prometheus.CounterValue, float64(bytes), uri)
	}
}

type logLine struct {
	text string
	path string
}

// RunPaths starts tailing multiple access log files. Blocks until context is cancelled.
func (c *LogCollector) RunPaths(ctx context.Context, paths []string) {
	lines := make(chan logLine, 256)

	for _, p := range paths {
		go c.tailFile(ctx, p, lines)
	}

	for {
		select {
		case <-ctx.Done():
			return
		case ll, ok := <-lines:
			if !ok {
				return
			}
			parser := c.defaultParser
			if p, ok := c.parsers[ll.path]; ok {
				parser = p
			}
			c.parseLineWith(parser, ll.text)
		}
	}
}

func (c *LogCollector) tailFile(ctx context.Context, path string, out chan<- logLine) {
	t, err := tail.TailFile(path, tail.Config{
		Follow:    true,
		ReOpen:    true,
		MustExist: false,
		Location:  &tail.SeekInfo{Offset: 0, Whence: 2},
	})
	if err != nil {
		c.Errorf("nginx-log: failed to tail %s: %v", path, err)
		return
	}
	c.Printf("nginx-log: tailing started, path=%s", path)

	for {
		select {
		case <-ctx.Done():
			t.Stop() //nolint:errcheck
			return
		case line, ok := <-t.Lines:
			if !ok {
				return
			}
			if line.Err != nil {
				continue
			}
			out <- logLine{text: line.Text, path: path}
		}
	}
}

func (c *LogCollector) parseLine(line string) {
	c.parseLineWith(c.defaultParser, line)
}

func (c *LogCollector) parseLineWith(parser *gonx.Parser, line string) { //nolint:gocognit,nestif
	entry, err := parser.ParseString(line)
	if err != nil {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Status code.
	if status, err := entry.Field("status"); err == nil { //nolint:nestif
		if len(c.extraFields) == 0 {
			c.statusCounts[status]++
		} else {
			key := taggedStatusKey{status: status, n: len(c.extraFields)}
			for i, f := range c.extraFields {
				if i >= len(key.extra) {
					break
				}
				v, _ := entry.Field(f)
				if v == "-" {
					v = ""
				}
				key.extra[i] = v
			}
			c.taggedCounts[key]++
		}

		// Extract normalized URI for 4xx/5xx tracking and bytes-by-URI.
		var uri string
		if req, err := entry.Field("request"); err == nil {
			uri = normalizeURI(req)
		} else if u, err := entry.Field("uri"); err == nil {
			uri = normalizePath(u)
		}

		// Track 5xx by status + normalized URI (capped to prevent unbounded growth).
		if strings.HasPrefix(status, "5") && uri != "" {
			key := statusURI{status, uri}
			if _, ok := c.uri5xx[key]; ok || len(c.uri5xx) < maxCardinalityURI {
				c.uri5xx[key]++
			}
		}

		// Track 4xx by status + normalized URI (capped to prevent unbounded growth).
		if strings.HasPrefix(status, "4") && uri != "" {
			key := statusURI{status, uri}
			if _, ok := c.uri4xx[key]; ok || len(c.uri4xx) < maxCardinalityURI {
				c.uri4xx[key]++
			}
		}

		// Body bytes (total + by URI).
		if s, err := entry.Field("body_bytes_sent"); err == nil {
			if v, err := strconv.ParseInt(s, 10, 64); err == nil {
				c.bytesTotal.Add(v)
				if uri != "" {
					if _, ok := c.bytesByURI[uri]; ok || len(c.bytesByURI) < maxCardinalityURI {
						c.bytesByURI[uri] += uint64(v)
					}
				}
			}
		}
	}

	// Request duration.
	if s, err := entry.Field("request_time"); err == nil {
		if v, err := strconv.ParseFloat(s, 64); err == nil {
			c.reqCount++
			c.reqSum += v
			c.reqBuckets[bucketIndex(v)]++
		}
	}

	// Upstream response time.
	if s, err := entry.Field("upstream_response_time"); err == nil {
		if i := strings.IndexByte(s, ','); i > 0 {
			s = strings.TrimSpace(s[:i])
		}
		if v, err := strconv.ParseFloat(s, 64); err == nil {
			c.upCount++
			c.upSum += v
			c.upBuckets[bucketIndex(v)]++
		}
	}

	// Upstream cache status.
	if s, err := entry.Field("upstream_cache_status"); err == nil && s != "-" && s != "" {
		c.cacheCounts[s]++
	}
}

func normalizeURI(request string) string {
	parts := strings.SplitN(request, " ", 3)
	if len(parts) < 2 {
		return request
	}
	path := parts[1]
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	return normalizePath(path)
}

func normalizePath(path string) string {
	path = numericSegment.ReplaceAllString(path, "/:id")
	path = hexHash.ReplaceAllString(path, ":hash")
	path = slugWithID.ReplaceAllString(path, "/:slug/")
	path = longSlug.ReplaceAllString(path, "/:slug")
	return truncatePath(path, maxPathDepth)
}

// truncatePath collapses path segments beyond maxDepth into /:rest.
// Trailing slash is not counted as an extra segment.
func truncatePath(path string, maxDepth int) string {
	trimmed := strings.TrimRight(path, "/")
	depth := 0
	for i := 1; i < len(trimmed); i++ {
		if trimmed[i] == '/' {
			depth++
			if depth >= maxDepth {
				return trimmed[:i] + "/:rest"
			}
		}
	}
	return path
}

func bucketIndex(v float64) int {
	for i, b := range defaultHTTPBuckets {
		if v <= b {
			return i
		}
	}
	return len(defaultHTTPBuckets)
}

func cumulativeBuckets(bounds []float64, ranges []uint64) map[float64]uint64 {
	result := make(map[float64]uint64, len(bounds))
	var cum uint64
	for i, b := range bounds {
		cum += ranges[i]
		result[b] = cum
	}
	return result
}
