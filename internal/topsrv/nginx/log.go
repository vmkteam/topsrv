package nginx

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

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

const maxCardinalityURI = 1000    // cap on uri4xx/uri5xx/bytesByURI keys; eviction policy in uricounters.go
const maxCardinalityTagged = 500  // cap taggedCounts (status × extra labels) to prevent unbounded growth
const maxPathDepth = 2            // collapse URI segments beyond this depth
const maxNormalizedURIBytes = 240 // hard byte cap; Prometheus exposition rejects label values >256 bytes
const maxRawPathBytes = 1024      // sanity cap on incoming $uri; anything larger is garbage / DoS amplification

// Sentinel labels for normalizePath outcomes. Kept as consts so call sites and
// truncation arithmetic (s[:N-len(restMarker)]) stay in sync.
const (
	restMarker    = "/:rest"
	invalidMarker = "/:invalid"
)

var (
	// numericSegment matches path segments that are pure digits.
	numericSegment = regexp.MustCompile(`/\d+`)
	// uuidSegment matches UUID v4 format (8-4-4-4-12 hex, case-insensitive).
	uuidSegment = regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)
	// hexHash matches 32+ char hex strings (md5 hashes in media URLs; longer
	// tokens too — a 48-hex name used to leave a 16-hex tail after :hash).
	hexHash = regexp.MustCompile(`[a-f0-9]{32,}`)
	// slugWithID matches slug-style segments ending with digits (e.g. "tommy-brewster-6401345").
	slugWithID = regexp.MustCompile(`/[a-z][\w-]*-\d{4,}/`)
	// hyphenSlug matches hyphenated slugs with 1+ hyphens (people, articles, products).
	hyphenSlug = regexp.MustCompile(`/[a-z][a-z0-9]*(?:-[a-z0-9]+)+`)
	// urlEncodedSegment matches path segments containing percent-encoded characters,
	// including the non-standard %uXXXX form scanners use (/%u002f%u002eenv).
	urlEncodedSegment = regexp.MustCompile(`/[^/]*%(?:[0-9A-Fa-f]{2}|u[0-9A-Fa-f]{4})[^/]*`)
	// xenForoSlug matches XenForo-style segments: text.digits (threads, attachments, blogs, members).
	xenForoSlug = regexp.MustCompile(`/[\w][\w-]*\.\d+/`)
	// base64Token matches base64-encoded tokens with padding (containing = or ==).
	base64Token = regexp.MustCompile(`[A-Za-z0-9_+-]{6,}={1,2}[^/]*`)
	// longBase64Token matches a single path segment of 32+ base64url-charset
	// characters. The uppercase requirement (random tokens are mixed-case,
	// product slugs are not) is enforced inside the replacement func in
	// normalizePath — keep in sync with the `hasUpper` gate there.
	longBase64Token = regexp.MustCompile(`/[A-Za-z0-9_-]{32,}`)
	// fileNumericSuffix matches _digits patterns in filenames (e.g. "_10778" in "show_10778.jpeg").
	fileNumericSuffix = regexp.MustCompile(`_\d{3,}`)
	// phpFile matches .php filename in the last path segment.
	phpFile = regexp.MustCompile(`/[^/]+\.php$`)
)

// scannerSuffixes are path suffixes that indicate bot/scanner probes and never appear in legitimate traffic.
var scannerSuffixes = [...]string{".env", ".git", ".aws", ".ssh", ".svn", ".bak", ".sql"}

// LogCollector parses nginx access logs and collects metrics.
// Supports custom labels from log fields via ExtraLabels (Prometheus labels)
// and a superset ExtractFields (values read into ParsedLine.Extras for
// observers such as botlog).
type LogCollector struct {
	embedlog.Logger

	defaultParser *gonx.Parser
	parsers       map[string]*gonx.Parser // path → parser (for multi-format)
	jsonPaths     map[string]bool         // path → true if log is JSON format
	extractFields []string                // nginx vars read into ParsedLine.Extras (superset of labelFields)
	methodField   string                  // resolved name of the request-verb field ("" → canonical names only)
	timeField     string                  // resolved name of the request-time field ("" → canonical names only)

	labelFields []string // nginx vars used as Prometheus labels (must be low-cardinality)
	labelIdx    []int    // labelFields[k] is at Extras[labelIdx[k]]; -1 if missing
	logPaths    []string // captured from LogConfig.LogPaths for Run

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
	uri5xx       uriCounters[statusURI] // bounded, idle keys evicted, overflow → /:other (uricounters.go)
	uri4xx       uriCounters[statusURI]
	bytesByURI   uriCounters[string]
	bytesTotal   atomic.Int64

	observers []LogObserver // set-once before Run; iterated lock-free on the parse goroutine
}

// LogObserver receives parsed log lines after metric accumulation. OnLogLine is
// invoked synchronously on the tail-parsing goroutine, so implementations must
// not block, perform I/O, or call back into LogCollector. Pass the ParsedLine
// through to async storage (channel, ring buffer) and return quickly. The
// pointer must not be retained past the call or mutated.
type LogObserver interface {
	OnLogLine(line *ParsedLine, path string)
}

type statusURI struct {
	status string
	uri    string
}

// MaxExtras caps the per-line Extras slot count. Sized to fit operator
// ExtraLabels (typically ≤3) plus botlog's RequiredFields() with room.
const MaxExtras = 8

type taggedStatusKey struct {
	status string
	extra  [MaxExtras]string // extra label values (fixed-size array)
	n      int               // number of used extra labels
}

// LogConfig holds parameters for creating a LogCollector.
type LogConfig struct {
	LogPaths   []string          // multiple log files tailed into one collector
	LogFormat  string            // default format for all logs
	LogFormats map[string]string // path → format override (from discovery)
	JSONPaths  map[string]bool   // path → true if log is JSON format

	// ExtraLabels are the nginx variables exported as Prometheus labels on
	// topsrv_nginx_http_requests_total. Must be bounded cardinality
	// (server_name, http_platform, http_version). Operator-controlled.
	ExtraLabels []string

	// ExtractFields is a superset of ExtraLabels: variables read into
	// ParsedLine.Extras for observers (e.g. botlog) that need raw values
	// without paying Prometheus cardinality cost. Empty → defaults to
	// ExtraLabels (single-purpose behaviour).
	ExtractFields []string

	// MethodField and TimeField name the field carrying the request verb and
	// the request timestamp: the nginx variable for text formats, the JSON key
	// for JSON ones. Operators rename these freely (`"ts":"$msec"`), and the
	// canonical names are only a fallback — looking them up unconditionally is
	// what made a renamed $msec read as "no timestamp at all". Empty → the
	// canonical candidates below are the only ones tried.
	MethodField string
	TimeField   string
}

func NewLogCollector(logger embedlog.Logger, cfg LogConfig) *LogCollector {
	if cfg.LogFormat == "" {
		cfg.LogFormat = DefaultLogFormat
	}

	// Default ExtractFields to ExtraLabels for backward compatibility.
	extractFields := cfg.ExtractFields
	if len(extractFields) == 0 {
		extractFields = cfg.ExtraLabels
	}
	if maxFields := len(ParsedLine{}.Extras); len(extractFields) > maxFields {
		extractFields = extractFields[:maxFields]
	}

	// labelIdx[k] = position in extractFields, or -1 if the label has no
	// matching extract entry. Caller is expected to surface mismatches via
	// LabelIdx()/ExtractFields() — see app.registerLogCollector.
	labelIdx := make([]int, len(cfg.ExtraLabels))
	for k, name := range cfg.ExtraLabels {
		labelIdx[k] = slices.Index(extractFields, name)
	}

	// Labels for httpRequests: "status" + low-cardinality extra labels.
	reqLabels := append([]string{"status"}, cfg.ExtraLabels...)

	// Build per-path parsers if multiple formats provided.
	parsers := make(map[string]*gonx.Parser, len(cfg.LogFormats))
	for path, format := range cfg.LogFormats {
		if !cfg.JSONPaths[path] {
			parsers[path] = gonx.NewParser(format)
		}
	}

	return &LogCollector{
		Logger:        logger,
		defaultParser: gonx.NewParser(cfg.LogFormat),
		parsers:       parsers,
		jsonPaths:     cfg.JSONPaths,
		extractFields: extractFields,
		methodField:   cfg.MethodField,
		timeField:     cfg.TimeField,
		labelFields:   cfg.ExtraLabels,
		labelIdx:      labelIdx,
		logPaths:      cfg.LogPaths,

		reqDuration:      prometheus.NewDesc("topsrv_nginx_request_duration_seconds", "Nginx request duration histogram.", nil, nil),
		upstreamDuration: prometheus.NewDesc("topsrv_nginx_upstream_duration_seconds", "Nginx upstream response time histogram.", nil, nil),
		httpRequests:     prometheus.NewDesc("topsrv_nginx_http_requests_total", "HTTP requests by status code.", reqLabels, nil),
		responseBytes:    prometheus.NewDesc("topsrv_nginx_response_bytes_total", "Total response bytes.", nil, nil),
		cacheRequests:    prometheus.NewDesc("topsrv_nginx_cache_requests_total", "Requests by upstream cache status.", []string{"status"}, nil),
		http5xxRequests:  prometheus.NewDesc("topsrv_nginx_5xx_requests_total", "5xx requests by status and normalized URI; past the per-host URI cap new paths count as uri=\"/:other\".", []string{"status", "uri"}, nil),
		http4xxRequests:  prometheus.NewDesc("topsrv_nginx_4xx_requests_total", "4xx requests by status and normalized URI; past the per-host URI cap new paths count as uri=\"/:other\".", []string{"status", "uri"}, nil),
		responseByteURI:  prometheus.NewDesc("topsrv_nginx_response_bytes_by_uri_total", "Response bytes by normalized URI; past the per-host URI cap new paths count as uri=\"/:other\".", []string{"uri"}, nil),

		reqBuckets:   make([]uint64, len(defaultHTTPBuckets)+1),
		upBuckets:    make([]uint64, len(defaultHTTPBuckets)+1),
		statusCounts: make(map[string]uint64),
		taggedCounts: make(map[taggedStatusKey]uint64),
		cacheCounts:  make(map[string]uint64),
		uri5xx:       newURICounters[statusURI](maxCardinalityURI),
		uri4xx:       newURICounters[statusURI](maxCardinalityURI),
		bytesByURI:   newURICounters[string](maxCardinalityURI),
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

	if len(c.labelFields) == 0 {
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

	for key, e := range c.uri5xx.m {
		ch <- prometheus.MustNewConstMetric(c.http5xxRequests, prometheus.CounterValue, float64(e.count), key.status, key.uri)
	}

	for key, e := range c.uri4xx.m {
		ch <- prometheus.MustNewConstMetric(c.http4xxRequests, prometheus.CounterValue, float64(e.count), key.status, key.uri)
	}

	for uri, e := range c.bytesByURI.m {
		ch <- prometheus.MustNewConstMetric(c.responseByteURI, prometheus.CounterValue, float64(e.count), uri)
	}
}

type logLine struct {
	text string
	path string
}

// Run tails every access log captured in LogPaths. Blocks until ctx is cancelled.
func (c *LogCollector) Run(ctx context.Context) {
	c.runPaths(ctx, c.logPaths)
}

// runPaths tails the explicit paths instead of the captured LogPaths — exposed
// only inside the package for tests that synthesize ad-hoc log files.
func (c *LogCollector) runPaths(ctx context.Context, paths []string) {
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
			if c.jsonPaths[ll.path] {
				c.parseJSONLine(ll.text, ll.path)
			} else {
				parser := c.defaultParser
				if p, ok := c.parsers[ll.path]; ok {
					parser = p
				}
				c.parseLineWith(parser, ll.text, ll.path)
			}
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
		c.Error(ctx, "nginx-log: failed to tail", "path", path, "error", err)
		return
	}
	c.Print(ctx, "nginx-log: tailing started", "path", path)

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

// AddObserver registers o to receive every parsed line. Must be called before Run;
// not safe to call concurrently with parsing.
func (c *LogCollector) AddObserver(o LogObserver) {
	c.observers = append(c.observers, o)
}

func (c *LogCollector) parseLine(line string) {
	c.parseLineWith(c.defaultParser, line, "")
}

// ParsedLine holds fields extracted from a log line by either text or JSON parser.
// Passed by pointer to LogObserver; implementations must not mutate it.
type ParsedLine struct {
	Status               string
	URI                  string // path normalized for nginx-metrics cardinality (/:id, /:rest)
	RawURI               string // un-normalized request URI (path + query) — for observers that need the full URL (e.g. botlog)
	BodyBytesSent        string
	RequestTime          string
	UpstreamResponseTime string
	UpstreamCacheStatus  string

	// Method is the request verb, "" when the log_format carries neither
	// $request_method nor $request. Typed field rather than an Extras slot:
	// MaxExtras is a hard budget shared with operator ExtraLabels, and the
	// verb is needed by every observer, not just the ones extras serve.
	Method string
	// Time is the raw request timestamp as logged ($msec / $time_iso8601 /
	// $time_local), "" when the format carries none. Kept unparsed here —
	// only observers that need it pay for the parse (see Timestamp).
	Time string

	// Client fields carried by request headers and the userid module, "" when
	// the format omits them. Typed rather than Extras slots for the same reason
	// as Method: MaxExtras is a hard budget shared with operator ExtraLabels,
	// and on a host logging $http_platform plus the botlog set only one slot is
	// left — a third field would be dropped by capExtractFields with nothing
	// but a warning to show for it.
	//
	// Platform and AppVersion identify the calling app ($http_platform,
	// $http_version); VisitorID is the userid cookie ($uid_got), which is the
	// only stable identity above the address — one client rotating addresses
	// under a single cookie and many cookies behind one address are opposite
	// cases and tell apart by nothing else.
	Platform   string
	AppVersion string
	VisitorID  string

	// RequestID is nginx's $request_id (32 hex) or an X-Request-Id header the
	// upstream generated — the only field that ties an event to the backend's
	// own logs for the same request. Without it a slow or failed request can be
	// seen here but not followed to where it was actually served.
	//
	// UpstreamStatus is $upstream_status: what the backend answered, as opposed
	// to Status, which is what the client got. They differ exactly where it
	// matters — nginx serving a 502 from its own error page, a retry chain
	// whose first attempt failed, a cached 200 over a backend that is down.
	//
	// Typed for the same reason as the three above: MaxExtras is a hard budget
	// shared with operator ExtraLabels, and a busy front node has none left.
	RequestID      string
	UpstreamStatus string

	Extras  [MaxExtras]string // extra field values (pre-extracted), addressed via LogCollector.ExtractFields()
	NExtras int
}

// Timestamp parses Time into a time.Time. ok is false when the log_format
// carried no timestamp or the value is unparseable, and callers then substitute
// their own clock — which silently destroys inter-request timing, because think
// time, request gaps and sequence detection are all computed from this field
// downstream.
//
// The common cause, a format carrying no timestamp at all, is reported once at
// startup as topsrv_collector_config_warnings_total{kind="botlog_no_time_field"}
// — it is a static property of the log_format, known before the first request.
// A per-line failure (garbage value, or one outside the sanity window) carries
// no separate signal on purpose: this runs on the tail goroutine for every
// line, and the fix for both is the same edit to the log_format.
func (p *ParsedLine) Timestamp() (time.Time, bool) { return parseLogTime(p.Time) }

// timeLocalLayout is nginx's $time_local ("18/Aug/2026:11:20:03 +0300").
const timeLocalLayout = "02/Jan/2006:15:04:05 -0700"

// minLogTime / maxLogSkew bound an accepted timestamp. A "0.000" from a broken
// format would otherwise land events in 1970 and pass any freshness window,
// and the other end is just as reachable: gonx matches fields positionally, so
// a log_format that drifted out of sync with the parser puts an arbitrary — in
// the limit client-controlled — token in the timestamp field. Unbounded, that
// writes a year-292277026 event and opens a partition that far out downstream.
var minLogTime = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)

const maxLogSkew = 24 * time.Hour

// maxEpochSec is a pre-conversion guard: int64() of a float too large to
// represent is undefined in Go, so the epoch is range-checked before the
// multiply, not only after. Far past any date minLogTime/maxLogSkew allow.
const maxEpochSec = 1e12

// parseLogTime decodes one of the three timestamp shapes nginx produces and
// rejects anything outside the sanity window above.
func parseLogTime(s string) (time.Time, bool) {
	t, ok := decodeLogTime(s)
	if !ok || t.Before(minLogTime) || t.After(time.Now().Add(maxLogSkew)) {
		return time.Time{}, false
	}
	return t, true
}

// decodeLogTime picks the shape by a marker byte instead of trying each parser
// in turn: every failed strconv/time parse allocates an error value that the
// fallthrough would immediately discard, which on a $time_local-only format
// made the "cheapest first" ordering the most expensive one.
func decodeLogTime(s string) (time.Time, bool) {
	if s == "" || s == "-" {
		return time.Time{}, false
	}
	// $time_local ("18/Aug/2026:11:20:03 +0300") is the only shape carrying a
	// '/', and $time_iso8601 the only one with a '-' past the first byte — a
	// leading '-' is a negative epoch, which ParseFloat below rejects.
	if strings.IndexByte(s, '/') > 0 {
		t, err := time.Parse(timeLocalLayout, s)
		return t, err == nil
	}
	if strings.IndexByte(s, '-') > 0 {
		t, err := time.Parse(time.RFC3339, s)
		return t, err == nil
	}
	if sec, err := strconv.ParseFloat(s, 64); err == nil {
		// ParseFloat also accepts "NaN", "Inf", "infinity" and hex floats
		// ("0x1p10"), none of which are timestamps. NaN is the sharp one: it
		// fails every comparison, so a bare `sec <= 0` lets it through.
		if math.IsNaN(sec) || sec <= 0 || sec > maxEpochSec {
			return time.Time{}, false
		}
		return time.UnixMilli(int64(sec * 1e3)).UTC(), true
	}
	return time.Time{}, false
}

func (c *LogCollector) parseLineWith(parser *gonx.Parser, line, path string) {
	entry, err := parser.ParseString(line)
	if err != nil {
		return
	}

	// Read the field map once instead of calling entry.Field per name: on a
	// miss gonx builds an error with fmt.Errorf("%+v", *entry), formatting the
	// entire record into a string that the `_` here throws away. A format
	// without $request_method/$msec/$time_iso8601 misses three times per line,
	// which costs more than the parse itself. Fields() returns the same map
	// with no copy, so each lookup below is a plain index.
	fields := entry.Fields()

	p := c.fillLine(func(name string) string { return fields[name] })
	c.finishLine(&p, path)
}

// fillLine assembles a ParsedLine from a field accessor. All three parse paths
// (text, JSON-into-map, JSON-into-struct) share it: they differ only in how a
// field is looked up by name, and keeping the assembly in one place is what
// stops them from drifting — the typed JSON path once carried its own URI
// resolution and silently disagreed with the other two for a year.
func (c *LogCollector) fillLine(get func(string) string) ParsedLine {
	var p ParsedLine
	p.Status = get("status")
	p.BodyBytesSent = get("body_bytes_sent")
	p.RequestTime = get("request_time")
	p.UpstreamResponseTime = get("upstream_response_time")
	p.UpstreamStatus = get("upstream_status")
	p.UpstreamCacheStatus = get("upstream_cache_status")
	p.URI, p.RawURI = resolveURI(get)
	p.Method = c.resolveMethod(get)
	p.Time = c.resolveTime(get)
	p.Platform = resolveClientField(get, PlatformCandidates)
	p.AppVersion = resolveClientField(get, AppVersionCandidates)
	p.VisitorID = resolveClientField(get, VisitorIDCandidates)
	p.RequestID = resolveClientField(get, requestIDCandidates)

	for i, f := range c.extractFields {
		if i >= len(p.Extras) {
			break
		}
		p.Extras[i] = get(f)
		p.NExtras = i + 1
	}
	return p
}

func (c *LogCollector) ParseJSONLine(line string) {
	c.parseJSONLine(line, "")
}

func (c *LogCollector) parseJSONLine(line, path string) {
	// When extra fields are needed, unmarshal into a generic map once — it is
	// the only shape that can answer for a field name the struct below has no
	// tag for. It costs ~18% more wall time and ~60% more garbage per line
	// (BenchmarkParseJSONLine), which is why the struct path stays for hosts
	// that need no extra fields.
	if len(c.extractFields) > 0 {
		var m map[string]logValue
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			return
		}

		p := c.fillLine(func(name string) string { return string(m[name]) })
		c.finishLine(&p, path)
		return
	}

	var entry jsonLogEntry
	if err := json.Unmarshal([]byte(line), &entry); err != nil {
		return
	}

	p := c.fillLine(entry.field)
	c.finishLine(&p, path)
}

func (c *LogCollector) finishLine(p *ParsedLine, path string) {
	c.recordLine(p)
	if len(c.observers) == 0 {
		return
	}
	for _, o := range c.observers {
		o.OnLogLine(p, path)
	}
}

// logValue is a log field that accepts both JSON shapes operators write. An
// nginx JSON log_format is a hand-written template, and numeric-looking
// variables are routinely emitted unquoted ('"msec":$msec', '"status":$status').
// A plain string field rejects those, and since a decode error drops the whole
// line, a single unquoted field costs the host every nginx metric and every
// bot-log event — silently, with nothing but the missing series to go on.
type logValue string

func (v *logValue) UnmarshalJSON(b []byte) error {
	if len(b) >= 2 && b[0] == '"' {
		// Fast path: an nginx log value with no escape sequence is the norm
		// (escape=json emits \xNN only for control bytes), and unquoting it is
		// a reslice. Handing every field to the decoder instead roughly
		// doubles decode cost on the tail goroutine's hot path.
		if body := b[1 : len(b)-1]; bytes.IndexByte(body, '\\') < 0 {
			*v = logValue(body)
			return nil
		}
		return json.Unmarshal(b, (*string)(v))
	}
	if string(b) == "null" {
		*v = ""
		return nil
	}
	*v = logValue(b) // number or bool literal — kept verbatim, as if quoted
	return nil
}

// jsonLogEntry represents a single JSON-formatted nginx access log line.
//
// Only the fields nginx can plausibly emit unquoted are logValue; the rest are
// plain strings on purpose. json/v2 interns repeated string values across lines
// through a decoder-level cache, and a type with its own UnmarshalJSON opts out
// of it — spending logValue where it buys nothing cost 8 extra allocations per
// line, on values that repeat constantly in an access log (method, host, cache
// status).
type jsonLogEntry struct {
	Status               logValue `json:"status"`
	BodyBytesSent        logValue `json:"body_bytes_sent"`
	RequestTime          logValue `json:"request_time"`
	UpstreamResponseTime logValue `json:"upstream_response_time"`
	Msec                 logValue `json:"msec"`

	UpstreamCacheStatus string `json:"upstream_cache_status"`
	RequestURI          string `json:"request_uri"`
	Request             string `json:"request"`
	URI                 string `json:"uri"`
	Args                string `json:"args"`
	QueryString         string `json:"query_string"`
	RequestMethod       string `json:"request_method"`
	TimeISO8601         string `json:"time_iso8601"`
	TimeLocal           string `json:"time_local"`
	HTTPPlatform        string `json:"http_platform"`
	HTTPVersion         string `json:"http_version"`
	UIDGot              string `json:"uid_got"`
	UIDSet              string `json:"uid_set"`
	RequestID           string `json:"request_id"`
	HTTPXRequestID      string `json:"http_x_request_id"`
	UpstreamStatus      string `json:"upstream_status"`
}

// field answers by nginx variable name so the typed decode path can be filled
// by the same fillLine as the map one. The two carried separate URI logic
// before, and the typed copy silently lagged: it counted nginx's "-"
// placeholder as a real path (uri="/-") and knew nothing about formats that log
// $uri and $args as separate fields. It must answer for every field the struct
// decodes, or a resolver written against get would work on one path only.
//
// Names outside the struct — an operator's renamed key — return "". Those are
// only reachable through the map path, which every format needing extra fields
// already takes.
func (e *jsonLogEntry) field(name string) string {
	switch name {
	case "status":
		return string(e.Status)
	case "body_bytes_sent":
		return string(e.BodyBytesSent)
	case "request_time":
		return string(e.RequestTime)
	case "upstream_response_time":
		return string(e.UpstreamResponseTime)
	case "msec":
		return string(e.Msec)
	case "upstream_cache_status":
		return e.UpstreamCacheStatus
	case "request_uri":
		return e.RequestURI
	case "request":
		return e.Request
	case "uri":
		return e.URI
	case "args":
		return e.Args
	case "query_string":
		return e.QueryString
	case "request_method":
		return e.RequestMethod
	case "time_iso8601":
		return e.TimeISO8601
	case "time_local":
		return e.TimeLocal
	case "http_platform":
		return e.HTTPPlatform
	case "http_version":
		return e.HTTPVersion
	case "request_id":
		return e.RequestID
	case "http_x_request_id":
		return e.HTTPXRequestID
	case "upstream_status":
		return e.UpstreamStatus
	case "uid_got":
		return e.UIDGot
	case "uid_set":
		return e.UIDSet
	}
	return ""
}

// maxMethodLen caps an accepted verb. Longest IANA-registered method is
// "VERSION-CONTROL" (15); 16 leaves one char of headroom without letting a
// hostile $request grow the receiver's LowCardinality dictionary.
const maxMethodLen = 16

// MethodCandidates and TimeCandidates are the nginx variables that can carry
// the request verb and the request timestamp, in resolution order. They are
// exported because botlog detects which of them an operator's log_format
// contains: detection and resolution must walk the same names in the same
// order, or the agent warns about a missing field it then reads happily —
// or, worse, reports a timestamp of a precision it did not resolve.
var (
	MethodCandidates = []string{"request_method", "request"}

	// Ordered by precision: $msec carries milliseconds, $time_iso8601 and
	// $time_local only whole seconds.
	TimeCandidates = []string{"msec", "time_iso8601", "time_local"}

	// URICandidates is the order resolveURI walks. Exported for the same reason
	// as the two above: a check that decides whether a format is usable must
	// name the same variables the parse path reads, or its verdict stops
	// describing what the agent will actually do.
	URICandidates = []string{"request_uri", "request", "uri"}

	// Client field candidates. Names are nginx variables, not the keys an
	// operator chose in the log line: gonx names fields after the variable, so
	// `platform="$http_platform"` is read as http_platform.
	PlatformCandidates   = []string{"http_platform"}
	AppVersionCandidates = []string{"http_version"}
	VisitorIDCandidates  = []string{"uid_got", "uid_set"}
	// $request_id is nginx's own; the http_ variant is what a load balancer in
	// front of it passes down. Unexported unlike the lists above: those are
	// walked by the format checks in weblog and by the alias detector, so the
	// two must agree on the same names in the same order. Nothing outside this
	// package reads this one.
	requestIDCandidates = []string{"request_id", "http_x_request_id"}
)

// methodOf coerces one logged value into a request verb. The value is either a
// bare verb ($request_method) or a whole request line ($request, "GET /x
// HTTP/1.1") — operators log either under either field name, so one function
// accepts both shapes. Empty when neither applies: callers must NOT substitute
// a default verb, because a guessed GET is indistinguishable from a real one,
// which hides POST floods against login/checkout in exactly the traffic this
// data is collected to inspect.
func methodOf(s string) string {
	if v := validMethod(s); v != "" {
		return v
	}
	if i := strings.IndexByte(s, ' '); i > 0 {
		return validMethod(s[:i])
	}
	return ""
}

// validMethod accepts uppercase ASCII tokens of a sane length, allowing the
// interior hyphen the two dashed IANA methods carry (VERSION-CONTROL,
// BASELINE-CONTROL). $request is verbatim client input: without this, a
// scanner sending binary or randomized verbs writes unbounded distinct values
// into a downstream LowCardinality column (same class of bug as the
// normalizeURI binary bypass). A leading or trailing hyphen is rejected, which
// also covers nginx's "-" placeholder for an absent value.
func validMethod(s string) string {
	if s == "" || len(s) > maxMethodLen {
		return ""
	}
	for i := range len(s) {
		switch c := s[i]; {
		case c >= 'A' && c <= 'Z':
		case c == '-' && i > 0 && i < len(s)-1:
		default:
			return ""
		}
	}
	return s
}

// resolveMethod and resolveTime try the operator's resolved field name first
// (LogConfig.MethodField / TimeField, detected from the log_format), then the
// canonical candidates in order, stopping at the first hit — a format logging
// $msec pays one lookup, not three. Both parse paths address fields by name, so
// the two resolvers are shared between them.
func (c *LogCollector) resolveMethod(get func(string) string) string {
	if c.methodField != "" {
		if v := methodOf(get(c.methodField)); v != "" {
			return v
		}
	}
	for _, name := range MethodCandidates {
		if v := methodOf(get(name)); v != "" {
			return v
		}
	}
	return ""
}

// resolveClientField walks the candidate variable names and returns the first
// usable value. nginx writes "-" for an absent value, and that placeholder must
// not reach the receiver: it would become a distinct value in a LowCardinality
// column and a bogus visitor identity shared by every anonymous request.
// Walked per line rather than narrowed at startup on purpose: a JSON access log
// whose log_format discovery could not read still yields these keys, and
// deciding from the format string would drop them silently on exactly those
// hosts. Seven map probes against a ~3.4 µs parse is not the trade to make.
//
// Known gap: this resolves canonical nginx variable names only. Method and Time
// take the stronger path — app.go resolves an operator's renamed field through
// FieldAliases and passes it in LogConfig — so a JSON format writing
// `"rid":"$request_id"` yields Method but not RequestID. Closing it means
// extending FieldAliases to the five typed fields; see docs/metrics.md.
func resolveClientField(get func(string) string, candidates []string) string {
	for _, name := range candidates {
		if v := get(name); v != "" && v != "-" {
			return v
		}
	}
	return ""
}

func (c *LogCollector) resolveTime(get func(string) string) string {
	if c.timeField != "" {
		if v := get(c.timeField); v != "" && v != "-" {
			return v
		}
	}
	for _, name := range TimeCandidates {
		if v := get(name); v != "" && v != "-" {
			return v
		}
	}
	return ""
}

// rawURIFromRequest extracts the un-normalized request URI (path + query) from
// "$request" (e.g. "GET /news/12345?utm=x HTTP/1.1"). Returns "" if malformed.
func rawURIFromRequest(request string) string {
	parts := strings.SplitN(request, " ", 3)
	if len(parts) < 2 {
		return ""
	}
	return parts[1]
}

// StripQuery cuts a raw URI at the query separator. Exported for observers that
// filter on the path alone.
func StripQuery(p string) string {
	if i := strings.IndexByte(p, '?'); i >= 0 {
		return p[:i]
	}
	return p
}

// resolveURI walks the nginx URI variables an operator might log in priority
// order — $request_uri (path+query, as received), then $request (combined
// "METHOD URI HTTP"), then $uri (+ optional $args/$query_string for splits).
// Returns the normalized URI (for metrics cardinality) and the un-normalized
// RawURI (full path + query) for botlog. get returns "" for absent fields.
func resolveURI(get func(string) string) (uri, rawURI string) {
	if v := get(URICandidates[0]); v != "" && v != "-" {
		return normalizePath(StripQuery(v)), v
	}
	if v := get(URICandidates[1]); v != "" && v != "-" {
		return normalizeURI(v), rawURIFromRequest(v)
	}
	if v := get(URICandidates[2]); v != "" && v != "-" {
		args := get("args")
		if args == "" || args == "-" {
			args = get("query_string")
		}
		// stripQuery on the metric URI is defensive — nginx $uri is path-only
		// per spec, but operators occasionally log $request_uri under the
		// "uri" field name and query strings must never reach metric labels.
		metricURI := normalizePath(StripQuery(v))
		if args != "" && args != "-" {
			return metricURI, joinPathArgs(v, args)
		}
		// No separate args field — preserve v verbatim so RawURI keeps any
		// accidental query string the operator's format carried through.
		return metricURI, v
	}
	return "", ""
}

// joinPathArgs reattaches a separate $args / $query_string value onto an
// $uri path. nginx's $uri is path-only and $args is the raw query string
// without a leading '?'; some operators log them as distinct fields, which
// strips the query unless we rejoin them here. stripQuery on path is
// defensive — guards against operators who log $request_uri under the
// "uri" field name by mistake.
func joinPathArgs(path, args string) string {
	path = StripQuery(path)
	args = strings.TrimPrefix(args, "?")
	if args == "" || args == "-" {
		return path
	}
	return path + "?" + args
}

// recordLine updates all metric accumulators from a parsed log line. Must not be called concurrently.
func (c *LogCollector) recordLine(p *ParsedLine) { //nolint:gocognit,nestif
	c.mu.Lock()
	defer c.mu.Unlock()

	if status := p.Status; status != "" { //nolint:nestif
		if len(c.labelFields) == 0 {
			c.statusCounts[status]++
		} else {
			// Pull label values out of ParsedLine.Extras using labelIdx so
			// ExtractFields can be a superset (e.g. botlog adds http_user_agent
			// for event enrichment without making it a Prometheus label).
			key := taggedStatusKey{status: status, n: len(c.labelFields)}
			for k, idx := range c.labelIdx {
				var v string
				if idx >= 0 && idx < p.NExtras {
					v = p.Extras[idx]
				}
				if v == "-" {
					v = ""
				}
				key.extra[k] = v
			}
			if _, ok := c.taggedCounts[key]; ok || len(c.taggedCounts) < maxCardinalityTagged {
				c.taggedCounts[key]++
			}
		}

		uri := p.URI
		now := nowUnix()

		if strings.HasPrefix(status, "5") && uri != "" {
			c.uri5xx.add(statusURI{status, uri}, statusURI{status, overflowMarker}, 1, now)
		}

		if strings.HasPrefix(status, "4") && uri != "" {
			c.uri4xx.add(statusURI{status, uri}, statusURI{status, overflowMarker}, 1, now)
		}

		if v, err := strconv.ParseInt(p.BodyBytesSent, 10, 64); err == nil {
			c.bytesTotal.Add(v)
			if uri != "" {
				c.bytesByURI.add(uri, overflowMarker, uint64(v), now)
			}
		}
	}

	if v, err := strconv.ParseFloat(p.RequestTime, 64); err == nil {
		c.reqCount++
		c.reqSum += v
		c.reqBuckets[bucketIndex(v)]++
	}

	if s := p.UpstreamResponseTime; s != "" {
		if i := strings.IndexByte(s, ','); i > 0 {
			s = strings.TrimSpace(s[:i])
		}
		if v, err := strconv.ParseFloat(s, 64); err == nil {
			c.upCount++
			c.upSum += v
			c.upBuckets[bucketIndex(v)]++
		}
	}

	if s := p.UpstreamCacheStatus; s != "" && s != "-" {
		c.cacheCounts[s]++
	}
}

func normalizeURI(request string) string {
	parts := strings.SplitN(request, " ", 3)
	// A well-formed $request is "METHOD URI HTTP/x.y" — at least one space.
	// Binary handshakes (TLS ClientHello hitting an HTTP port, SSH probes, etc.)
	// arrive as a single space-less blob; without this guard they bypassed
	// normalizePath entirely and pushed raw bytes into the uri label, blowing
	// past Prometheus' 256-byte cap.
	if len(parts) < 2 {
		return invalidMarker
	}
	path := parts[1]
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	return normalizePath(path)
}

func normalizePath(path string) string {
	// Sanity cap on input: nginx limits $uri via large_client_header_buffers
	// (default 8KB) but we shouldn't trust upstream. 1KB covers any real URL;
	// longer payloads are garbage and would amplify the regex pipeline below.
	if len(path) > maxRawPathBytes {
		return invalidMarker
	}
	// Non-printable / invalid UTF-8 — TLS handshake garbage, SSH probes, etc.
	if !utf8.ValidString(path) {
		return invalidMarker
	}
	// Single byte-scan covering three checks at once:
	//  - control bytes (< 0x20): raw binary in $uri (rare; mostly caught by utf8 above)
	//  - `\x` literal escape: nginx writes non-printable bytes as printable
	//    `\xHH` text before logging, defeating the control-byte check above
	//  - hasUpper: gates two downstream allocations on the all-lowercase path
	//    (longBase64Token regex below, and the strings.ToLower call right after).
	hasUpper := false
	for i := range len(path) {
		c := path[i]
		if c < 0x20 {
			return invalidMarker
		}
		if c == '\\' && i+1 < len(path) && path[i+1] == 'x' {
			return invalidMarker
		}
		if c >= 'A' && c <= 'Z' {
			hasUpper = true
		}
	}

	// Scanner probe suffixes (.env, .git, .aws, etc.) — case-insensitive scan,
	// but lower-casing the path allocates a copy; skip when already lowercase.
	haystack := path
	if hasUpper {
		haystack = strings.ToLower(path)
	}
	for _, suffix := range scannerSuffixes {
		if strings.Contains(haystack, suffix) {
			return "/:bot-scanners"
		}
	}

	// Normalize .php filenames: /foo/bar.php → /foo/:file.php
	path = phpFile.ReplaceAllString(path, "/:file.php")

	path = uuidSegment.ReplaceAllString(path, ":uuid")
	path = base64Token.ReplaceAllString(path, ":token")
	path = xenForoSlug.ReplaceAllString(path, "/:slug/")
	path = urlEncodedSegment.ReplaceAllString(path, "/:slug")
	path = hexHash.ReplaceAllString(path, ":hash")
	path = numericSegment.ReplaceAllString(path, "/:id")
	path = slugWithID.ReplaceAllString(path, "/:slug/")
	path = hyphenSlug.ReplaceAllString(path, "/:slug")
	path = fileNumericSuffix.ReplaceAllString(path, "_:id")

	// Long base64-ish segments (mixed case = random token, not a slug) → /:rest.
	// Slug heuristic: hyphenated all-lowercase strings are product/article URLs
	// and stay readable; anything with uppercase is treated as a random token.
	if hasUpper {
		path = longBase64Token.ReplaceAllStringFunc(path, func(m string) string {
			for i := 1; i < len(m); i++ { // skip leading `/`
				if m[i] >= 'A' && m[i] <= 'Z' {
					return restMarker
				}
			}
			return m
		})
	}

	out := truncatePath(path, maxPathDepth)
	// Hard byte cap: even after all the above, a single segment can carry
	// 256+ bytes (long transliterated slugs, concatenated normalized markers).
	// Prometheus rejects label values >256 bytes, so trim with restMarker
	// as a final guard. TruncateAtRune walks back to a rune boundary so a
	// multi-byte UTF-8 tail (Cyrillic, CJK) is never cut mid-rune.
	if len(out) > maxNormalizedURIBytes {
		return topsrv.TruncateAtRune(out, maxNormalizedURIBytes-len(restMarker)) + restMarker
	}
	return out
}

// truncatePath collapses path segments beyond maxDepth into restMarker.
// Trailing slash is not counted as an extra segment.
func truncatePath(path string, maxDepth int) string {
	trimmed := strings.TrimRight(path, "/")
	depth := 0
	for i := 1; i < len(trimmed); i++ {
		if trimmed[i] == '/' {
			depth++
			if depth >= maxDepth {
				return trimmed[:i] + restMarker
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
