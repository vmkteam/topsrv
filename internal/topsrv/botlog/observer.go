package botlog

import (
	"net"
	"slices"
	"strings"
	"time"

	"github.com/vmkteam/topsrv/internal/topsrv/nginx"
)

// nginx variable names botlog needs from the log_format.
const (
	fieldUserAgent  = "http_user_agent"
	fieldHost       = "host"
	fieldServerName = "server_name"
	fieldRemoteAddr = "remote_addr"
	fieldReferer    = "http_referer"
)

// RequiredFields lists the nginx variables the LogCollector must read into
// ParsedLine.Extras for the bot-log Observer to work. These are NOT promoted
// to Prometheus labels — app.registerLogCollector merges them into
// LogConfig.ExtractFields, leaving operator-supplied ExtraLabels (low
// cardinality) as the only Prometheus label set.
func RequiredFields() []string {
	return []string{fieldUserAgent, fieldHost, fieldServerName, fieldRemoteAddr, fieldReferer}
}

// maxHostLen caps the request Host header value retained on an Event. Picked
// to fit any legal FQDN (DNS RFC 1035 = 253 chars) with headroom for IDN
// punycode plus a bracketed IPv6 literal — anything longer is hostile input.
// Operator-tunable UA truncation lives separately as Config.UATruncate.
const maxHostLen = 256

// normalizeHost lowercases the host and strips an optional `:port` suffix,
// handling bracketed IPv6 literals (`[::1]:80` → `[::1]`). The length cap is
// applied first so SplitHostPort doesn't scan a hostile 8 KB Host header
// (nginx accepts up to large_client_header_buffers without escaping).
func normalizeHost(s string) string {
	s = truncate(s, maxHostLen)
	if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	}
	return strings.ToLower(s)
}

// Observer implements nginx.LogObserver. On every parsed access log line it
// classifies the UA, drops non-bots, and enqueues a fully-built Event onto the
// Pusher. Observer is created once at startup, registered before LogCollector.Run,
// and runs synchronously on the tail goroutine — keep work minimal.
type Observer struct {
	pusher        *Pusher
	hostname      string
	uaTruncate    int
	extraPatterns []string

	// Resolved at construction from the LogCollector's ExtractFields. -1 when
	// the operator's log_format doesn't carry that variable.
	idxUA, idxHost, idxServerName, idxRemoteAddr, idxReferer int
}

// NewObserver wires an Observer against an already-constructed Pusher.
// extractFields must mirror the LogCollector's ExtractFields slice — its
// indices determine where each variable lands in ParsedLine.Extras.
func NewObserver(p *Pusher, cfg Config, hostname string, extractFields []string) *Observer {
	return &Observer{
		pusher:        p,
		hostname:      hostname,
		uaTruncate:    cfg.UATruncate,
		extraPatterns: cfg.ExtraUAPatterns,
		idxUA:         slices.Index(extractFields, fieldUserAgent),
		idxHost:       slices.Index(extractFields, fieldHost),
		idxServerName: slices.Index(extractFields, fieldServerName),
		idxRemoteAddr: slices.Index(extractFields, fieldRemoteAddr),
		idxReferer:    slices.Index(extractFields, fieldReferer),
	}
}

// OnLogLine satisfies nginx.LogObserver. Matches the UA first to skip Fields
// construction on the ~90% non-bot traffic — the hot path is one Extras read
// and one substring scan when no bot is seen.
func (o *Observer) OnLogLine(p *nginx.ParsedLine, _ string) {
	ua := o.field(p, o.idxUA)
	if ua == "" {
		return
	}
	family, name := MatchUA(ua, o.extraPatterns)
	if family == "" {
		return
	}

	// Bot-log UI groups by actual URL, not the nginx-metrics-normalized form.
	// Prefer RawURI (path + query) so HasQueryParams on gatesrv side is meaningful;
	// fall back to RawPath (legacy log formats), then to the normalized URI when
	// nothing else is available.
	uri := p.RawURI
	if uri == "" {
		uri = p.RawPath
	}
	if uri == "" {
		uri = p.URI
	}
	ev := BuildEvent(time.Now(), o.hostname, Fields{
		Status:               p.Status,
		URI:                  uri,
		BodyBytesSent:        p.BodyBytesSent,
		RequestTime:          p.RequestTime,
		UpstreamResponseTime: p.UpstreamResponseTime,
		UpstreamCacheStatus:  p.UpstreamCacheStatus,
		UserAgent:            ua,
		Host:                 o.field(p, o.idxHost),
		ServerName:           o.field(p, o.idxServerName),
		RemoteAddr:           o.field(p, o.idxRemoteAddr),
		Referer:              o.field(p, o.idxReferer),
	}, family, name, o.uaTruncate)
	o.pusher.RecordMatch(family)
	o.pusher.Enqueue(ev)
}

func (o *Observer) field(p *nginx.ParsedLine, idx int) string {
	if idx < 0 || idx >= p.NExtras {
		return ""
	}
	return p.Extras[idx]
}
