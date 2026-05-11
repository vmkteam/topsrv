package botlog

import (
	"time"

	"github.com/vmkteam/topsrv/internal/topsrv/nginx"
)

// nginx variable names botlog needs from the log_format.
const (
	fieldUserAgent  = "http_user_agent"
	fieldServerName = "server_name"
	fieldRemoteAddr = "remote_addr"
	fieldReferer    = "http_referer"
)

// Positions in ParsedLine.Extras assigned by ordering of RequiredFields. The
// observer reads these directly to avoid a per-line map lookup.
const (
	idxUA         = 0
	idxServerName = 1
	idxRemoteAddr = 2
	idxReferer    = 3
)

// RequiredFields lists the nginx variables the LogCollector must extract into
// ParsedLine.Extras for the bot-log Observer to work. Order is load-bearing —
// Observer indexes Extras by position (see idxUA etc). TestRequiredFieldsOrder
// guards the mapping; a reorder here that drops the assertion will fail tests.
func RequiredFields() []string {
	return []string{fieldUserAgent, fieldServerName, fieldRemoteAddr, fieldReferer}
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
}

// NewObserver wires an Observer against an already-constructed Pusher.
// hostname is shipped on every event as agentHostname; cfg supplies bot-UA
// patterns and the UA truncate limit (passed explicitly so the Observer does
// not reach into Pusher internals).
func NewObserver(p *Pusher, cfg Config, hostname string) *Observer {
	return &Observer{
		pusher:        p,
		hostname:      hostname,
		uaTruncate:    cfg.UATruncate,
		extraPatterns: cfg.ExtraUAPatterns,
	}
}

// OnLogLine satisfies nginx.LogObserver. Matches the UA first to skip Fields
// construction on the ~90% non-bot traffic — the hot path is one Extras read
// and one substring scan when no bot is seen.
func (o *Observer) OnLogLine(p *nginx.ParsedLine, _ string) {
	if idxUA >= p.NExtras {
		return
	}
	ua := p.Extras[idxUA]
	if ua == "" {
		return
	}
	family, name := MatchUA(ua, o.extraPatterns)
	if family == "" {
		return
	}

	// Bot-log UI groups by actual URL, not the nginx-metrics-normalized form.
	// Fall back to URI if the log format doesn't yield a raw path (legacy
	// $uri after rewrite — less precise but still useful).
	uri := p.RawPath
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
		ServerName:           o.field(p, idxServerName),
		RemoteAddr:           o.field(p, idxRemoteAddr),
		Referer:              o.field(p, idxReferer),
	}, family, name, o.uaTruncate)
	o.pusher.RecordMatch(family)
	o.pusher.Enqueue(ev)
}

func (o *Observer) field(p *nginx.ParsedLine, idx int) string {
	if idx >= p.NExtras {
		return ""
	}
	return p.Extras[idx]
}
