package botlog

import (
	"strconv"
	"strings"
	"time"

	"github.com/vmkteam/topsrv/internal/topsrv"
	"github.com/vmkteam/topsrv/internal/topsrv/shipper"
)

// Event is one bot-log record on the wire. It lives in shipper because both
// streams send the same shape; botlog keeps the name as an alias so the
// observer and its tests read unchanged.
type Event = shipper.Event

// Fields holds raw nginx fields the observer pulls from a ParsedLine. Strings are
// the verbatim log values (status as decimal, request_time in seconds with a
// decimal point, etc.). Empty fields are dropped or substituted with defaults.
type Fields struct {
	Status               string
	URI                  string
	BodyBytesSent        string
	RequestTime          string // seconds, e.g. "0.123"
	UpstreamResponseTime string // may be a comma-separated chain on retries
	UpstreamCacheStatus  string
	UserAgent            string
	Host                 string // raw request Host header — BuildEvent runs normalizeHost
	ServerName           string // matched nginx vhost config name
	RemoteAddr           string
	Referer              string
	Method               string
}

// NewEvent matches the UA against the bot list and, on match, builds an Event.
// Convenience wrapper around MatchUA + BuildEvent — callers that want to skip
// Fields construction on misses should call MatchUA directly and then BuildEvent.
func NewEvent(now time.Time, agentHostname string, f Fields, extraUAPatterns []string, uaTruncate int) (Event, bool) {
	family, name := MatchUA(f.UserAgent, extraUAPatterns)
	if family == "" {
		return Event{}, false
	}
	return BuildEvent(now, agentHostname, f, family, name, uaTruncate), true
}

// BuildEvent assembles an Event from already-resolved bot family/name. Hot-path
// callers (Observer) use this to avoid constructing Fields when MatchUA misses.
func BuildEvent(now time.Time, agentHostname string, f Fields, family, name string, uaTruncate int) Event {
	return Event{
		TS:            now,
		Host:          normalizeHost(f.Host),
		ServerName:    f.ServerName,
		AgentHostname: agentHostname,
		RemoteAddr:    DashToEmpty(f.RemoteAddr),
		Method:        f.Method,
		URI:           f.URI,
		// Referer arrives already capped: like URI it is a client-controlled URL,
		// and nginx accepts header values up to large_client_header_buffers.
		Referer:                DashToEmpty(f.Referer),
		Status:                 parseStatus(f.Status),
		BodyBytesSent:          parseUint32(f.BodyBytesSent),
		RequestTimeUs:          parseSecondsToMicros(f.RequestTime),
		UpstreamResponseTimeUs: parseSecondsToMicros(firstUpstreamTime(f.UpstreamResponseTime)),
		UpstreamCacheStatus:    DashToEmpty(f.UpstreamCacheStatus),
		UserAgent:              Truncate(f.UserAgent, uaTruncate),
		BotFamily:              family,
		BotName:                name,
	}
}

func parseStatus(s string) uint16 {
	n, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0
	}
	return uint16(n)
}

func parseUint32(s string) uint32 {
	if s == "" || s == "-" {
		return 0
	}
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0
	}
	return uint32(n)
}

// parseSecondsToMicros converts an nginx time field ("0.123") to microseconds.
// Empty / "-" / parse errors / negatives return 0. Values above uint32 max
// saturate (nginx upstream chains can exceed 4000s on misconfigured backends).
func parseSecondsToMicros(s string) uint32 {
	if s == "" || s == "-" {
		return 0
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil || v < 0 {
		return 0
	}
	us := v * 1e6
	if us > float64(^uint32(0)) {
		return ^uint32(0)
	}
	return uint32(us)
}

// firstUpstreamTime returns the first segment of a comma-separated chain like
// "0.012, 0.034" produced by nginx when a request hits multiple upstreams.
func firstUpstreamTime(s string) string {
	if i := strings.IndexByte(s, ','); i > 0 {
		return strings.TrimSpace(s[:i])
	}
	return s
}

// DashToEmpty drops nginx's placeholder for an absent value. Exported for the
// same reason as Truncate: "the dash is not a value" is one rule, and both
// streams have to apply it identically or the receiver grows a "-" bucket in a
// low-cardinality column.
func DashToEmpty(s string) string {
	if s == "-" {
		return ""
	}
	return s
}

// Truncate caps s at n bytes, n <= 0 meaning "no cap". The cut lands on a rune
// boundary: UA, URI and Host are all client-controlled and routinely carry
// multi-byte UTF-8, and encodeBatch aborts on the first marshal error, so one
// mid-rune cut would drop every event batched alongside it.
//
// Exported because the web stream truncates the same client-controlled strings
// and must not re-derive this — a plain s[:n] there would reintroduce exactly
// the batch-wide loss described above.
func Truncate(s string, n int) string {
	if n <= 0 { // no cap configured; TruncateAtRune would read it as "cut to nothing"
		return s
	}
	return topsrv.TruncateAtRune(s, n)
}
