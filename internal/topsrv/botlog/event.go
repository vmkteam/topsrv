package botlog

import (
	"strconv"
	"strings"
	"time"
)

// Event is one bot-log entry shipped to the topsrv.io ingest endpoint. JSON
// tags mirror the documented /v1/bot-logs Input contract — keep them in sync.
// Numeric fields ship 0 when absent (the receiver treats 0 as sentinel
// "not present"); string fields use omitempty so empty values stay off the
// wire and save bytes.
type Event struct {
	TS                     time.Time `json:"ts"`
	Host                   string    `json:"host,omitempty"`
	ServerName             string    `json:"serverName,omitempty"`
	AgentHostname          string    `json:"agentHostname"`
	RemoteAddr             string    `json:"remoteAddr,omitempty"`
	Method                 string    `json:"method,omitempty"`
	URI                    string    `json:"uri"`
	Referer                string    `json:"referer,omitempty"`
	Status                 uint16    `json:"status"`
	BodyBytesSent          uint32    `json:"bodyBytesSent"`
	RequestTimeUs          uint32    `json:"requestTimeUs"`
	UpstreamResponseTimeUs uint32    `json:"upstreamResponseTimeUs"`
	UpstreamCacheStatus    string    `json:"upstreamCacheStatus,omitempty"`
	UserAgent              string    `json:"userAgent,omitempty"`
	BotFamily              string    `json:"botFamily,omitempty"`
	BotName                string    `json:"botName,omitempty"`
}

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
		TS:                     now,
		Host:                   normalizeHost(f.Host),
		ServerName:             f.ServerName,
		AgentHostname:          agentHostname,
		RemoteAddr:             dashToEmpty(f.RemoteAddr),
		Method:                 f.Method,
		URI:                    f.URI,
		Referer:                dashToEmpty(f.Referer),
		Status:                 parseStatus(f.Status),
		BodyBytesSent:          parseUint32(f.BodyBytesSent),
		RequestTimeUs:          parseSecondsToMicros(f.RequestTime),
		UpstreamResponseTimeUs: parseSecondsToMicros(firstUpstreamTime(f.UpstreamResponseTime)),
		UpstreamCacheStatus:    dashToEmpty(f.UpstreamCacheStatus),
		UserAgent:              truncate(f.UserAgent, uaTruncate),
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

func dashToEmpty(s string) string {
	if s == "-" {
		return ""
	}
	return s
}

func truncate(s string, n int) string {
	if n <= 0 || len(s) <= n {
		return s
	}
	return s[:n]
}
