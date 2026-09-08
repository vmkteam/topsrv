package weblog

import (
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/vmkteam/topsrv/internal/topsrv/botlog"
	"github.com/vmkteam/topsrv/internal/topsrv/nginx"
	"github.com/vmkteam/topsrv/internal/topsrv/shipper"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordingSink stands in for the pusher: the observer's contract is "which
// lines become events, and what the event carries", and that needs no batching.
type recordingSink struct{ events []shipper.Event }

func (s *recordingSink) Enqueue(ev shipper.Event) { s.events = append(s.events, ev) }

// extractFields is the layout the collector would produce for the default
// aliases plus $proxy_host, which the web stream adds.
func extractFields() []string {
	return append(botlog.RequiredFields(botlog.DefaultAliases()), "proxy_host")
}

// line builds a ParsedLine with the Extras laid out as extractFields orders them.
func line(t *testing.T, ua, proxyHost string) *nginx.ParsedLine {
	t.Helper()
	values := map[string]string{
		"http_user_agent": ua,
		"host":            "site.example.com",
		"server_name":     "site.example.com",
		"remote_addr":     "203.0.113.7",
		"http_referer":    "https://site.example.com/",
		"proxy_host":      proxyHost,
	}
	p := &nginx.ParsedLine{
		Status:               "200",
		URI:                  "/:id",
		RawURI:               "/profile/42?tab=lists",
		BodyBytesSent:        "1024",
		RequestTime:          "0.031",
		UpstreamResponseTime: "0.029",
		Method:               "GET",
		Time:                 "2026-09-08T12:00:00+03:00",
	}
	fields := extractFields()
	require.LessOrEqual(t, len(fields), nginx.MaxExtras)
	for i, name := range fields {
		p.Extras[i] = values[name]
	}
	p.NExtras = len(fields)
	return p
}

func newObserver(t *testing.T, cfg *Config, filters Filters) (*Observer, *recordingSink) {
	t.Helper()
	sink := &recordingSink{}
	// A real registry rather than nil metrics: the counters are part of what
	// the observer does, and a nil-tolerant metrics type exists only to serve
	// tests that skip them.
	o := NewObserver(sink, NewMetrics(prometheus.NewRegistry(), 1), cfg, "web01", []string{tailedPath},
		extractFields(), botlog.DefaultAliases(), filters)
	return o, sink
}

func TestObserverFilters(t *testing.T) {
	const browserUA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 " +
		"(KHTML, like Gecko) Chrome/128.0 Safari/537.36"

	// The observer runs on every line of every tailed file, including the ones
	// this stream did not ask for.
	t.Run("line from an untailed file is dropped", func(t *testing.T) {
		o, sink := newObserver(t, &Config{}, Filters{})
		o.OnLogLine(line(t, browserUA, "backend"), "/var/log/nginx/other.log")
		assert.Empty(t, sink.events)
	})

	t.Run("RequireUpstream drops what never reached a backend", func(t *testing.T) {
		o, sink := newObserver(t, &Config{}, Filters{RequireUpstream: true})

		p := line(t, browserUA, "backend")
		p.UpstreamResponseTime = "-" // served from disk
		o.OnLogLine(p, tailedPath)
		assert.Empty(t, sink.events, "nginx logs a dash when no upstream was used")

		p = line(t, browserUA, "backend")
		p.UpstreamResponseTime = ""
		o.OnLogLine(p, tailedPath)
		assert.Empty(t, sink.events, "an empty field means the same thing")

		o.OnLogLine(line(t, browserUA, "backend"), tailedPath)
		assert.Len(t, sink.events, 1)
	})

	t.Run("Upstreams keeps only the allowlisted backends", func(t *testing.T) {
		o, sink := newObserver(t, &Config{Upstreams: []string{"backend"}}, Filters{Upstreams: true})

		o.OnLogLine(line(t, browserUA, "media"), tailedPath)
		assert.Empty(t, sink.events)

		o.OnLogLine(line(t, browserUA, "backend"), tailedPath)
		assert.Len(t, sink.events, 1)
	})

	// A format without $proxy_host makes the allowlist unreadable; applying it
	// anyway would drop every line and read as "no traffic".
	t.Run("Upstreams is inert when the format cannot feed it", func(t *testing.T) {
		o, sink := newObserver(t, &Config{Upstreams: []string{"backend"}}, Filters{})
		o.OnLogLine(line(t, browserUA, ""), tailedPath)
		assert.Len(t, sink.events, 1)
	})

	// Prefixes match the raw path, not the normalized URI: a rule written
	// against /:id would otherwise depend on the normalizer's current shape.
	t.Run("ExcludePathPrefixes matches the raw path", func(t *testing.T) {
		cfg := &Config{ExcludePathPrefixes: []string{"/static/", "/_build/"}}
		o, sink := newObserver(t, cfg, Filters{})

		p := line(t, browserUA, "backend")
		p.RawURI = "/static/app.css?v=3"
		p.URI = "/:rest"
		o.OnLogLine(p, tailedPath)
		assert.Empty(t, sink.events)

		p = line(t, browserUA, "backend")
		p.RawURI = "/staticky/page" // prefix, not path component — still a prefix match by design
		p.URI = "/:rest"
		o.OnLogLine(p, tailedPath)
		assert.Len(t, sink.events, 1)
	})

	// The whole reason this stream exists: a scraper on a plain browser UA is
	// invisible to the bot stream, so a non-match here must still ship.
	t.Run("UA is a signal, not a gate", func(t *testing.T) {
		o, sink := newObserver(t, &Config{}, Filters{})

		o.OnLogLine(line(t, browserUA, "backend"), tailedPath)
		require.Len(t, sink.events, 1)
		assert.False(t, sink.events[0].UAMatched)
		assert.Empty(t, sink.events[0].BotFamily)

		o.OnLogLine(line(t, "Googlebot/2.1 (+http://www.google.com/bot.html)", "backend"), tailedPath)
		require.Len(t, sink.events, 2)
		assert.True(t, sink.events[1].UAMatched)
		assert.NotEmpty(t, sink.events[1].BotFamily)
	})
}

func TestObserverEventFields(t *testing.T) {
	o, sink := newObserver(t, &Config{URITruncate: 2048, UATruncate: 1024}, Filters{})

	p := line(t, "Mozilla/5.0", "backend")
	p.Platform = "ios"
	p.AppVersion = "7.4.1"
	p.VisitorID = "AgAAAGpxAAABc2Vzc2lvbg=="
	o.OnLogLine(p, tailedPath)

	require.Len(t, sink.events, 1)
	ev := sink.events[0]

	assert.Equal(t, "web01", ev.AgentHostname, "the node the line was read on")
	assert.Equal(t, "site.example.com", ev.Host, "the vhost the client asked for")
	assert.Equal(t, "/profile/42?tab=lists", ev.URI, "the raw URI ships, query included")
	assert.Equal(t, "GET", ev.Method)
	assert.Equal(t, "203.0.113.7", ev.RemoteAddr)

	// Web-only fields — what the bot stream has no place for.
	assert.True(t, ev.ReachedUpstream)
	assert.Equal(t, "backend", ev.ProxyHost)
	assert.Equal(t, "ios", ev.Platform)
	assert.Equal(t, "7.4.1", ev.AppVersion)
	assert.Equal(t, "AgAAAGpxAAABc2Vzc2lvbg==", ev.VisitorID)

	// The stream boundary moves when the list changes, so "not a bot" and "the
	// list did not know it yet" have to stay distinguishable downstream.
	assert.Equal(t, botlog.UAListVersion, ev.UAListVersion)
}

func TestObserverProxyHostPlaceholder(t *testing.T) {
	// nginx writes a dash for an absent value; shipping it would create a
	// "-" bucket in a low-cardinality column downstream.
	o, sink := newObserver(t, &Config{}, Filters{})
	o.OnLogLine(line(t, "Mozilla/5.0", "-"), tailedPath)

	require.Len(t, sink.events, 1)
	assert.Empty(t, sink.events[0].ProxyHost)
}

func TestObserverTruncatesURI(t *testing.T) {
	// Probes send multi-kilobyte URIs with encoded payloads, and the receiver
	// stores this verbatim.
	o, sink := newObserver(t, &Config{URITruncate: 64}, Filters{})

	p := line(t, "Mozilla/5.0", "backend")
	p.RawURI = "/search?q=" + string(make([]byte, 4096))
	o.OnLogLine(p, tailedPath)

	require.Len(t, sink.events, 1)
	assert.Len(t, sink.events[0].URI, 64)
}

// Referer is client-controlled and unbounded — nginx accepts header values up
// to large_client_header_buffers (8 KB by default). At one event per request an
// uncapped one inflates every batch and the send queue behind it.
func TestObserverTruncatesReferer(t *testing.T) {
	o, sink := newObserver(t, &Config{URITruncate: 32}, Filters{})

	p := line(t, "Mozilla/5.0", "backend")
	p.Extras[slices.Index(extractFields(), "http_referer")] = "https://example.com/?q=" + strings.Repeat("x", 8192)
	o.OnLogLine(p, tailedPath)

	require.Len(t, sink.events, 1)
	assert.Len(t, sink.events[0].Referer, 32)
}

// The cut must land on a rune boundary. encodeBatch aborts on the first
// marshal error and encoding/json/v2 refuses invalid UTF-8, so one mid-rune
// cut would drop every event batched alongside it — up to BatchSize of them.
func TestObserverTruncatesURIOnRuneBoundary(t *testing.T) {
	o, sink := newObserver(t, &Config{URITruncate: 10}, Filters{})

	p := line(t, "Mozilla/5.0", "backend")
	p.RawURI = "/поиск/книги" // multi-byte from byte 1; byte 10 lands mid-rune
	o.OnLogLine(p, tailedPath)

	require.Len(t, sink.events, 1)
	assert.True(t, utf8.ValidString(sink.events[0].URI), "truncated URI must stay valid UTF-8")
	assert.LessOrEqual(t, len(sink.events[0].URI), 10)
}
