package botlog

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vmkteam/topsrv/internal/topsrv"
	"github.com/vmkteam/topsrv/internal/topsrv/nginx"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vmkteam/embedlog"
)

func TestRequiredFieldsContents(t *testing.T) {
	// RequiredFields contract: with default aliases, the returned set covers
	// the five canonical nginx variables botlog needs read into Extras. Order
	// is not load-bearing (Observer resolves indices at runtime), but the set
	// must stay stable across versions.
	assert.ElementsMatch(t,
		[]string{fieldUserAgent, fieldHost, fieldServerName, fieldRemoteAddr, fieldReferer},
		RequiredFields(DefaultAliases()))
}

func TestRequiredFieldsHonoursAliases(t *testing.T) {
	// Custom JSON keys → RequiredFields returns the aliased names.
	a := FieldAliases{UserAgent: "ua", Host: "h", ServerName: "sn", RemoteAddr: "ip", Referer: "ref"}
	assert.ElementsMatch(t, []string{"ua", "h", "sn", "ip", "ref"}, RequiredFields(a))
}

func newObserverPair(t *testing.T) (*Observer, *Pusher) {
	t.Helper()
	cfg := Config{
		Enabled:   true,
		Endpoint:  "http://example.invalid/v1/bot-logs",
		Token:     "bl_test",
		BatchSize: 100,
	}
	require.NoError(t, cfg.Validate(topsrv.PushConfig{}))
	p := NewPusher(embedlog.Logger{}, "topsrv-test", "test", cfg, prometheus.NewRegistry())
	// Tests use the canonical default aliases — ExtractFields and Observer
	// indices line up with botParsedLine's Extras layout.
	o := NewObserver(p, cfg, "web01", RequiredFields(DefaultAliases()), DefaultAliases())
	return o, p
}

func botParsedLine(ua, host, serverName, remoteAddr, referer string) *nginx.ParsedLine {
	return &nginx.ParsedLine{
		Status:        "200",
		URI:           "/api",
		BodyBytesSent: "1234",
		RequestTime:   "0.150",
		Extras:        [nginx.MaxExtras]string{ua, host, serverName, remoteAddr, referer},
		NExtras:       5,
	}
}

func TestObserver_EnqueuesBotEvent(t *testing.T) {
	o, p := newObserverPair(t)

	o.OnLogLine(botParsedLine("Mozilla/5.0 GPTBot/1.0", "api.example.com", "vhost_cfg", "203.0.113.5", "-"), "")

	assert.InDelta(t, 1, testutil.ToFloat64(p.eventsTotal.WithLabelValues(stateEnqueued, "")), 0.01)
	assert.InDelta(t, 1, testutil.ToFloat64(p.matchTotal.WithLabelValues("openai")), 0.01)

	select {
	case ev := <-p.queue:
		assert.Equal(t, "openai", ev.BotFamily)
		assert.Equal(t, "gptbot", ev.BotName)
		assert.Equal(t, "api.example.com", ev.Host, "Host carries the request $host header")
		assert.Equal(t, "vhost_cfg", ev.ServerName, "ServerName carries the matched $server_name")
		assert.Equal(t, "203.0.113.5", ev.RemoteAddr)
		assert.Empty(t, ev.Referer, "dash referer dropped")
		assert.Equal(t, "web01", ev.AgentHostname)
	case <-time.After(time.Second):
		t.Fatal("event not enqueued")
	}
}

// Verifies the bot-logs UI fix: Event.URI must carry RawURI (un-normalized
// hit URL with query string), not the cardinality-collapsed ParsedLine.URI.
func TestObserver_UsesRawURIOverURI(t *testing.T) {
	o, p := newObserverPair(t)
	pl := &nginx.ParsedLine{
		Status:  "200",
		URI:     "/news/:id/:rest",
		RawURI:  "/news/12345/some-title?utm=x",
		Extras:  [nginx.MaxExtras]string{"GPTBot/1.0", "", "", ""},
		NExtras: 1,
	}
	o.OnLogLine(pl, "")
	require.Len(t, p.queue, 1)
	ev := <-p.queue
	assert.Equal(t, "/news/12345/some-title?utm=x", ev.URI)
}

// Pathological bot probes regularly send 4-8KB URIs with base64/SQLi payloads.
// Observer must cap Event.URI at Config.URITruncate before shipping.
func TestObserver_TruncatesURI(t *testing.T) {
	o, p := newObserverPair(t)
	long := "/probe?p=" + strings.Repeat("A", 5000)
	pl := &nginx.ParsedLine{
		Status:  "200",
		URI:     "/probe",
		RawURI:  long,
		Extras:  [nginx.MaxExtras]string{"GPTBot/1.0", "", "", ""},
		NExtras: 1,
	}
	o.OnLogLine(pl, "")
	require.Len(t, p.queue, 1)
	ev := <-p.queue
	assert.Len(t, ev.URI, DefaultURITruncate)
	assert.Equal(t, long[:DefaultURITruncate], ev.URI)
}

// When the log format yields no RawURI (legacy $uri after rewrite), Observer
// must fall back to ParsedLine.URI rather than emit an empty event URI.
func TestObserver_FallsBackToURIWhenRawURIEmpty(t *testing.T) {
	o, p := newObserverPair(t)
	pl := &nginx.ParsedLine{
		Status:  "200",
		URI:     "/news/:id",
		Extras:  [nginx.MaxExtras]string{"GPTBot/1.0", "", "", ""},
		NExtras: 1,
	}
	o.OnLogLine(pl, "")
	require.Len(t, p.queue, 1)
	ev := <-p.queue
	assert.Equal(t, "/news/:id", ev.URI)
}

func TestObserver_NonBotIgnored(t *testing.T) {
	o, p := newObserverPair(t)

	o.OnLogLine(botParsedLine("Mozilla/5.0 (Macintosh) Safari/605", "x.example.com", "", "1.2.3.4", "-"), "")

	assert.InDelta(t, 0, testutil.ToFloat64(p.eventsTotal.WithLabelValues(stateEnqueued, "")), 0.01)
	assert.InDelta(t, 0, testutil.ToFloat64(p.matchTotal.WithLabelValues("openai")), 0.01)
}

func TestObserver_EmptyUAIgnored(t *testing.T) {
	o, p := newObserverPair(t)

	o.OnLogLine(botParsedLine("", "x.example.com", "", "1.2.3.4", "-"), "")

	assert.InDelta(t, 0, testutil.ToFloat64(p.eventsTotal.WithLabelValues(stateEnqueued, "")), 0.01)
}

func TestObserver_LogFormatMissingUAField(t *testing.T) {
	o, p := newObserverPair(t)

	// NExtras=0 — log_format doesn't include http_user_agent at all.
	pl := &nginx.ParsedLine{Status: "200", URI: "/", NExtras: 0}
	o.OnLogLine(pl, "")

	assert.InDelta(t, 0, testutil.ToFloat64(p.eventsTotal.WithLabelValues(stateEnqueued, "")), 0.01)
}

func TestObserver_PartialFields(t *testing.T) {
	// log_format includes only http_user_agent — server_name/remote_addr/referer
	// are absent. Observer should still ship the event with empty serverName etc.
	o, p := newObserverPair(t)

	pl := &nginx.ParsedLine{
		Status:  "200",
		URI:     "/",
		Extras:  [nginx.MaxExtras]string{"Googlebot/2.1", "", "", ""},
		NExtras: 1,
	}
	o.OnLogLine(pl, "")

	require.Len(t, p.queue, 1)
	ev := <-p.queue
	assert.Equal(t, "google", ev.BotFamily)
	assert.Empty(t, ev.ServerName)
	assert.Empty(t, ev.RemoteAddr)
}

func TestObserver_PluggableThroughLogCollector(t *testing.T) {
	// End-to-end: real LogCollector, observer attached, feed two JSON lines
	// through. One bot line lands on the pusher queue; the other doesn't.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer srv.Close()

	cfg := Config{
		Enabled:   true,
		Endpoint:  srv.URL,
		Token:     "bl_test",
		BatchSize: 100,
	}
	require.NoError(t, cfg.Validate(topsrv.PushConfig{}))
	p := NewPusher(embedlog.Logger{}, "topsrv-test", "test", cfg, prometheus.NewRegistry())

	logPath := "/var/log/nginx/access.json"
	// Operator labels here are empty (Prometheus-side); botlog needs the four
	// vars only as extracted fields, not as labels.
	logC := nginx.NewLogCollector(embedlog.Logger{}, nginx.LogConfig{
		LogPaths:      []string{logPath},
		JSONPaths:     map[string]bool{logPath: true},
		ExtractFields: RequiredFields(DefaultAliases()),
	})
	obs := NewObserver(p, cfg, "web01", RequiredFields(DefaultAliases()), DefaultAliases())
	logC.AddObserver(obs)

	logC.ParseJSONLine(`{"status":"200","body_bytes_sent":"100","request_time":"0.1","request_uri":"/a",` +
		`"http_user_agent":"GPTBot/1.0","server_name":"example.com","remote_addr":"1.2.3.4","http_referer":"-"}`)
	logC.ParseJSONLine(`{"status":"200","body_bytes_sent":"100","request_time":"0.1","request_uri":"/b",` +
		`"http_user_agent":"curl/8.0","server_name":"example.com","remote_addr":"1.2.3.4","http_referer":"-"}`)

	assert.Len(t, p.queue, 1, "only the GPTBot line should land on the queue")
}

// Operator labels first in ExtractFields → Observer still finds UA at its
// actual position, not Extras[0].
func TestObserver_IndicesResolvedAtRuntime(t *testing.T) {
	cfg := Config{
		Enabled: true, Endpoint: "http://x.invalid/", Token: "bl_test", BatchSize: 10,
	}
	require.NoError(t, cfg.Validate(topsrv.PushConfig{}))
	p := NewPusher(embedlog.Logger{}, "topsrv-test", "test", cfg, prometheus.NewRegistry())

	// Operator labels first, botlog's required fields after — UA at index 2.
	extract := []string{"server_name", "http_platform", fieldUserAgent, fieldRemoteAddr, fieldReferer}
	obs := NewObserver(p, cfg, "host1", extract, DefaultAliases())

	pl := &nginx.ParsedLine{
		Status:  "200",
		URI:     "/api",
		Extras:  [nginx.MaxExtras]string{"example.com", "ios-3.0", "GPTBot/1.0", "1.2.3.4"},
		NExtras: 4,
	}
	obs.OnLogLine(pl, "")

	require.Len(t, p.queue, 1)
	ev := <-p.queue
	assert.Equal(t, "openai", ev.BotFamily)
	assert.Equal(t, "example.com", ev.ServerName)
	assert.Equal(t, "1.2.3.4", ev.RemoteAddr)
}

// When ExtractFields omits a required botlog variable, Observer must not
// panic — that field just ships empty in the event.
func TestObserver_MissingFieldsSafe(t *testing.T) {
	cfg := Config{
		Enabled: true, Endpoint: "http://x.invalid/", Token: "bl_test", BatchSize: 10,
	}
	require.NoError(t, cfg.Validate(topsrv.PushConfig{}))
	p := NewPusher(embedlog.Logger{}, "topsrv-test", "test", cfg, prometheus.NewRegistry())

	// Only UA — no server_name / remote_addr / referer fields tailed.
	obs := NewObserver(p, cfg, "host1", []string{fieldUserAgent}, DefaultAliases())
	pl := &nginx.ParsedLine{
		Status:  "200",
		URI:     "/a",
		Extras:  [nginx.MaxExtras]string{"GPTBot/1.0"},
		NExtras: 1,
	}
	assert.NotPanics(t, func() { obs.OnLogLine(pl, "") })
	require.Len(t, p.queue, 1)
	ev := <-p.queue
	assert.Equal(t, "openai", ev.BotFamily)
	assert.Empty(t, ev.Host)
	assert.Empty(t, ev.ServerName)
	assert.Empty(t, ev.RemoteAddr)
	assert.Empty(t, ev.Referer)
}

func TestNormalizeHost(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"empty", "", ""},
		{"lowercase", "Example.COM", "example.com"},
		{"strip port", "example.com:8080", "example.com"},
		{"strip port + lowercase", "API.Example.com:443", "api.example.com"},
		{"no port", "example.com", "example.com"},
		{"trailing colon — SplitHostPort accepts empty port", "example.com:", "example.com"},
		{"IPv6 bracketed with port", "[::1]:8080", "::1"},
		// SplitHostPort needs a port to unwrap brackets; bare bracketed
		// literals pass through verbatim. Not a design choice — artifact.
		{"IPv6 bracketed no port", "[2001:db8::1]", "[2001:db8::1]"},
		{"truncate over maxHostLen", strings.Repeat("a", 300), strings.Repeat("a", 256)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, normalizeHost(tc.in))
		})
	}
}

// Host and ServerName are independent: Host carries the (normalized) request
// $host, ServerName carries the matched nginx $server_name. Either may be
// empty if the log_format doesn't include it.
func TestObserver_HostAndServerNameIndependent(t *testing.T) {
	o, p := newObserverPair(t)
	o.OnLogLine(botParsedLine("GPTBot/1.0", "Real.Example.COM:443", "vhost_cfg", "1.2.3.4", "https://prev.example.com/page"), "")

	require.Len(t, p.queue, 1)
	ev := <-p.queue
	assert.Equal(t, "real.example.com", ev.Host, "Host = normalizeHost($host)")
	assert.Equal(t, "vhost_cfg", ev.ServerName, "ServerName = raw $server_name")
	assert.Equal(t, "https://prev.example.com/page", ev.Referer, "non-dash referer passes through")
}

// log_format without $host: Event.Host is empty, ServerName still ships.
func TestObserver_HostMissingShipsEmpty(t *testing.T) {
	o, p := newObserverPair(t)
	o.OnLogLine(botParsedLine("GPTBot/1.0", "", "vhost_cfg", "1.2.3.4", "-"), "")

	require.Len(t, p.queue, 1)
	ev := <-p.queue
	assert.Empty(t, ev.Host)
	assert.Equal(t, "vhost_cfg", ev.ServerName)
}
