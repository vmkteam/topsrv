package botlog

import (
	"net/http"
	"net/http/httptest"
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
	// RequiredFields contract: the four nginx variables botlog needs read into
	// ParsedLine.Extras. Order is no longer load-bearing (Observer resolves
	// indices at runtime), but the set must stay stable across versions.
	assert.ElementsMatch(t,
		[]string{fieldUserAgent, fieldServerName, fieldRemoteAddr, fieldReferer},
		RequiredFields())
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
	// Default order matches botParsedLine's Extras layout (ua, serverName,
	// remoteAddr, referer) so existing tests' positional assumptions hold.
	o := NewObserver(p, cfg, "web01", RequiredFields())
	return o, p
}

func botParsedLine(ua, serverName, remoteAddr, referer string) *nginx.ParsedLine {
	return &nginx.ParsedLine{
		Status:        "200",
		URI:           "/api",
		BodyBytesSent: "1234",
		RequestTime:   "0.150",
		Extras:        [nginx.MaxExtras]string{ua, serverName, remoteAddr, referer},
		NExtras:       4,
	}
}

func TestObserver_EnqueuesBotEvent(t *testing.T) {
	o, p := newObserverPair(t)

	o.OnLogLine(botParsedLine("Mozilla/5.0 GPTBot/1.0", "api.example.com", "203.0.113.5", "-"), "")

	assert.InDelta(t, 1, testutil.ToFloat64(p.eventsTotal.WithLabelValues(stateEnqueued, "")), 0.01)
	assert.InDelta(t, 1, testutil.ToFloat64(p.matchTotal.WithLabelValues("openai")), 0.01)

	// Pull the event off the queue and inspect.
	select {
	case ev := <-p.queue:
		assert.Equal(t, "openai", ev.BotFamily)
		assert.Equal(t, "gptbot", ev.BotName)
		assert.Equal(t, "api.example.com", ev.ServerName)
		assert.Equal(t, "203.0.113.5", ev.RemoteAddr)
		assert.Empty(t, ev.Referer, "dash referer dropped")
		assert.Equal(t, "web01", ev.AgentHostname)
	case <-time.After(time.Second):
		t.Fatal("event not enqueued")
	}
}

// Verifies the bot-logs UI fix: Event.URI must carry RawPath (un-normalized
// hit URL), not the cardinality-collapsed ParsedLine.URI.
func TestObserver_UsesRawPathOverURI(t *testing.T) {
	o, p := newObserverPair(t)
	pl := &nginx.ParsedLine{
		Status:  "200",
		URI:     "/news/:id/:rest",
		RawPath: "/news/12345/some-title",
		Extras:  [nginx.MaxExtras]string{"GPTBot/1.0", "", "", ""},
		NExtras: 1,
	}
	o.OnLogLine(pl, "")
	require.Len(t, p.queue, 1)
	ev := <-p.queue
	assert.Equal(t, "/news/12345/some-title", ev.URI)
}

// When the log format yields no RawPath (legacy $uri after rewrite), Observer
// must fall back to ParsedLine.URI rather than emit an empty event URI.
func TestObserver_FallsBackToURIWhenRawPathEmpty(t *testing.T) {
	o, p := newObserverPair(t)
	pl := &nginx.ParsedLine{
		Status:  "200",
		URI:     "/news/:id",
		RawPath: "",
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

	o.OnLogLine(botParsedLine("Mozilla/5.0 (Macintosh) Safari/605", "x.example.com", "1.2.3.4", "-"), "")

	assert.InDelta(t, 0, testutil.ToFloat64(p.eventsTotal.WithLabelValues(stateEnqueued, "")), 0.01)
	assert.InDelta(t, 0, testutil.ToFloat64(p.matchTotal.WithLabelValues("openai")), 0.01)
}

func TestObserver_EmptyUAIgnored(t *testing.T) {
	o, p := newObserverPair(t)

	o.OnLogLine(botParsedLine("", "x.example.com", "1.2.3.4", "-"), "")

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
		ExtractFields: RequiredFields(),
	})
	obs := NewObserver(p, cfg, "web01", logC.ExtractFields())
	logC.AddObserver(obs)

	logC.ParseJSONLine(`{"status":"200","body_bytes_sent":"100","request_time":"0.1","request_uri":"/a",` +
		`"http_user_agent":"GPTBot/1.0","server_name":"example.com","remote_addr":"1.2.3.4","http_referer":"-"}`)
	logC.ParseJSONLine(`{"status":"200","body_bytes_sent":"100","request_time":"0.1","request_uri":"/b",` +
		`"http_user_agent":"curl/8.0","server_name":"example.com","remote_addr":"1.2.3.4","http_referer":"-"}`)

	assert.Len(t, p.queue, 1, "only the GPTBot line should land on the queue")
}

// Operator labels come first in ExtractFields; Observer must still find UA at
// its actual position (not assume Extras[0]). Guards against the v0.0.22-rc.2
// compile-time-idx fragility.
func TestObserver_IndicesResolvedAtRuntime(t *testing.T) {
	cfg := Config{
		Enabled: true, Endpoint: "http://x.invalid/", Token: "bl_test", BatchSize: 10,
	}
	require.NoError(t, cfg.Validate(topsrv.PushConfig{}))
	p := NewPusher(embedlog.Logger{}, "topsrv-test", "test", cfg, prometheus.NewRegistry())

	// Operator labels first, botlog's required fields after — UA at index 2.
	extract := []string{"server_name", "http_platform", fieldUserAgent, fieldRemoteAddr, fieldReferer}
	obs := NewObserver(p, cfg, "host1", extract)

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
	obs := NewObserver(p, cfg, "host1", []string{fieldUserAgent})
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
	assert.Empty(t, ev.ServerName)
	assert.Empty(t, ev.RemoteAddr)
	assert.Empty(t, ev.Referer)
}
