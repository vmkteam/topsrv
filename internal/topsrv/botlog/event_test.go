package botlog

import (
	"encoding/json/v2"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewEvent_GooglebotSmartphone(t *testing.T) {
	now := time.Date(2026, 5, 11, 12, 0, 0, 0, time.UTC)
	ev, ok := NewEvent(now, "web01", Fields{
		Status:               "200",
		URI:                  "/api/series",
		BodyBytesSent:        "12345",
		RequestTime:          "0.150",
		UpstreamResponseTime: "0.120",
		UpstreamCacheStatus:  "HIT",
		UserAgent:            "Mozilla/5.0 (Linux; Android 6.0.1) Googlebot/2.1",
		ServerName:           "example.com",
		RemoteAddr:           "66.249.77.4",
		Method:               "GET",
		Referer:              "-",
	}, nil, 1024)

	require.True(t, ok)
	assert.Equal(t, now, ev.TS)
	assert.Equal(t, "web01", ev.AgentHostname)
	assert.Equal(t, "example.com", ev.ServerName)
	assert.Equal(t, "66.249.77.4", ev.RemoteAddr)
	assert.Equal(t, "/api/series", ev.URI)
	assert.Empty(t, ev.Referer, "dash should be normalised to empty")
	assert.EqualValues(t, 200, ev.Status)
	assert.EqualValues(t, 12345, ev.BodyBytesSent)
	assert.EqualValues(t, 150000, ev.RequestTimeUs)
	assert.EqualValues(t, 120000, ev.UpstreamResponseTimeUs)
	assert.Equal(t, "HIT", ev.UpstreamCacheStatus)
	assert.Equal(t, "google", ev.BotFamily)
	assert.Equal(t, "googlebot-smartphone", ev.BotName)
}

func TestNewEvent_NonBotReturnsFalse(t *testing.T) {
	ev, ok := NewEvent(time.Now(), "web01", Fields{
		Status:    "200",
		URI:       "/",
		UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15",
	}, nil, 1024)
	assert.False(t, ok)
	assert.Empty(t, ev.URI, "zero value on drop")
}

func TestNewEvent_UpstreamChainTakesFirst(t *testing.T) {
	ev, ok := NewEvent(time.Now(), "web01", Fields{
		Status:               "502",
		URI:                  "/",
		UserAgent:            "GPTBot/1.0",
		UpstreamResponseTime: "0.012, 0.034, 0.056",
	}, nil, 1024)
	require.True(t, ok)
	assert.EqualValues(t, 12000, ev.UpstreamResponseTimeUs)
}

func TestNewEvent_TruncatesUA(t *testing.T) {
	long := strings.Repeat("A", 2000)
	ev, ok := NewEvent(time.Now(), "web01", Fields{
		Status:    "200",
		URI:       "/",
		UserAgent: "GPTBot/1.0 " + long,
	}, nil, 100)
	require.True(t, ok)
	assert.Len(t, ev.UserAgent, 100)
}

func TestNewEvent_BadNumericFieldsCoerceToZero(t *testing.T) {
	ev, ok := NewEvent(time.Now(), "web01", Fields{
		Status:               "garbage",
		URI:                  "/",
		BodyBytesSent:        "-",
		RequestTime:          "-",
		UpstreamResponseTime: "",
		UserAgent:            "Googlebot/2.1",
	}, nil, 1024)
	require.True(t, ok)
	assert.EqualValues(t, 0, ev.Status)
	assert.EqualValues(t, 0, ev.BodyBytesSent)
	assert.EqualValues(t, 0, ev.RequestTimeUs)
	assert.EqualValues(t, 0, ev.UpstreamResponseTimeUs)
}

func TestNewEvent_JSONShapeMatchesGatesrvContract(t *testing.T) {
	now := time.Date(2026, 5, 11, 12, 0, 0, 0, time.UTC)
	ev, ok := NewEvent(now, "web01", Fields{
		Status:        "200",
		URI:           "/",
		BodyBytesSent: "100",
		UserAgent:     "GPTBot/1.0",
	}, nil, 1024)
	require.True(t, ok)

	raw, err := json.Marshal(ev)
	require.NoError(t, err)
	s := string(raw)

	// Required fields are always present.
	assert.Contains(t, s, `"ts":`)
	assert.Contains(t, s, `"uri":"/"`)
	assert.Contains(t, s, `"status":200`)
	assert.Contains(t, s, `"agentHostname":"web01"`)
	assert.Contains(t, s, `"botFamily":"openai"`)
	assert.Contains(t, s, `"botName":"gptbot"`)
	assert.Contains(t, s, `"userAgent":"GPTBot/1.0"`)

	// Numeric optionals ship 0 — the receiver treats 0 as sentinel "not present".
	assert.Contains(t, s, `"requestTimeUs":0`)
	assert.Contains(t, s, `"upstreamResponseTimeUs":0`)

	// Empty strings are omitted.
	assert.NotContains(t, s, `"referer"`)
	assert.NotContains(t, s, `"upstreamCacheStatus"`)
}

func TestParseSecondsToMicros(t *testing.T) {
	cases := []struct {
		in   string
		want uint32
	}{
		{"", 0},
		{"-", 0},
		{"0", 0},
		{"0.001", 1000},
		{"0.123", 123000},
		{"1.5", 1500000},
		{"-1.0", 0},
		{"garbage", 0},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			assert.Equal(t, tc.want, parseSecondsToMicros(tc.in))
		})
	}
}

func TestParseSecondsToMicros_SaturatesOnOverflow(t *testing.T) {
	// uint32 max microseconds ≈ 4294.97 seconds. 5000s should saturate.
	assert.Equal(t, ^uint32(0), parseSecondsToMicros("5000"))
}

func TestFirstUpstreamTime(t *testing.T) {
	assert.Equal(t, "0.012", firstUpstreamTime("0.012, 0.034"))
	assert.Equal(t, "0.012", firstUpstreamTime("0.012,0.034"))
	assert.Equal(t, "0.5", firstUpstreamTime("0.5"))
	assert.Empty(t, firstUpstreamTime(""))
}

// $upstream_status carries every attempt on a retry. The last one is what the
// client actually got and the only entry comparable with Status; a naive parse
// of the whole string yields 0 and looks like "the backend never answered".
func TestBuildEventUpstreamStatusChain(t *testing.T) {
	cases := map[string]uint16{
		"200":       200,
		"502, 200":  200, // first attempt failed, retry succeeded
		"-":         0,   // nginx never reached a backend
		"":          0,
		"200 : 404": 0, // not a chain nginx writes — refuse rather than guess
	}
	for in, want := range cases {
		ev := BuildEvent(time.Now(), "web01", Fields{Status: "200", UpstreamStatus: in}, "", "", 1024)
		assert.Equalf(t, want, ev.UpstreamStatus, "upstreamStatus %q", in)
	}
}

// The request id is what ties an event to the backend's own logs. nginx writes
// a dash when the format declares the variable but nothing set it, and that
// placeholder must not travel — the receiver would store it as a literal.
func TestBuildEventRequestID(t *testing.T) {
	const hex32 = "1a7ccaf3ab908eccad1912d7badcc7ac"

	ev := BuildEvent(time.Now(), "web01", Fields{Status: "200", RequestID: hex32}, "", "", 1024)
	assert.Equal(t, hex32, ev.RequestID, "passed through verbatim; the receiver parses it")

	ev = BuildEvent(time.Now(), "web01", Fields{Status: "200", RequestID: "-"}, "", "", 1024)
	assert.Empty(t, ev.RequestID, "empty means 'the format carries none', and the receiver generates one")
}

// $http_x_request_id is a client header, and nginx carries up to
// large_client_header_buffers (8 KB) of it. The receiver would reject the value
// and generate its own id anyway, so shipping it is pure payload — at one event
// per request, enough to inflate every batch on demand.
func TestBuildEventRejectsOversizedRequestID(t *testing.T) {
	hostile := strings.Repeat("A", 8192)
	ev := BuildEvent(time.Now(), "web01", Fields{Status: "200", RequestID: hostile}, "", "", 1024)
	assert.Empty(t, ev.RequestID, "an 8 KB header is not an identifier")

	// A W3C traceparent is 55 chars — the cap must not clip legitimate formats.
	const traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	ev = BuildEvent(time.Now(), "web01", Fields{Status: "200", RequestID: traceparent}, "", "", 1024)
	assert.Equal(t, traceparent, ev.RequestID)
}
