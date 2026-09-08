package weblog

import (
	"testing"

	"github.com/vmkteam/topsrv/internal/topsrv/botlog"
	"github.com/vmkteam/topsrv/internal/topsrv/nginx"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	fullFormat = `time="$time_iso8601" host="$host" serverName="$server_name" clientIp="$remote_addr" ` +
		`httpMethod="$request_method" uriPath="$uri" httpStatus=$status bodyBytesSent=$body_bytes_sent ` +
		`requestTime=$request_time upstreamResponseTime="$upstream_response_time" userAgent="$http_user_agent" ` +
		`xRequestId="$request_id" upstreamStatus="$upstream_status"`
	bodyFormat   = fullFormat + ` requestBody="$request_body"`
	cookieFormat = fullFormat + ` cookie="$http_cookie"`
)

// tailedPath is the one path the collector in these tests writes.
const tailedPath = "/var/log/nginx/site.log"

// collector builds the LogConfig the collector would be started with: one
// tailed path, one format.
func collector(format string) nginx.LogConfig {
	return nginx.LogConfig{
		LogPaths:   []string{tailedPath},
		LogFormats: map[string]string{tailedPath: format},
	}
}

func TestCheckFormats(t *testing.T) {
	const path = tailedPath

	t.Run("usable format is tailed without warnings", func(t *testing.T) {
		cfg := &Config{LogPaths: []string{path}}
		tail, _, warnings := CheckFormats(cfg, collector(fullFormat), botlog.DefaultAliases())

		assert.Equal(t, []string{path}, tail)
		assert.Empty(t, warnings)
	})

	// The whole reason this check exists: a format carrying bodies, cookies or
	// credentials is refused outright, not filtered afterwards.
	t.Run("format with request bodies is never tailed", func(t *testing.T) {
		for name, format := range map[string]string{"body": bodyFormat, "cookie": cookieFormat} {
			cfg := &Config{LogPaths: []string{path}}
			tail, _, warnings := CheckFormats(cfg, collector(format), botlog.DefaultAliases())

			assert.Emptyf(t, tail, "%s format must not be tailed", name)
			require.Len(t, warnings, 1)
			assert.Equal(t, KindUnsafeFormat, warnings[0].Kind)
			assert.True(t, warnings[0].Fatal)
		}
	})

	t.Run("path nginx does not write is a configuration error", func(t *testing.T) {
		cfg := &Config{LogPaths: []string{"/var/log/nginx/typo.log"}}
		tail, _, warnings := CheckFormats(cfg, collector(fullFormat), botlog.DefaultAliases())

		assert.Empty(t, tail)
		require.Len(t, warnings, 1)
		assert.Equal(t, KindUnknownPath, warnings[0].Kind)
	})

	t.Run("format without client address or status is unusable", func(t *testing.T) {
		cases := map[string]struct {
			format string
			kind   string
		}{
			"no client ip": {`time="$time_iso8601" uriPath="$uri" httpStatus=$status`, KindNoClientIP},
			"no status":    {`time="$time_iso8601" clientIp="$remote_addr" uriPath="$uri"`, KindIncompleteFormat},
			"no uri":       {`time="$time_iso8601" clientIp="$remote_addr" httpStatus=$status`, KindIncompleteFormat},
		}
		for name, tc := range cases {
			t.Run(name, func(t *testing.T) {
				cfg := &Config{LogPaths: []string{path}}
				tail, _, warnings := CheckFormats(cfg, collector(tc.format), botlog.DefaultAliases())

				assert.Empty(t, tail)
				require.Len(t, warnings, 1)
				assert.Equal(t, tc.kind, warnings[0].Kind)
			})
		}
	})

	// Missing timestamp, verb or upstream time degrade the data but do not make
	// it useless — the operator is told once, and the stream keeps running.
	t.Run("missing optional variables warn but still tail", func(t *testing.T) {
		const minimal = `clientIp="$remote_addr" uriPath="$uri" httpStatus=$status`
		cfg := &Config{LogPaths: []string{path}}
		tail, _, warnings := CheckFormats(cfg, collector(minimal), botlog.DefaultAliases())

		assert.Equal(t, []string{path}, tail)
		kinds := make([]string, 0, len(warnings))
		for _, w := range warnings {
			assert.False(t, w.Fatal)
			kinds = append(kinds, w.Kind)
		}
		assert.ElementsMatch(t,
			[]string{KindNoTimestamp, KindNoMethod, KindNoUpstream, KindNoRequestID, KindNoUpstreamStatus},
			kinds)
	})

	// A filter reading a field the format lacks would drop every line, and a
	// silent zero stream is indistinguishable from "this site has no traffic".
	t.Run("upstream allowlist without proxy_host is reported, not applied", func(t *testing.T) {
		cfg := &Config{LogPaths: []string{path}, Upstreams: []string{"backend"}}
		tail, _, warnings := CheckFormats(cfg, collector(fullFormat), botlog.DefaultAliases())

		assert.Equal(t, []string{path}, tail)
		require.Len(t, warnings, 1)
		assert.Equal(t, KindUpstreamFilterOff, warnings[0].Kind)
		assert.False(t, warnings[0].Fatal)
	})

	t.Run("word boundaries: $request_time is not $request", func(t *testing.T) {
		const noVerb = `clientIp="$remote_addr" uriPath="$uri" httpStatus=$status requestTime=$request_time`
		_, _, warnings := CheckFormats(&Config{LogPaths: []string{path}}, collector(noVerb), botlog.DefaultAliases())

		kinds := map[string]bool{}
		for _, w := range warnings {
			kinds[w.Kind] = true
		}
		assert.True(t, kinds[KindNoMethod], "$request_time must not be read as $request")
	})
}

func TestCheckFormatsFallsBackToDefaultFormat(t *testing.T) {
	// Without discovery there is no per-path format, only the collector's
	// default — the check still has something to read.
	tail, _, warnings := CheckFormats(&Config{LogPaths: []string{tailedPath}},
		nginx.LogConfig{LogPaths: []string{tailedPath}, LogFormat: fullFormat}, botlog.DefaultAliases())

	assert.Equal(t, []string{tailedPath}, tail)
	assert.Empty(t, warnings)
}

func TestCheckFormatsResolvesFilters(t *testing.T) {
	const (
		withUpstream = `clientIp="$remote_addr" uriPath="$uri" httpStatus=$status ` +
			`upstreamResponseTime="$upstream_response_time" proxyHost="$proxy_host"`
		withoutUpstream = `clientIp="$remote_addr" uriPath="$uri" httpStatus=$status`
	)
	full, bare := "/var/log/nginx/api.log", "/var/log/nginx/site.log"
	log := nginx.LogConfig{
		LogPaths:   []string{full, bare},
		LogFormats: map[string]string{full: withUpstream, bare: withoutUpstream},
	}
	on := &Config{RequireUpstream: true, Upstreams: []string{"backend"}}

	t.Run("format carrying both fields enables both filters", func(t *testing.T) {
		on.LogPaths = []string{full}
		_, f, _ := CheckFormats(on, log, botlog.DefaultAliases())
		assert.True(t, f.RequireUpstream)
		assert.True(t, f.Upstreams)
	})

	// One path short of the field disables the filter for the whole host:
	// applying it would drop that file's entire traffic without a trace.
	t.Run("one path short of the fields disables both", func(t *testing.T) {
		on.LogPaths = []string{full, bare}
		_, f, _ := CheckFormats(on, log, botlog.DefaultAliases())
		assert.False(t, f.RequireUpstream)
		assert.False(t, f.Upstreams)
	})

	// Config is the other half of the AND: a usable field with the filter
	// switched off must stay off.
	t.Run("fields present but not configured stays off", func(t *testing.T) {
		_, f, _ := CheckFormats(&Config{LogPaths: []string{full}}, log, botlog.DefaultAliases())
		assert.False(t, f.RequireUpstream)
		assert.False(t, f.Upstreams)
	})
}

// A host logging its client address under an operator-defined name is judged by
// what the parser will read, not by the canonical spelling — otherwise a format
// the observer handles fine is refused outright.
func TestCheckFormatsHonoursResolvedAliases(t *testing.T) {
	const custom = `clientIp="$custom_ip" uriPath="$uri" httpStatus=$status`
	cfg := &Config{LogPaths: []string{tailedPath}}

	_, _, warnings := CheckFormats(cfg, collector(custom), botlog.DefaultAliases())
	require.Len(t, warnings, 1)
	assert.Equal(t, KindNoClientIP, warnings[0].Kind, "canonical names only: refused")

	aliases := botlog.DefaultAliases()
	aliases.RemoteAddr = "custom_ip"
	tail, _, warnings := CheckFormats(cfg, collector(custom), aliases)
	assert.Equal(t, []string{tailedPath}, tail)
	for _, w := range warnings {
		assert.NotEqual(t, KindNoClientIP, w.Kind)
	}
}

// The docs list $request_id and $upstream_status as recommended; the check
// layer has to say the same thing, or an operator learns about an empty column
// weeks later. Advisory only — the path still ships.
func TestCheckFormatsWarnsOnMissingTracingFields(t *testing.T) {
	const noTracing = `time="$time_iso8601" clientIp="$remote_addr" httpMethod="$request_method" ` +
		`uriPath="$uri" httpStatus=$status upstreamResponseTime="$upstream_response_time"`

	tail, _, warnings := CheckFormats(&Config{LogPaths: []string{tailedPath}},
		collector(noTracing), botlog.DefaultAliases())

	assert.Equal(t, []string{tailedPath}, tail, "advisory warnings must not disqualify the path")
	kinds := map[string]bool{}
	for _, w := range warnings {
		assert.False(t, w.Fatal)
		kinds[w.Kind] = true
	}
	assert.True(t, kinds[KindNoRequestID])
	assert.True(t, kinds[KindNoUpstreamStatus])

	// The edge-assigned header counts: an id is an id.
	_, _, warnings = CheckFormats(&Config{LogPaths: []string{tailedPath}},
		collector(noTracing+` xRequestId="$http_x_request_id"`), botlog.DefaultAliases())
	for _, w := range warnings {
		assert.NotEqual(t, KindNoRequestID, w.Kind)
	}
}
