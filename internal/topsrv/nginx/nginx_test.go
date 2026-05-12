package nginx

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/satyrius/gonx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vmkteam/embedlog"
)

const stubStatusResponse = `Active connections: 291
server accepts handled requests
 16630948 16630948 31070465
Reading: 6 Writing: 175 Waiting: 110
`

func TestStubCollector(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(stubStatusResponse))
	}))
	defer srv.Close()

	c := NewStubCollector(embedlog.Logger{}, srv.URL)
	assert.Equal(t, "nginx", c.Name())

	reg := prometheus.NewRegistry()
	reg.MustRegister(c)

	mfs, err := reg.Gather()
	require.NoError(t, err)

	metrics := make(map[string]float64)
	for _, mf := range mfs {
		for _, m := range mf.GetMetric() {
			key := mf.GetName()
			var sb strings.Builder
			for _, l := range m.GetLabel() {
				sb.WriteString("{" + l.GetName() + "=" + l.GetValue() + "}")
			}
			key += sb.String()
			if m.GetGauge() != nil {
				metrics[key] = m.GetGauge().GetValue()
			} else if m.GetCounter() != nil {
				metrics[key] = m.GetCounter().GetValue()
			}
		}
	}

	checks := map[string]float64{
		"topsrv_nginx_up":                         1,
		"topsrv_nginx_connections{state=active}":  291,
		"topsrv_nginx_connections{state=reading}": 6,
		"topsrv_nginx_connections{state=writing}": 175,
		"topsrv_nginx_connections{state=waiting}": 110,
		"topsrv_nginx_connections_accepted_total": 16630948,
		"topsrv_nginx_requests_total":             31070465,
	}
	for key, want := range checks {
		got, ok := metrics[key]
		assert.True(t, ok, "metric %s not found", key)
		assert.InDelta(t, want, got, 1e-9, key)
	}
}

func TestStubCollectorDown(t *testing.T) {
	c := NewStubCollector(embedlog.Logger{}, "http://127.0.0.1:1")
	reg := prometheus.NewRegistry()
	reg.MustRegister(c)

	mfs, _ := reg.Gather()
	for _, mf := range mfs {
		if mf.GetName() == "topsrv_nginx_up" {
			assert.InDelta(t, float64(0), mf.GetMetric()[0].GetGauge().GetValue(), 1e-9)
			return
		}
	}
	t.Error("topsrv_nginx_up not found")
}

func TestLogCollectorParseLine(t *testing.T) {
	c := NewLogCollector(embedlog.Logger{}, LogConfig{LogPaths: []string{"/dev/null"}, LogFormat: DefaultLogFormat})

	lines := []string{
		`10.10.10.14 - - [11/Apr/2026:17:15:23 +0300] "GET /api/v1/users HTTP/1.1" 200 1234 "https://example.com/" "Mozilla/5.0" 0.015 0.012`,
		`10.10.10.14 - - [11/Apr/2026:17:15:24 +0300] "POST /api/v1/login HTTP/1.1" 401 89 "-" "curl/7.68" 0.750 -`,
		`10.10.10.14 - - [11/Apr/2026:17:15:25 +0300] "GET /slow HTTP/1.1" 503 0 "-" "bot" 2.500 1.800`,
		`10.10.10.14 - - [11/Apr/2026:17:15:26 +0300] "GET /static/app.js HTTP/1.1" 304 0 "-" "Mozilla/5.0" 0.001 -`,
	}
	for _, l := range lines {
		c.parseLine(l)
	}

	assert.EqualValues(t, 4, c.reqCount)
	assert.EqualValues(t, 2, c.upCount)
	assert.EqualValues(t, 1, c.statusCounts["503"])
	assert.EqualValues(t, 1, c.uri5xx[statusURI{"503", "/slow"}])
	assert.EqualValues(t, 1323, c.bytesTotal.Load())
}

// recordingObserver collects every parsed line for assertions. uaIdx is the
// position of http_user_agent in the collector's ExtraLabels, captured at
// construction — observers own the mapping from label name to Extras[i].
type recordingObserver struct {
	uaIdx int
	lines []recordedLine
}

type recordedLine struct {
	status string
	uri    string
	rawURI string
	ua     string
	path   string
}

func (r *recordingObserver) OnLogLine(p *ParsedLine, path string) {
	rl := recordedLine{status: p.Status, uri: p.URI, rawURI: p.RawURI, path: path}
	if r.uaIdx >= 0 && r.uaIdx < p.NExtras {
		rl.ua = p.Extras[r.uaIdx]
	}
	r.lines = append(r.lines, rl)
}

func TestLogCollectorObserver(t *testing.T) {
	c := NewLogCollector(embedlog.Logger{}, LogConfig{
		LogPaths:    []string{"/dev/null"},
		LogFormat:   `$remote_addr [$time_local] "$request" $status $body_bytes_sent "$http_user_agent"`,
		ExtraLabels: []string{"http_user_agent"},
	})

	obs := &recordingObserver{uaIdx: 0}
	c.AddObserver(obs)

	// Format has no $request_time / $upstream_response_time — verifies that
	// observer fires regardless of timing fields.
	lines := []string{
		`1.2.3.4 [11/Apr/2026:17:15:23 +0300] "GET /api/users HTTP/1.1" 200 1234 "Mozilla/5.0"`,
		`5.6.7.8 [11/Apr/2026:17:15:24 +0300] "GET /robots.txt HTTP/1.1" 200 50 "Googlebot/2.1"`,
		`9.10.11.12 [11/Apr/2026:17:15:25 +0300] "GET /missing HTTP/1.1" 404 0 "curl/7.68"`,
	}
	for _, l := range lines {
		c.parseLineWith(c.defaultParser, l, "/var/log/nginx/access.log")
	}

	require.Len(t, obs.lines, 3)
	assert.Equal(t, "200", obs.lines[0].status)
	assert.Equal(t, "Mozilla/5.0", obs.lines[0].ua)
	assert.Equal(t, "Googlebot/2.1", obs.lines[1].ua)
	assert.Equal(t, "404", obs.lines[2].status)
	assert.Equal(t, "/var/log/nginx/access.log", obs.lines[2].path)

	// Status counters still work without timing.
	assert.EqualValues(t, 1, c.taggedCounts[taggedStatusKey{status: "200", extra: [MaxExtras]string{"Mozilla/5.0"}, n: 1}])
	assert.EqualValues(t, 1, c.taggedCounts[taggedStatusKey{status: "200", extra: [MaxExtras]string{"Googlebot/2.1"}, n: 1}])
	assert.EqualValues(t, 0, c.reqCount, "no timing field → no histogram update")
}

// Verifies the URI / RawURI split: nginx-metrics keep the normalized form
// (cardinality control), observers like botlog get the full hit URL with
// query string from RawURI.
func TestParsedLine_RawURIUnnormalized(t *testing.T) {
	cases := []struct {
		name       string
		setup      func(c *LogCollector)
		feed       func(c *LogCollector)
		wantURI    string
		wantRawURI string
	}{
		{
			name: "text/$request with numeric segment",
			setup: func(c *LogCollector) {
				c.AddObserver(&recordingObserver{uaIdx: -1})
			},
			feed: func(c *LogCollector) {
				c.parseLineWith(c.defaultParser,
					`1.2.3.4 [11/Apr/2026:17:15:23 +0300] "GET /news/12345/title?utm=x HTTP/1.1" 200 1234 "Bot/1"`,
					"/var/log/nginx/access.log")
			},
			wantURI:    "/news/:id/:rest",
			wantRawURI: "/news/12345/title?utm=x",
		},
		{
			name: "JSON request_uri with querystring",
			setup: func(c *LogCollector) {
				c.AddObserver(&recordingObserver{uaIdx: -1})
			},
			feed: func(c *LogCollector) {
				c.ParseJSONLine(`{"status":"200","body_bytes_sent":"100","request_time":"0.1",` +
					`"request_uri":"/series/777/episodes?page=2","upstream_response_time":""}`)
			},
			wantURI:    "/series/:id/:rest",
			wantRawURI: "/series/777/episodes?page=2",
		},
		{
			name: "JSON with extra-labels path (map unmarshal)",
			setup: func(c *LogCollector) {
				c.extractFields = []string{"http_user_agent"}
				c.AddObserver(&recordingObserver{uaIdx: 0})
			},
			feed: func(c *LogCollector) {
				c.ParseJSONLine(`{"status":"200","body_bytes_sent":"100","request_time":"0.1",` +
					`"request_uri":"/user/42/comments","http_user_agent":"Bot/1"}`)
			},
			wantURI:    "/user/:id/:rest",
			wantRawURI: "/user/42/comments",
		},
		{
			// Percent-encoded chars in query must survive verbatim so the
			// gatesrv side can decode params (e.g. utm_term=hello%20world).
			name: "text/$request with percent-encoded query",
			setup: func(c *LogCollector) {
				c.AddObserver(&recordingObserver{})
			},
			feed: func(c *LogCollector) {
				c.parseLine(`10.0.0.1 [01/Jan/2026:00:00:00 +0000] "GET /search?q=hello%20world&p=a%2Fb HTTP/1.1" 200 100 "Bot/1"`)
			},
			wantURI:    "/search",
			wantRawURI: "/search?q=hello%20world&p=a%2Fb",
		},
		{
			name: "JSON request_uri preserves percent-encoded query",
			setup: func(c *LogCollector) {
				c.AddObserver(&recordingObserver{})
			},
			feed: func(c *LogCollector) {
				c.ParseJSONLine(`{"status":"200","body_bytes_sent":"100","request_time":"0.1",` +
					`"request_uri":"/api?token=ab%3Dcd%26ef"}`)
			},
			wantURI:    "/api",
			wantRawURI: "/api?token=ab%3Dcd%26ef",
		},
		{
			// Key=value log_format with separate $uri and $args fields.
			// Without joining, RawURI would be path-only and gatesrv-side
			// HasQueryParams stays false (the original bug).
			name: "text key=value with separate $uri and $args",
			setup: func(c *LogCollector) {
				c.defaultParser = gonx.NewParser(`time="$time_iso8601" host="$host" uriPath="$uri" uriQuery="$args" httpStatus=$status bodyBytesSent=$body_bytes_sent`)
				c.AddObserver(&recordingObserver{})
			},
			feed: func(c *LogCollector) {
				c.parseLine(`time="2026-05-12T12:09:45+03:00" host="en.example.com" uriPath="/movies/catalog/" uriQuery="page=11051" httpStatus=404 bodyBytesSent=11496`)
			},
			wantURI:    "/movies/catalog/",
			wantRawURI: "/movies/catalog/?page=11051",
		},
		{
			// Empty $args (the common case — most requests have no query).
			// RawURI must NOT carry a trailing '?'.
			name: "text key=value with empty $args",
			setup: func(c *LogCollector) {
				c.defaultParser = gonx.NewParser(`host="$host" uriPath="$uri" uriQuery="$args" httpStatus=$status bodyBytesSent=$body_bytes_sent`)
				c.AddObserver(&recordingObserver{})
			},
			feed: func(c *LogCollector) {
				c.parseLine(`host="x.example" uriPath="/about/" uriQuery="" httpStatus=200 bodyBytesSent=100`)
			},
			wantURI:    "/about/",
			wantRawURI: "/about/",
		},
		{
			// $query_string is an alias of $args; some operators prefer it.
			name: "text key=value with $query_string instead of $args",
			setup: func(c *LogCollector) {
				c.defaultParser = gonx.NewParser(`host="$host" uriPath="$uri" qs="$query_string" httpStatus=$status bodyBytesSent=$body_bytes_sent`)
				c.AddObserver(&recordingObserver{})
			},
			feed: func(c *LogCollector) {
				c.parseLine(`host="x.example" uriPath="/search" qs="q=hello" httpStatus=200 bodyBytesSent=100`)
			},
			wantURI:    "/search",
			wantRawURI: "/search?q=hello",
		},
		{
			// $request_uri carries the original path+query, URL-encoded as
			// received. Formats that log it directly need no rejoining.
			name: "text key=value with $request_uri directly",
			setup: func(c *LogCollector) {
				c.defaultParser = gonx.NewParser(`host="$host" reqUri="$request_uri" httpStatus=$status bodyBytesSent=$body_bytes_sent`)
				c.AddObserver(&recordingObserver{})
			},
			feed: func(c *LogCollector) {
				c.parseLine(`host="x.example" reqUri="/news/12345/title?utm=x" httpStatus=200 bodyBytesSent=100`)
			},
			wantURI:    "/news/:id/:rest",
			wantRawURI: "/news/12345/title?utm=x",
		},
		{
			// Hybrid format: "$request" + ru="$request_uri" + u="$uri".
			// $request_uri wins so we ship what the client actually requested,
			// not the post-rewrite $uri pointing at the FastCGI dispatcher.
			name: "hybrid combined + key=value, internal rewrite",
			setup: func(c *LogCollector) {
				c.defaultParser = gonx.NewParser(`$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" rt="$request_time" "$http_user_agent" "$http_x_forwarded_for" h="$host" sn="$server_name" ru="$request_uri" u="$uri"`)
				c.AddObserver(&recordingObserver{})
			},
			feed: func(c *LogCollector) {
				c.parseLine(`192.0.2.9 - - [12/May/2026:00:00:30 +0000] "GET /events.ics HTTP/2.0" 200 900 "-" rt="0.098" "iOS/17.1 (21B74) dataaccessd/1.0" "-" h="example.com" sn="example.com" ru="/events.ics" u="/dispatch.php"`)
			},
			wantURI:    "/events.ics",
			wantRawURI: "/events.ics",
		},
		{
			// Same hybrid format with a long query containing commas — gonx
			// must not get confused by literal commas inside the quoted value.
			name: "hybrid format with comma-rich query string",
			setup: func(c *LogCollector) {
				c.defaultParser = gonx.NewParser(`$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" rt="$request_time" "$http_user_agent" "$http_x_forwarded_for" h="$host" sn="$server_name" ru="$request_uri" u="$uri"`)
				c.AddObserver(&recordingObserver{})
			},
			feed: func(c *LogCollector) {
				c.parseLine(`192.0.2.5 - - [12/May/2026:00:00:23 +0000] "GET /shared/minify.php?hash&files=/a.js,/b.js,/c.js HTTP/2.0" 200 80612 "https://example.com/" rt="0.004" "Mozilla/5.0" "-" h="example.com" sn="example.com" ru="/shared/minify.php?hash&files=/a.js,/b.js,/c.js" u="/shared/minify.php"`)
			},
			wantURI:    "/shared/:file.php",
			wantRawURI: "/shared/minify.php?hash&files=/a.js,/b.js,/c.js",
		},
		{
			// Operator misconfiguration: $request_uri logged under "uri" field
			// name. RawURI keeps the query (that's the point); metric URI must
			// be query-free — otherwise utm/session params blow up cardinality.
			name: "metric URI stays query-free even if $uri field carries query",
			setup: func(c *LogCollector) {
				c.defaultParser = gonx.NewParser(`host="$host" uriPath="$uri" httpStatus=$status bodyBytesSent=$body_bytes_sent`)
				c.AddObserver(&recordingObserver{})
			},
			feed: func(c *LogCollector) {
				c.parseLine(`host="x.example" uriPath="/news/12345?utm_source=tg&utm_campaign=spring" httpStatus=200 bodyBytesSent=100`)
			},
			wantURI:    "/news/:id",
			wantRawURI: "/news/12345?utm_source=tg&utm_campaign=spring",
		},
		{
			// JSON map path with a base64-like signed URL (file CDN style):
			// "/get/<token>==,<numeric-id>/<asset-path>". RawURI ships verbatim;
			// metric URI collapses the token+id and truncates deep paths.
			name: "JSON map path with base64 token in request_uri",
			setup: func(c *LogCollector) {
				c.extractFields = []string{"http_user_agent"}
				c.AddObserver(&recordingObserver{uaIdx: 0})
			},
			feed: func(c *LogCollector) {
				c.ParseJSONLine(`{"status":"200","body_bytes_sent":"123456789","request_time":"42.000","request_uri":"/get/AbCdEf01234567_HiJkLmNo-PqRs==,1234567890/category/asset/files/example.zip","http_user_agent":"Mozilla/5.0"}`)
			},
			wantURI:    "/get/:token/:rest",
			wantRawURI: "/get/AbCdEf01234567_HiJkLmNo-PqRs==,1234567890/category/asset/files/example.zip",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := NewLogCollector(embedlog.Logger{}, LogConfig{
				LogPaths:  []string{"/dev/null"},
				LogFormat: `$remote_addr [$time_local] "$request" $status $body_bytes_sent "$http_user_agent"`,
			})
			tc.setup(c)
			tc.feed(c)
			rec := c.observers[0].(*recordingObserver)
			require.Len(t, rec.lines, 1)
			assert.Equal(t, tc.wantURI, rec.lines[0].uri, "URI must be normalized for nginx-metrics")
			assert.Equal(t, tc.wantRawURI, rec.lines[0].rawURI, "RawURI must be the raw request URI (path + query)")
		})
	}
}

func TestLogCollectorCustomFormat(t *testing.T) {
	format := `$remote_addr - $remote_user [$time_local] "$server_name" "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" $request_time $upstream_cache_status [$upstream_response_time] $http_platform-$http_version $geoip_country_code $request_id`

	c := NewLogCollector(embedlog.Logger{}, LogConfig{
		LogPaths:    []string{"/dev/null"},
		LogFormat:   format,
		ExtraLabels: []string{"server_name", "http_platform", "http_version"},
	})

	lines := []string{
		`10.10.10.14 - - [11/Apr/2026:17:15:23 +0300] "example.com" "GET /api/v1/users HTTP/1.1" 200 1234 "https://example.com/" "Mozilla/5.0" 0.015 HIT [0.012] ios-3.2.1 RU abc123`,
		`10.10.10.14 - - [11/Apr/2026:17:15:24 +0300] "api.example.com" "POST /rpc/ HTTP/1.1" 200 89 "-" "curl/7.68" 0.750 MISS [0.740] android-2.1.0 US def456`,
		`10.10.10.14 - - [11/Apr/2026:17:15:25 +0300] "example.com" "GET /broken HTTP/1.1" 502 0 "-" "bot" 2.500 - [1.800] -- KZ ghi789`,
	}
	for _, l := range lines {
		c.parseLine(l)
	}

	assert.EqualValues(t, 3, c.reqCount)
	assert.EqualValues(t, 1, c.cacheCounts["HIT"])
	assert.EqualValues(t, 1, c.cacheCounts["MISS"])
	assert.Len(t, c.taggedCounts, 3)

	reg := prometheus.NewRegistry()
	reg.MustRegister(c)
	mfs, err := reg.Gather()
	require.NoError(t, err)
	for _, mf := range mfs {
		t.Logf("metric: %s (%d series)", mf.GetName(), len(mf.GetMetric()))
	}
}

func TestLogCollectorJSONParseLine(t *testing.T) {
	c := NewLogCollector(embedlog.Logger{}, LogConfig{
		LogPaths:  []string{"/dev/null"},
		JSONPaths: map[string]bool{"/dev/null": true},
	})

	lines := []string{
		`{"time_local":"14/Apr/2026:18:18:52 +0300","remote_addr":"10.0.0.1","remote_user":"","host":"cdn.example.com","protocol":"HTTP/2.0","request_uri":"/files/abc123/archive.tar.gz","http_method":"GET","status": "200","body_bytes_sent":"10939722","request_time":"29.177","http_referrer":"https://example.com/","http_user_agent":"Mozilla/5.0","upstream_response_time":"","geoip_country_code":"US"}`,
		`{"time_local":"14/Apr/2026:18:18:55 +0300","remote_addr":"10.0.0.2","remote_user":"","host":"cdn.example.com","protocol":"HTTP/2.0","request_uri":"/files/def456/document.pdf","http_method":"GET","status": "200","body_bytes_sent":"1043200","request_time":"0.217","http_referrer":"https://example.com/downloads","http_user_agent":"Mozilla/5.0","upstream_response_time":"","geoip_country_code":"DE"}`,
		`{"time_local":"14/Apr/2026:18:19:02 +0300","remote_addr":"10.0.0.3","remote_user":"","host":"cdn.example.com","protocol":"HTTP/2.0","request_uri":"/files/ghi789/image.iso","http_method":"GET","status": "503","body_bytes_sent":"221239839","request_time":"301.437","http_referrer":"https://example.com/","http_user_agent":"Mozilla/5.0","upstream_response_time":"1.200","geoip_country_code":"FR"}`,
		`{"time_local":"14/Apr/2026:18:19:10 +0300","remote_addr":"10.0.0.4","remote_user":"","host":"cdn.example.com","protocol":"HTTP/1.1","request_uri":"/missing","http_method":"GET","status":"404","body_bytes_sent":"162","request_time":"0.001","http_referrer":"","http_user_agent":"curl/7.68","upstream_response_time":"","geoip_country_code":""}`,
	}
	for _, l := range lines {
		c.ParseJSONLine(l)
	}

	assert.EqualValues(t, 4, c.reqCount)
	assert.EqualValues(t, 1, c.upCount, "only one line has non-empty upstream_response_time")
	assert.EqualValues(t, 2, c.statusCounts["200"])
	assert.EqualValues(t, 1, c.statusCounts["503"])
	assert.EqualValues(t, 1, c.statusCounts["404"])
	assert.Len(t, c.uri5xx, 1, "one 503 URI")
	assert.Len(t, c.uri4xx, 1, "one 404 URI")
	assert.Equal(t, int64(10939722+1043200+221239839+162), c.bytesTotal.Load())
}

func TestLogCollectorJSONExtraLabels(t *testing.T) {
	c := NewLogCollector(embedlog.Logger{}, LogConfig{
		LogPaths:    []string{"/dev/null"},
		JSONPaths:   map[string]bool{"/dev/null": true},
		ExtraLabels: []string{"host", "geoip_country_code"},
	})

	c.ParseJSONLine(`{"status":"200","body_bytes_sent":"100","request_time":"0.010","request_uri":"/api","upstream_response_time":"","host":"example.com","geoip_country_code":"RU"}`)
	c.ParseJSONLine(`{"status":"200","body_bytes_sent":"200","request_time":"0.020","request_uri":"/api","upstream_response_time":"","host":"other.com","geoip_country_code":"US"}`)

	assert.Len(t, c.taggedCounts, 2, "two distinct host+country combos")
	assert.Empty(t, c.statusCounts, "statusCounts should be empty when extraLabels used")
}

func TestLogCollectorJSONTail(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "access.json.log")
	f, err := os.Create(logPath)
	require.NoError(t, err)

	c := NewLogCollector(embedlog.Logger{}, LogConfig{
		LogPaths:  []string{logPath},
		JSONPaths: map[string]bool{logPath: true},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.runPaths(ctx, []string{logPath})

	time.Sleep(100 * time.Millisecond)
	_, _ = f.WriteString(`{"status":"500","body_bytes_sent":"100","request_time":"1.500","request_uri":"/users/123","upstream_response_time":"1.200","http_method":"GET"}` + "\n")
	_ = f.Sync()
	time.Sleep(200 * time.Millisecond)

	reg := prometheus.NewRegistry()
	reg.MustRegister(c)
	mfs, err := reg.Gather()
	require.NoError(t, err)

	metrics := make(map[string]float64)
	for _, mf := range mfs {
		for _, m := range mf.GetMetric() {
			metrics[mf.GetName()] += float64(m.GetHistogram().GetSampleCount()) + m.GetCounter().GetValue()
		}
	}
	assert.Greater(t, metrics["topsrv_nginx_request_duration_seconds"], 0.0, "expected request duration histogram")
	assert.Greater(t, metrics["topsrv_nginx_5xx_requests_total"], 0.0, "expected 5xx counter")
}

func TestLogCollectorTail(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "access.log")
	f, err := os.Create(logPath)
	require.NoError(t, err)

	c := NewLogCollector(embedlog.Logger{}, LogConfig{LogPaths: []string{logPath}, LogFormat: DefaultLogFormat})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.runPaths(ctx, []string{logPath})

	time.Sleep(100 * time.Millisecond)
	_, _ = f.WriteString(`1.2.3.4 - - [11/Apr/2026:17:15:23 +0300] "GET /users/123 HTTP/1.1" 500 100 "-" "test" 1.500 1.200` + "\n")
	_ = f.Sync()
	time.Sleep(200 * time.Millisecond)

	// Read metrics via Collect (takes the lock) to avoid data race.
	reg := prometheus.NewRegistry()
	reg.MustRegister(c)
	mfs, err := reg.Gather()
	require.NoError(t, err)

	metrics := make(map[string]float64)
	for _, mf := range mfs {
		for _, m := range mf.GetMetric() {
			metrics[mf.GetName()] += float64(m.GetHistogram().GetSampleCount()) + m.GetCounter().GetValue()
		}
	}
	assert.Greater(t, metrics["topsrv_nginx_request_duration_seconds"], 0.0, "expected request duration histogram")
	assert.Greater(t, metrics["topsrv_nginx_5xx_requests_total"], 0.0, "expected 5xx counter")
}

func TestLogCollectorCardinalityCap(t *testing.T) {
	c := NewLogCollector(embedlog.Logger{}, LogConfig{LogPaths: []string{"/dev/null"}, LogFormat: DefaultLogFormat})

	// Fill uri5xx, uri4xx, bytesByURI to maxCardinalityURI with unique URIs.
	for i := range maxCardinalityURI {
		uri := "/section" + strconv.Itoa(i) + "/page"
		c.uri5xx[statusURI{"500", uri}] = 1
		c.uri4xx[statusURI{"404", uri}] = 1
		c.bytesByURI[uri] = 1
	}
	assert.Len(t, c.uri5xx, maxCardinalityURI)
	assert.Len(t, c.uri4xx, maxCardinalityURI)
	assert.Len(t, c.bytesByURI, maxCardinalityURI)

	// Parse a line with a URI that normalizes to an EXISTING entry — counters must still grow.
	existingURI := "/section0/page"
	c.parseLine(`1.2.3.4 - - [11/Apr/2026:17:15:23 +0300] "GET ` + existingURI + ` HTTP/1.1" 500 999 "-" "test" 0.1 0.1`)
	assert.EqualValues(t, 2, c.uri5xx[statusURI{"500", existingURI}], "existing 5xx URI counter must increment")
	assert.EqualValues(t, 1000, c.bytesByURI[existingURI], "existing bytes URI counter must increment")

	// Parse a line with a NEW URI — must be rejected (cap reached).
	c.parseLine(`1.2.3.4 - - [11/Apr/2026:17:15:24 +0300] "GET /brand-new HTTP/1.1" 503 500 "-" "test" 0.2 0.2`)
	_, exists := c.uri5xx[statusURI{"503", "/brand-new"}]
	assert.False(t, exists, "new URI must not be added when cap is reached")
	assert.Len(t, c.uri5xx, maxCardinalityURI)
}

func TestNormalizeURI(t *testing.T) {
	tests := []struct {
		request, want string
	}{
		{"GET /api/v1/users/12345/posts HTTP/1.1", "/api/v1/:rest"},
		{"POST /shows/99999 HTTP/1.1", "/shows/:id"},
		{"GET /static/app.js?v=123 HTTP/1.1", "/static/app.js"},
		{"GET / HTTP/1.1", "/"},
		// slug with trailing ID
		{"GET /people/tommy-brewster-6401345/ HTTP/1.1", "/people/:slug/"},
		// hex hashes in media URLs — truncated by depth
		{"GET /media/roles/e/ef/d763d0a80cfe86a9fcc378db4d5935bf.jpg HTTP/1.1", "/media/roles/:rest"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, normalizeURI(tt.request), tt.request)
	}
}

func TestNormalizePath(t *testing.T) {
	tests := []struct {
		path, want string
	}{
		{"/people/tommy-brewster-6401345/", "/people/:slug/"},
		{"/people/anna-brewster-5448750/", "/people/:slug/"},
		{"/movie/699853/", "/movie/:id/"},
		{"/media/movies/normal/:rest", "/media/movies/:rest"},
		{"/view/episode/123/", "/view/episode/:rest"},
		{"/v3/rpc/stat/", "/v3/rpc/:rest"},
		// hyphen slugs (people, articles, products)
		{"/people/anna-paquin/", "/people/:slug/"},
		{"/people/tom-hardy/", "/people/:slug/"},
		{"/articles/bolezni/:slug/", "/articles/bolezni/:rest"},
		{"/articles/lekarstva/:slug/", "/articles/lekarstva/:rest"},
		// depth limiting: 3+ real segments get truncated (trailing slash ignored)
		{"/search/all/g-drama/", "/search/all/:rest"},
		{"/search/all/g-drama/c-AU/", "/search/all/:rest"},
		{"/search/all/g-drama/c-AU/ch-US-abc/", "/search/all/:rest"},
		{"/search/all/c-AU/", "/search/all/:rest"},
		{"/movies/catalog/horror/g-action/c-FR/", "/movies/catalog/:rest"},
		{"/movies/catalog/g-drama/", "/movies/catalog/:rest"},
		{"/movies/catalog/c-CA/", "/movies/catalog/:rest"},
		// shallow paths stay unchanged
		{"/", "/"},
		{"/view/123/", "/view/:id/"},

		// XenForo-style: text.digits (threads, attachments, blogs, members)
		{"/forum/threads/:slug/", "/forum/threads/:rest"},
		{"/forum/attachments/:slug/", "/forum/attachments/:rest"},
		{"/forum/attachments/:slug/", "/forum/attachments/:rest"},
		{"/forum/blogs/:slug/", "/forum/blogs/:rest"},
		{"/forum/members/:slug/", "/forum/members/:rest"},
		{"/forum/threads/baldurs-gate.13472/page-2", "/forum/threads/:rest"},

		// base64 tokens (download links with = padding)
		{"/get/Ff6tPA2V90mzyHp1QqNI3A==,1776358785/pc/zuma/files/file.rar", "/get/:token/:rest"},
		{"/get/HcMp5L-WV7ChJaTSCai08g==,1776358793/pc/game/files/game.rar", "/get/:token/:rest"},
		{"/get/sOrtv860L7CZHzUQMvV5Bw==,1776276144/pc/test/files/test.zip", "/get/:token/:rest"},

		// file numeric suffixes (media filenames like show_10778.jpeg)
		{"/media/123/456_10778.jpeg", "/media/:id/:rest"},
		{"/media/123/456_4036.jpg", "/media/:id/:rest"},

		// hex hash before numeric: /preview/shows/<md5>.jpg — truncated by depth 2
		{"/preview/shows/a0367b46de8f1c2a9b3e5d7f00112233.jpg", "/preview/shows/:rest"},
		{"/preview/shows/de51d412b8e4abcdef0123456789abcd.png", "/preview/shows/:rest"},
		{"/preview/comments/a0367b46de8f1c2a9b3e5d7f00112233.jpg", "/preview/comments/:rest"},

		// URL-encoded segments (Cyrillic wiki pages, etc.)
		{"/wiki/%D0%94%D1%8D%D0%B2%D0%B8%D0%B4_%D0%9F%D1%8D%D1%80%D1%80%D0%B8", "/wiki/:slug"},
		{"/wiki/%D0%9A%D0%BB%D0%B0%D0%B4", "/wiki/:slug"},
		{"/search/all/c-%D0%A0%D0%BE%D1%81%D1%81%D0%B8%D1%8F/", "/search/all/:rest"},

		// non-printable / TLS garbage → /:invalid
		{"\x16\x03\x01\x00{\x01", "/:invalid"},
		{"/page\x00inject", "/:invalid"},

		// scanner probe suffixes → /:bot-scanners
		{"/.env", "/:bot-scanners"},
		{"/.git/config", "/:bot-scanners"},
		{"/.aws/credentials", "/:bot-scanners"},
		{"/backup.sql", "/:bot-scanners"},
		{"/dump.bak", "/:bot-scanners"},
		{"/.ssh/id_rsa", "/:bot-scanners"},
		{"/.svn/entries", "/:bot-scanners"},

		// .php normalization → :file.php
		{"/shell.php", "/:file.php"},
		{"/wp-login.php", "/:file.php"},
		{"/wiki/index.php", "/wiki/:file.php"},
		{"/forum/proxy.php", "/forum/:file.php"},

		// static well-known paths stay unchanged
		{"/.well-known/security.txt", "/.well-known/security.txt"},
		{"/robots.txt", "/robots.txt"},
		{"/favicon.ico", "/favicon.ico"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, normalizePath(tt.path), tt.path)
	}
}

func TestTruncatePath(t *testing.T) {
	tests := []struct {
		path     string
		maxDepth int
		want     string
	}{
		{"/", 2, "/"},
		{"/a", 2, "/a"},
		{"/a/b", 2, "/a/b"},
		{"/a/b/", 2, "/a/b/"}, // trailing slash ignored
		{"/a/b/c", 2, "/a/b/:rest"},
		{"/a/b/c/d", 2, "/a/b/:rest"},
		{"/a/b/c/d/e/f", 2, "/a/b/:rest"},
		{"/a/b/c", 3, "/a/b/c"},
		{"/a/b/c/d", 3, "/a/b/c/:rest"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, truncatePath(tt.path, tt.maxDepth), tt.path)
	}
}

func TestDiscoverJSONLogFormat(t *testing.T) {
	dir := t.TempDir()

	nginxConf := `
http {
    log_format json_combined escape=json
        '{'
        '"time_local":"$time_local",'
        '"remote_addr":"$remote_addr",'
        '"host":"$host",'
        '"request_uri":"$request_uri",'
        '"http_method":"$request_method",'
        '"status":"$status",'
        '"body_bytes_sent":"$body_bytes_sent",'
        '"request_time":"$request_time",'
        '"upstream_response_time":"$upstream_response_time"'
        '}';

    log_format main '$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" $request_time';

    access_log /var/log/nginx/json.log json_combined;
    access_log /var/log/nginx/access.log main;
}
`
	os.WriteFile(filepath.Join(dir, "nginx.conf"), []byte(nginxConf), 0644)

	result, err := DiscoverConfig(filepath.Join(dir, "nginx.conf"))
	require.NoError(t, err)

	assert.Len(t, result.LogFormats, 2)
	assert.True(t, result.JSONFormats["json_combined"], "json_combined should be detected as JSON")
	assert.False(t, result.JSONFormats["main"], "main should not be JSON")

	// Verify JSON format content starts with '{'.
	assert.True(t, strings.HasPrefix(result.LogFormats["json_combined"], "{"))
}

func TestDiscoverAngieAPI(t *testing.T) {
	dir := t.TempDir()

	angieConf := `
http {
    server {
        listen 8080;

        location /status/ {
            api /status/;
            allow 127.0.0.1;
            deny all;
        }
    }

    server {
        listen 80;
        status_zone http_main;

        location /stub_status {
            stub_status;
        }
    }
}
`
	os.WriteFile(filepath.Join(dir, "angie.conf"), []byte(angieConf), 0644)

	result, err := DiscoverConfig(filepath.Join(dir, "angie.conf"))
	require.NoError(t, err)

	assert.Equal(t, "/status/", result.APIStatusPath)
	assert.Equal(t, 8080, result.APIStatusPort)
	assert.Equal(t, "/stub_status", result.StubStatusPath)
	assert.Equal(t, 80, result.StubStatusPort)
}

func TestDiscoverConfigNoAPI(t *testing.T) {
	dir := t.TempDir()

	nginxConf := `
http {
    server {
        listen 80;
        location /stub_status {
            stub_status;
        }
    }
}
`
	os.WriteFile(filepath.Join(dir, "nginx.conf"), []byte(nginxConf), 0644)

	result, err := DiscoverConfig(filepath.Join(dir, "nginx.conf"))
	require.NoError(t, err)

	assert.Empty(t, result.APIStatusPath)
	assert.Equal(t, 0, result.APIStatusPort)
	assert.Equal(t, "/stub_status", result.StubStatusPath)
}

func TestDiscoverConfig(t *testing.T) {
	dir := t.TempDir()

	nginxConf := `
http {
    log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
                      '$status $body_bytes_sent "$http_referer" '
                      '"$http_user_agent"';

    log_format combined_plus '$remote_addr [$time_local] "$request" $status $request_time';

    access_log  /var/log/nginx/access.log  main;

    include ` + filepath.Join(dir, "conf.d", "*.conf") + `;
}
`
	os.WriteFile(filepath.Join(dir, "nginx.conf"), []byte(nginxConf), 0644)

	os.MkdirAll(filepath.Join(dir, "conf.d"), 0755)
	siteConf := `
server {
    access_log /var/log/nginx/example.com.log combined_plus;
    access_log off;
}
`
	os.WriteFile(filepath.Join(dir, "conf.d", "site.conf"), []byte(siteConf), 0644)

	result, err := DiscoverConfig(filepath.Join(dir, "nginx.conf"))
	require.NoError(t, err)

	assert.Len(t, result.LogFormats, 2)
	assert.Contains(t, result.LogFormats, "main")
	assert.Contains(t, result.LogFormats, "combined_plus")

	nonOff := 0
	for _, entry := range result.AccessLogs {
		if entry.Path != "off" {
			nonOff++
		}
	}
	assert.Equal(t, 2, nonOff)
}

// ExtractFields being a superset of ExtraLabels must NOT leak the
// extra-only variables (e.g. http_user_agent read by botlog) into
// Prometheus labels.
func TestExtraLabels_NotInExtractFields_NoBleed(t *testing.T) {
	format := `$remote_addr [$time_local] "$server_name" "$request" $status $body_bytes_sent "$http_user_agent"`
	c := NewLogCollector(embedlog.Logger{}, LogConfig{
		LogPaths:      []string{"/dev/null"},
		LogFormat:     format,
		ExtraLabels:   []string{"server_name"},
		ExtractFields: []string{"server_name", "http_user_agent"},
	})

	// Two lines, same server_name, different UAs. If UA leaked into labels,
	// taggedCounts would split into two series.
	for _, l := range []string{
		`1.1.1.1 [11/Apr/2026:17:15:23 +0300] "example.com" "GET /a HTTP/1.1" 200 100 "Mozilla/5.0"`,
		`1.1.1.1 [11/Apr/2026:17:15:24 +0300] "example.com" "GET /b HTTP/1.1" 200 100 "Googlebot/2.1"`,
	} {
		c.parseLine(l)
	}

	require.Len(t, c.taggedCounts, 1, "UA must NOT split the (status, server_name) cardinality bucket")
	for key := range c.taggedCounts {
		assert.Equal(t, "200", key.status)
		assert.Equal(t, "example.com", key.extra[0])
		assert.Equal(t, 1, key.n, "exactly one label dimension beyond status")
	}
}

// When ExtractFields is empty, behaviour matches v0.0.21: ExtraLabels is both
// the parser read-list and the Prometheus label set.
func TestExtractFields_DefaultsToExtraLabels(t *testing.T) {
	format := `$remote_addr [$time_local] "$server_name" "$request" $status $body_bytes_sent "$http_user_agent"`
	c := NewLogCollector(embedlog.Logger{}, LogConfig{
		LogPaths:    []string{"/dev/null"},
		LogFormat:   format,
		ExtraLabels: []string{"server_name"},
		// ExtractFields intentionally empty
	})
	assert.Equal(t, []string{"server_name"}, c.extractFields)
	assert.Equal(t, []string{"server_name"}, c.labelFields)
}

// labelIdx must point at the correct Extras slot when operator labels are
// listed before botlog's extra-only fields in ExtractFields.
func TestExtractFields_SupersetOrderingLabelIdx(t *testing.T) {
	c := NewLogCollector(embedlog.Logger{}, LogConfig{
		LogPaths:      []string{"/dev/null"},
		LogFormat:     `$remote_addr [$time_local] "$server_name" "$http_platform" "$request" $status $body_bytes_sent "$http_user_agent"`,
		ExtraLabels:   []string{"server_name", "http_platform"},
		ExtractFields: []string{"server_name", "http_platform", "http_user_agent"},
	})
	require.Len(t, c.labelIdx, 2)
	assert.Equal(t, 0, c.labelIdx[0], "server_name lives at Extras[0]")
	assert.Equal(t, 1, c.labelIdx[1], "http_platform lives at Extras[1]")
}
