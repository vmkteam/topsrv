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

func TestLogCollectorTail(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "access.log")
	f, err := os.Create(logPath)
	require.NoError(t, err)

	c := NewLogCollector(embedlog.Logger{}, LogConfig{LogPaths: []string{logPath}, LogFormat: DefaultLogFormat})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.RunPaths(ctx, []string{logPath})

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
		{"GET /api/v1/users/12345/posts HTTP/1.1", "/api/v1/users/:rest"},
		{"POST /shows/99999 HTTP/1.1", "/shows/:id"},
		{"GET /static/app.js?v=123 HTTP/1.1", "/static/app.js"},
		{"GET / HTTP/1.1", "/"},
		// slug with trailing ID
		{"GET /people/tommy-brewster-6401345/ HTTP/1.1", "/people/:slug/"},
		// hex hashes in media URLs — truncated by depth
		{"GET /media/roles/e/ef/d763d0a80cfe86a9fcc378db4d5935bf.jpg HTTP/1.1", "/media/roles/e/:rest"},
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
		{"/media/movies/normal/d/42/d763d0a80cfe86a9fcc378db4d5935bf.jpg", "/media/movies/normal/:rest"},
		{"/view/episode/123/", "/view/episode/:id/"},
		{"/v3/rpc/stat/", "/v3/rpc/stat/"},
		// long slugs (articles, products)
		{"/articles/bolezni/mozhno-li-uskorit-lechenie-orvi-i-grippa/", "/articles/bolezni/:slug/"},
		{"/articles/lekarstva/top-luchshih-kapel-v-nos/", "/articles/lekarstva/:slug/"},
		// depth limiting: 4+ real segments get truncated (trailing slash ignored)
		{"/search/all/g-drama/", "/search/all/g-drama/"},
		{"/search/all/g-drama/c-AU/", "/search/all/g-drama/:rest"},
		{"/search/all/g-drama/c-AU/ch-US-abc/", "/search/all/g-drama/:rest"},
		{"/search/all/c-AU/", "/search/all/c-AU/"},
		{"/movies/catalog/horror/g-action/c-FR/", "/movies/catalog/horror/:rest"},
		// shallow paths stay unchanged
		{"/", "/"},
		{"/view/123/", "/view/:id/"},
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
		{"/", 3, "/"},
		{"/a", 3, "/a"},
		{"/a/b", 3, "/a/b"},
		{"/a/b/c", 3, "/a/b/c"},
		{"/a/b/c/", 3, "/a/b/c/"}, // trailing slash ignored
		{"/a/b/c/d", 3, "/a/b/c/:rest"},
		{"/a/b/c/d/e/f", 3, "/a/b/c/:rest"},
		{"/a/b/c/d", 2, "/a/b/:rest"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, truncatePath(tt.path, tt.maxDepth), tt.path)
	}
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
