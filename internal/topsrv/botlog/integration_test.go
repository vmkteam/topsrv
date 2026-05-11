package botlog

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json/v2"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vmkteam/topsrv/internal/topsrv"
	"github.com/vmkteam/topsrv/internal/topsrv/nginx"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vmkteam/embedlog"
)

// TestE2E_TailFileToIngest is the bot-logs smoke test: a real LogCollector
// tails a temp file, the Observer pipes matched lines into the Pusher, and a
// mock HTTP receiver decodes the gzipped ndjson batch. Covers the full
// production path except for the topsrv.io endpoint itself.
func TestE2E_TailFileToIngest(t *testing.T) {
	type received struct {
		auth    string
		batchID string
		events  []Event
	}

	var (
		mu     sync.Mutex
		bodies []received
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		_ = req.Body.Close()
		gz, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		plain, _ := io.ReadAll(gz)
		_ = gz.Close()

		var evs []Event
		for _, line := range strings.Split(strings.TrimRight(string(plain), "\n"), "\n") {
			if line == "" {
				continue
			}
			var ev Event
			if err := json.Unmarshal([]byte(line), &ev); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			evs = append(evs, ev)
		}
		mu.Lock()
		bodies = append(bodies, received{
			auth:    req.Header.Get("Authorization"),
			batchID: req.Header.Get("X-Batch-Id"),
			events:  evs,
		})
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Pusher + Observer.
	cfg := Config{
		Enabled:       true,
		Endpoint:      srv.URL,
		Token:         "bl_smoke",
		BatchSize:     5,
		BatchInterval: "50ms",
	}
	require.NoError(t, cfg.Validate(topsrv.PushConfig{}))
	reg := prometheus.NewRegistry()
	p := NewPusher(embedlog.Logger{}, "topsrv-smoke", "test", cfg, reg)

	// Temp access log + LogCollector with the JSON format (so we can write
	// structured lines directly without learning gonx). botlog needs its four
	// fields in ExtractFields only — operator's ExtraLabels stays empty here.
	dir := t.TempDir()
	logPath := filepath.Join(dir, "access.json")
	f, err := os.Create(logPath)
	require.NoError(t, err)
	defer f.Close()

	logC := nginx.NewLogCollector(embedlog.Logger{}, nginx.LogConfig{
		LogPaths:      []string{logPath},
		JSONPaths:     map[string]bool{logPath: true},
		ExtractFields: RequiredFields(),
	})
	obs := NewObserver(p, cfg, "smoke-host", RequiredFields())
	logC.AddObserver(obs)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go logC.Run(ctx)
	go p.Run(ctx)

	// Mix of one bot line, one human, one Anthropic Claude.
	lines := []string{
		`{"status":"200","body_bytes_sent":"1234","request_time":"0.150","request_uri":"/api/series",` +
			`"http_user_agent":"Mozilla/5.0 GPTBot/1.0","server_name":"example.com","remote_addr":"203.0.113.5","http_referer":"-"}`,
		`{"status":"200","body_bytes_sent":"50","request_time":"0.020","request_uri":"/static/app.js",` +
			`"http_user_agent":"Mozilla/5.0 (Macintosh) Safari/605","server_name":"example.com","remote_addr":"198.51.100.7","http_referer":"-"}`,
		`{"status":"404","body_bytes_sent":"0","request_time":"0.005","request_uri":"/robots.txt",` +
			`"http_user_agent":"ClaudeBot/1.0 (+claudebot@anthropic.com)","server_name":"api.example.com","remote_addr":"203.0.113.99","http_referer":""}`,
	}
	// nxadm/tail starts at EOF, so writes before the tail goroutine sets up
	// inotify are silently skipped. 300ms is well above the observed attach
	// latency on macOS/Linux; if this becomes flaky on slow CI, raise it
	// rather than switching to a polling write loop (polling produces
	// duplicates, breaking exact event-count assertions below).
	time.Sleep(300 * time.Millisecond)
	for _, l := range lines {
		_, err := f.WriteString(l + "\n")
		require.NoError(t, err)
	}
	require.NoError(t, f.Sync())

	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		total := 0
		for _, b := range bodies {
			total += len(b.events)
		}
		return total >= 2 // GPTBot + ClaudeBot
	}, 3*time.Second, 25*time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	require.NotEmpty(t, bodies, "ingest received no batches")
	for _, b := range bodies {
		assert.Equal(t, "Bearer bl_smoke", b.auth)
		assert.NotEmpty(t, b.batchID)
	}

	// Flatten and inspect.
	var events []Event
	for _, b := range bodies {
		events = append(events, b.events...)
	}
	require.Len(t, events, 2)

	byFamily := map[string]Event{}
	for _, ev := range events {
		byFamily[ev.BotFamily] = ev
	}
	require.Contains(t, byFamily, "openai")
	require.Contains(t, byFamily, "anthropic")

	gpt := byFamily["openai"]
	assert.Equal(t, "gptbot", gpt.BotName)
	assert.Equal(t, "example.com", gpt.ServerName)
	assert.Equal(t, "203.0.113.5", gpt.RemoteAddr)
	assert.Equal(t, "/api/series", gpt.URI)
	assert.EqualValues(t, 200, gpt.Status)
	assert.EqualValues(t, 1234, gpt.BodyBytesSent)
	assert.EqualValues(t, 150000, gpt.RequestTimeUs)
	assert.Equal(t, "smoke-host", gpt.AgentHostname)

	claude := byFamily["anthropic"]
	assert.Equal(t, "claudebot", claude.BotName)
	assert.EqualValues(t, 404, claude.Status)
	assert.Equal(t, "api.example.com", claude.ServerName)
}
