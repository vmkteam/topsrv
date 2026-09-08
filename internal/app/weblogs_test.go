package app

import (
	"context"
	"testing"

	"github.com/vmkteam/topsrv/internal/topsrv/nginx"
	"github.com/vmkteam/topsrv/internal/topsrv/weblog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const webLogPath = "/var/log/nginx/site.access.log"

// safeFormat carries everything both streams need, plus the two variables the
// web stream's filters read.
const safeFormat = `$remote_addr [$time_local] "$request" $status $body_bytes_sent ` +
	`"$http_referer" "$http_user_agent" $host $server_name $proxy_host $upstream_response_time`

func newWebLogTestApp(t *testing.T, cfg *weblog.Config) *App {
	t.Helper()
	a := newLogCollectorTestApp(t)
	a.cfg.BotLogs.Enabled = false
	a.cfg.WebLogs = cfg
	a.hostname = "web01"
	return a
}

// tailedPaths reads topsrv_weblog_tailed_paths out of the app registry. The
// gauge is registered only once a path survives the format checks, so "not
// present" is the readable form of "the stream did not start".
func tailedPaths(t *testing.T, reg *prometheus.Registry) (float64, bool) {
	t.Helper()
	families, err := reg.Gather()
	require.NoError(t, err)
	for _, f := range families {
		if f.GetName() == "topsrv_weblog_tailed_paths" {
			require.Len(t, f.GetMetric(), 1)
			return f.GetMetric()[0].GetGauge().GetValue(), true
		}
	}
	return 0, false
}

// Both streams read the same five nginx variables, so enabling either one is
// what makes resolving aliases worthwhile — before this, a web-only host got
// empty Extras and every event shipped without a UA.
func TestRegisterLogCollector_WebLogsAloneStillResolvesFields(t *testing.T) {
	a := newWebLogTestApp(t, &weblog.Config{Enabled: true, LogPaths: []string{webLogPath}})
	a.registerLogCollector(context.Background(), nginx.LogConfig{
		LogPaths:  []string{webLogPath},
		LogFormat: safeFormat,
	})

	assert.Equal(t, "http_user_agent", a.botlogAliases.UserAgent)
	assert.Contains(t, a.logCfg.ExtractFields, "http_user_agent")
	// $proxy_host is the web stream's alone — the bot stream has no field for it.
	assert.Contains(t, a.logCfg.ExtractFields, "proxy_host")
}

func TestRegisterLogCollector_ProxyHostOnlyForWebLogs(t *testing.T) {
	a := newLogCollectorTestApp(t) // BotLogs only
	a.registerLogCollector(context.Background(), nginx.LogConfig{
		LogPaths:  []string{webLogPath},
		LogFormat: safeFormat,
	})

	assert.NotContains(t, a.logCfg.ExtractFields, "proxy_host",
		"an extra field costs a slot out of the MaxExtras budget")
}

func TestRegisterWebLogs(t *testing.T) {
	newRunning := func(t *testing.T, cfg *weblog.Config, format string) *App {
		t.Helper()
		a := newWebLogTestApp(t, cfg)
		a.registerLogCollector(context.Background(), nginx.LogConfig{
			LogPaths:  []string{webLogPath},
			LogFormat: format,
		})
		// Cancelled up front: the pusher goroutine has nothing queued, so it
		// exits without touching the network.
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		a.registerWebLogs(ctx)
		return a
	}

	t.Run("usable format attaches the observer", func(t *testing.T) {
		a := newRunning(t, &weblog.Config{
			Enabled: true, Token: "wl_test", Endpoint: "http://example.invalid/v1/web-logs",
			LogPaths: []string{webLogPath},
		}, safeFormat)

		tailed, ok := tailedPaths(t, a.registry)
		require.True(t, ok, "stream did not start")
		assert.InDelta(t, 1.0, tailed, 1e-9)
	})

	// The refusal that matters most: a format one config line away from a vhost
	// we tail must not be shipped, and with nothing left the stream does not
	// start at all.
	t.Run("format carrying cookies is refused and the stream does not start", func(t *testing.T) {
		a := newRunning(t, &weblog.Config{
			Enabled: true, Token: "wl_test", Endpoint: "http://example.invalid/v1/web-logs",
			LogPaths: []string{webLogPath},
		}, safeFormat+` "$http_cookie"`)

		_, ok := tailedPaths(t, a.registry)
		assert.False(t, ok, "no path is usable — nothing should be registered")
		assert.InDelta(t, 1.0,
			counterValue(t, a.configWarnings.WithLabelValues(weblog.KindUnsafeFormat)), 1e-9)
	})

	// A shared token cannot be revoked separately, which is the whole reason
	// the two streams have one each.
	t.Run("token reused from the bot stream disables it", func(t *testing.T) {
		a := newWebLogTestApp(t, &weblog.Config{
			Enabled: true, Token: "shared", Endpoint: "http://example.invalid/v1/web-logs",
			LogPaths: []string{webLogPath},
		})
		a.cfg.BotLogs.Token = "shared"
		a.registerLogCollector(context.Background(), nginx.LogConfig{
			LogPaths: []string{webLogPath}, LogFormat: safeFormat,
		})
		a.registerWebLogs(context.Background())

		_, ok := tailedPaths(t, a.registry)
		assert.False(t, ok)
	})

	t.Run("disabled section is a no-op", func(t *testing.T) {
		a := newWebLogTestApp(t, &weblog.Config{Enabled: false})
		a.registerWebLogs(context.Background())

		_, ok := tailedPaths(t, a.registry)
		assert.False(t, ok)
	})
}
