package app

import (
	"testing"

	"github.com/vmkteam/topsrv/internal/topsrv/nginx"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vmkteam/embedlog"
)

// fakeCollector is a minimal topsrv.Collector used to drive instrumentedCollector in tests.
type fakeCollector struct {
	name       string
	onCollect  func(ch chan<- prometheus.Metric)
	onDescribe func(ch chan<- *prometheus.Desc)
}

func (f *fakeCollector) Name() string                        { return f.name }
func (f *fakeCollector) Describe(ch chan<- *prometheus.Desc) { f.onDescribe(ch) }
func (f *fakeCollector) Collect(ch chan<- prometheus.Metric) { f.onCollect(ch) }
func noopDescribe(_ chan<- *prometheus.Desc)                 {}
func noopCollect(_ chan<- prometheus.Metric)                 {}

func newInstrumented(inner *fakeCollector) (*instrumentedCollector, prometheus.Counter) {
	duration := prometheus.NewGauge(prometheus.GaugeOpts{Name: "test_scrape_duration_seconds", Help: "test"})
	panics := prometheus.NewCounter(prometheus.CounterOpts{Name: "test_scrape_panics_total", Help: "test"})
	return &instrumentedCollector{
		inner:    inner,
		logger:   embedlog.Logger{},
		duration: duration,
		panics:   panics,
	}, panics
}

func counterValue(t *testing.T, c prometheus.Counter) float64 {
	t.Helper()
	var m dto.Metric
	require.NoError(t, c.Write(&m))
	return m.GetCounter().GetValue()
}

// TestInstrumentedCollectorRecoversPanic is the contract test for the operability
// guarantee: one buggy collector must not take down /metrics. If Collect() panics,
// the wrapper must recover, increment panics_total, and return normally.
func TestInstrumentedCollectorRecoversPanic(t *testing.T) {
	panicky := &fakeCollector{
		name:       "panicky",
		onDescribe: noopDescribe,
		onCollect:  func(_ chan<- prometheus.Metric) { panic("boom") },
	}
	ic, panics := newInstrumented(panicky)

	ch := make(chan prometheus.Metric, 1)
	assert.NotPanics(t, func() { ic.Collect(ch) }, "instrumentedCollector must swallow panics from inner.Collect")
	assert.InDelta(t, 1.0, counterValue(t, panics), 1e-9, "panics counter must be incremented once")
}

// TestLogHasUserAgent guards the BotLogs "silent zero metrics" trap (O4):
// when no tailed log_format contains $http_user_agent, Observer drops every
// line and operators see an empty match_total with no explanation. The check
// must cover both the discovered per-path map and the single LogFormat
// override used when AccessLogs are configured manually.
func TestLogHasUserAgent(t *testing.T) {
	cases := []struct {
		name string
		cfg  nginx.LogConfig
		want bool
	}{
		{"empty", nginx.LogConfig{}, false},
		{"single format with UA", nginx.LogConfig{LogFormat: "$remote_addr - $http_user_agent"}, true},
		{"single format without UA", nginx.LogConfig{LogFormat: "$remote_addr $request_time"}, false},
		{"map with UA", nginx.LogConfig{LogFormats: map[string]string{"/a": "$http_user_agent"}}, true},
		{"map without UA", nginx.LogConfig{LogFormats: map[string]string{"/a": "$remote_addr"}}, false},
		{"any-of map has UA", nginx.LogConfig{LogFormats: map[string]string{
			"/a": "$remote_addr",
			"/b": "$http_user_agent",
		}}, true},
		{"json with UA", nginx.LogConfig{LogFormats: map[string]string{
			"/a": `{"ua":"$http_user_agent"}`,
		}}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, logHasUserAgent(tc.cfg))
		})
	}
}

// TestInstrumentedCollectorNormalCallNoPanicCount verifies the counter stays zero
// for well-behaved collectors — panics_total must be signal, not noise.
func TestInstrumentedCollectorNormalCallNoPanicCount(t *testing.T) {
	wellBehaved := &fakeCollector{
		name:       "ok",
		onDescribe: noopDescribe,
		onCollect:  noopCollect,
	}
	ic, panics := newInstrumented(wellBehaved)

	ch := make(chan prometheus.Metric, 1)
	ic.Collect(ch)
	assert.InDelta(t, 0.0, counterValue(t, panics), 1e-9)
}
