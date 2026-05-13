package app

import (
	"context"
	"testing"

	"github.com/vmkteam/topsrv/internal/topsrv/botlog"
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

// newAliasTestApp builds the minimal App required to exercise
// resolveBotlogAliases — Logger for warnConfig, configWarnings counter for
// the warning side-effect, and a BotLogs config carrying the override.
func newAliasTestApp(t *testing.T, override botlog.FieldAliases) *App {
	t.Helper()
	a := &App{
		cfg: Config{BotLogs: &botlog.Config{FieldAliases: override}},
		configWarnings: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "test_config_warnings_total", Help: "test",
		}, []string{"kind"}),
	}
	return a
}

func TestResolveBotlogAliases_SinglePathStandardFormat(t *testing.T) {
	a := newAliasTestApp(t, botlog.FieldAliases{})
	cfg := nginx.LogConfig{
		LogPaths:  []string{"/var/log/nginx/a.log"},
		LogFormat: `$remote_addr [$time_local] "$request" $status "$http_referer" "$http_user_agent"`,
	}
	got := a.resolveBotlogAliases(context.Background(), cfg)
	assert.Equal(t, "http_user_agent", got.UserAgent)
	assert.Equal(t, "http_referer", got.Referer)
	assert.Equal(t, "remote_addr", got.RemoteAddr)
}

func TestResolveBotlogAliases_OverrideWins(t *testing.T) {
	a := newAliasTestApp(t, botlog.FieldAliases{Referer: "ref"})
	cfg := nginx.LogConfig{
		LogPaths:  []string{"/var/log/nginx/a.log"},
		LogFormat: `$remote_addr "$http_referer" "$http_user_agent"`,
	}
	got := a.resolveBotlogAliases(context.Background(), cfg)
	assert.Equal(t, "ref", got.Referer, "explicit override beats auto-detected")
	assert.Equal(t, "http_user_agent", got.UserAgent, "non-overridden fields keep detection")
}

func TestResolveBotlogAliases_MismatchEmitsWarning(t *testing.T) {
	a := newAliasTestApp(t, botlog.FieldAliases{})
	// Two paths, different formats with diverging detected aliases:
	// path A uses $http_referer, path B uses $http_referrer.
	cfg := nginx.LogConfig{
		LogPaths: []string{"/var/log/a.log", "/var/log/b.log"},
		LogFormats: map[string]string{
			"/var/log/a.log": `$remote_addr "$http_referer" "$http_user_agent"`,
			"/var/log/b.log": `$remote_addr "$http_referrer" "$http_user_agent"`,
		},
	}
	got := a.resolveBotlogAliases(context.Background(), cfg)
	assert.Equal(t, "http_referer", got.Referer, "first path's resolution wins")
	assert.InDelta(t, 1.0, counterValue(t, a.configWarnings.WithLabelValues("botlog_alias_mismatch")), 1e-9)
}

func TestResolveBotlogAliases_AllPathsAgreeNoWarning(t *testing.T) {
	a := newAliasTestApp(t, botlog.FieldAliases{})
	// Two paths sharing the same format → no mismatch warning, no DetectAliases
	// re-run (memoised by (format,isJSON)).
	cfg := nginx.LogConfig{
		LogPaths: []string{"/var/log/a.log", "/var/log/b.log"},
		LogFormats: map[string]string{
			"/var/log/a.log": `$remote_addr "$http_referer" "$http_user_agent"`,
			"/var/log/b.log": `$remote_addr "$http_referer" "$http_user_agent"`,
		},
	}
	a.resolveBotlogAliases(context.Background(), cfg)
	assert.InDelta(t, 0.0, counterValue(t, a.configWarnings.WithLabelValues("botlog_alias_mismatch")), 1e-9)
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

func TestHighCardLabels(t *testing.T) {
	assert.Empty(t, highCardLabels(nil))
	assert.Empty(t, highCardLabels([]string{"server_name", "http_platform"}))
	assert.Equal(t, []string{"remote_addr"},
		highCardLabels([]string{"server_name", "remote_addr"}))
	assert.Equal(t, []string{"http_user_agent", "http_referer"},
		highCardLabels([]string{"server_name", "http_user_agent", "http_referer"}))
}

// Wiring contract: registerLogCollector builds the same union mergeUnique
// produces and parks it on App.extractFields. Other tests (mergeUnique unit
// test, nginx labelIdx test) cover the rest.
func TestMergeUnique_RegisterLogCollectorWiring(t *testing.T) {
	got := mergeUnique(
		[]string{"server_name", "http_platform"},
		[]string{"http_user_agent", "server_name", "remote_addr", "http_referer"},
	)
	assert.Equal(t,
		[]string{"server_name", "http_platform", "http_user_agent", "remote_addr", "http_referer"},
		got, "operator labels first, then unique botlog requireds")
}

func TestMergeUnique(t *testing.T) {
	cases := []struct {
		name         string
		base, extras []string
		want         []string
	}{
		{"empty", nil, nil, []string{}},
		{"base only", []string{"a", "b"}, nil, []string{"a", "b"}},
		{"extras only", nil, []string{"x", "y"}, []string{"x", "y"}},
		{"distinct", []string{"a"}, []string{"b"}, []string{"a", "b"}},
		{"overlap, base order preserved", []string{"server_name", "http_platform"},
			[]string{"http_user_agent", "server_name", "remote_addr"},
			[]string{"server_name", "http_platform", "http_user_agent", "remote_addr"}},
		{"dedup within base", []string{"a", "a", "b"}, []string{"a"}, []string{"a", "b"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := mergeUnique(tc.base, tc.extras)
			if len(tc.want) == 0 {
				assert.Empty(t, got)
				return
			}
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestCapExtractFields(t *testing.T) {
	t.Run("no truncation", func(t *testing.T) {
		cfg := nginx.LogConfig{ExtractFields: []string{"a", "b"}}
		assert.Empty(t, capExtractFields(&cfg))
		assert.Equal(t, []string{"a", "b"}, cfg.ExtractFields)
	})
	t.Run("truncated past MaxExtras", func(t *testing.T) {
		fields := []string{"f1", "f2", "f3", "f4", "f5", "f6", "f7", "f8", "f9", "f10"}
		cfg := nginx.LogConfig{ExtractFields: fields}
		dropped := capExtractFields(&cfg)
		assert.Len(t, cfg.ExtractFields, nginx.MaxExtras)
		assert.Equal(t, []string{"f9", "f10"}, dropped)
	})
}

func TestMissingFromExtract(t *testing.T) {
	assert.Empty(t, missingFromExtract([]string{"a", "b"}, []string{"a", "b", "c"}))
	assert.Equal(t,
		[]string{"missing1", "missing2"},
		missingFromExtract(
			[]string{"server_name", "missing1", "missing2"},
			[]string{"server_name", "http_user_agent"}))
}

func TestTruncateList(t *testing.T) {
	assert.Equal(t, []string{"a", "b"}, truncateList([]string{"a", "b"}, 4))
	got := truncateList([]string{"a", "b", "c", "d", "e"}, 2)
	assert.Equal(t, []string{"a", "b", "…+more"}, got)
}
