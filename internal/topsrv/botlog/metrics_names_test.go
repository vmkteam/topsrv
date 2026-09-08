package botlog

import (
	"sort"
	"strings"
	"testing"

	"github.com/vmkteam/topsrv/internal/topsrv"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vmkteam/embedlog"
)

// The bot-log metric names are load-bearing for existing dashboards and alerts.
// Delivery moved to another package; the names must not have moved with it.
func TestPusherMetricNamesUnchanged(t *testing.T) {
	cfg := Config{Enabled: true, Endpoint: "http://x.invalid/", Token: "bl_test", BatchSize: 10}
	require.NoError(t, cfg.Validate(topsrv.PushConfig{}))

	reg := prometheus.NewRegistry()
	p := NewPusher(embedlog.Logger{}, "topsrv-test", "test", cfg, reg)
	// A CounterVec with no observations never reaches Gather, so the UA metric
	// needs one tick to show up. send_errors_total has no such entry point here
	// and is covered where it actually fires — the shipper delivery tests.
	p.RecordMatch("openai")

	families, err := reg.Gather()
	require.NoError(t, err)
	got := make([]string, 0, len(families))
	for _, f := range families {
		got = append(got, f.GetName())
	}
	sort.Strings(got)

	assert.Equal(t, []string{
		"topsrv_botlog_batch_duration_seconds",
		"topsrv_botlog_events_total",
		"topsrv_botlog_match_total",
		"topsrv_botlog_queue_depth",
		"topsrv_botlog_spool_bytes",
		"topsrv_botlog_spool_files",
	}, got)

	for _, name := range got {
		assert.True(t, strings.HasPrefix(name, "topsrv_botlog_"), name)
	}
}
