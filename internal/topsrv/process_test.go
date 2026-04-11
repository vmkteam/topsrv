package topsrv

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vmkteam/embedlog"
)

func TestProcessCollector(t *testing.T) {
	c := NewProcessCollector(embedlog.Logger{})
	assert.Equal(t, "process", c.Name())

	n := collectAndLint(t, c)
	require.NotZero(t, n, "process collector returned no metrics")
	t.Logf("process collector returned %d metric families", n)
}

func TestProcessCollectorKeyMetrics(t *testing.T) {
	reg := prometheus.NewRegistry()
	reg.MustRegister(NewProcessCollector(embedlog.Logger{}))

	requireMetric(t, reg, "topsrv_process_cpu_seconds_total")
	requireMetric(t, reg, "topsrv_process_memory_bytes")
	requireMetric(t, reg, "topsrv_process_num_procs")
	requireMetric(t, reg, "topsrv_process_threads")
}

func TestProcessCollectorGroupLabel(t *testing.T) {
	reg := prometheus.NewRegistry()
	reg.MustRegister(NewProcessCollector(embedlog.Logger{}))

	mfs, err := reg.Gather()
	require.NoError(t, err)

	for _, mf := range mfs {
		if !strings.HasPrefix(mf.GetName(), "topsrv_process_") {
			continue
		}
		for _, m := range mf.GetMetric() {
			hasGroup := false
			for _, l := range m.GetLabel() {
				if l.GetName() == "group" {
					hasGroup = true
					assert.NotEmpty(t, l.GetValue(), "%s: empty group label", mf.GetName())
					break
				}
			}
			assert.True(t, hasGroup, "%s: missing group label", mf.GetName())
		}
	}
}

func TestProcessCollectorNoConflicts(t *testing.T) {
	reg := prometheus.NewRegistry()
	reg.MustRegister(NewSystemCollector(embedlog.Logger{}))
	reg.MustRegister(NewDiskCollector(embedlog.Logger{}))
	reg.MustRegister(NewNetworkCollector(embedlog.Logger{}))
	reg.MustRegister(NewNetstatCollector(embedlog.Logger{}))
	reg.MustRegister(NewProcessCollector(embedlog.Logger{}))

	problems, err := testutil.GatherAndLint(reg)
	require.NoError(t, err)
	for _, p := range problems {
		t.Logf("lint warning: %s", p.Text)
	}

	mfs, err := reg.Gather()
	require.NoError(t, err)
	t.Logf("total metric families with process collector: %d", len(mfs))
}
