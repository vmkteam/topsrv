package topsrv

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vmkteam/embedlog"
)

func TestSystemCollector(t *testing.T) {
	c := NewSystemCollector(embedlog.Logger{})
	assert.Equal(t, "system", c.Name())

	n := collectAndLint(t, c)
	require.NotZero(t, n, "system collector returned no metrics")
}

func TestSystemCollectorKeyMetrics(t *testing.T) {
	reg := prometheus.NewRegistry()
	reg.MustRegister(NewSystemCollector(embedlog.Logger{}))

	requireMetric(t, reg, "topsrv_cpu_seconds_total")
	requireMetric(t, reg, "topsrv_cpu_cores")
	requireMetric(t, reg, "topsrv_load_average")
	requireMetric(t, reg, "topsrv_memory_bytes")
	requireMetric(t, reg, "topsrv_swap_bytes")
	requireMetric(t, reg, "topsrv_swap_io_bytes_total")
	requireMetric(t, reg, "topsrv_uptime_seconds")
	requireMetric(t, reg, "topsrv_boot_time_seconds")
	requireMetric(t, reg, "topsrv_host_info")
}

func TestSystemCollectorCPULabels(t *testing.T) {
	reg := prometheus.NewRegistry()
	reg.MustRegister(NewSystemCollector(embedlog.Logger{}))

	mfs, err := reg.Gather()
	require.NoError(t, err)

	for _, mf := range mfs {
		if mf.GetName() != "topsrv_cpu_seconds_total" {
			continue
		}
		m := mf.GetMetric()
		require.NotEmpty(t, m, "cpu_seconds_total has no metrics")

		// Check label structure: cpu + mode.
		labels := m[0].GetLabel()
		require.GreaterOrEqual(t, len(labels), 2)
		assert.Equal(t, "cpu", labels[0].GetName())
		assert.Equal(t, "mode", labels[1].GetName())

		// Check all 8 modes exist.
		modes := map[string]bool{}
		for _, metric := range m {
			for _, l := range metric.GetLabel() {
				if l.GetName() == "mode" {
					modes[l.GetValue()] = true
				}
			}
		}
		for _, mode := range []string{"user", "system", "idle", "iowait", "steal", "irq", "softirq", "nice"} {
			assert.True(t, modes[mode], "missing CPU mode: %s", mode)
		}
		return
	}
	t.Fatal("topsrv_cpu_seconds_total not found")
}

func TestSystemCollectorMemoryTypes(t *testing.T) {
	reg := prometheus.NewRegistry()
	reg.MustRegister(NewSystemCollector(embedlog.Logger{}))

	mfs, err := reg.Gather()
	require.NoError(t, err)

	for _, mf := range mfs {
		if mf.GetName() != "topsrv_memory_bytes" {
			continue
		}
		types := map[string]bool{}
		for _, m := range mf.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "type" {
					types[l.GetValue()] = true
				}
			}
		}
		for _, typ := range []string{"total", "used", "free", "buffers", "cached", "available"} {
			assert.True(t, types[typ], "missing memory type: %s", typ)
		}
		return
	}
	t.Fatal("topsrv_memory_bytes not found")
}

func TestSystemCollectorSwapTypes(t *testing.T) {
	reg := prometheus.NewRegistry()
	reg.MustRegister(NewSystemCollector(embedlog.Logger{}))

	mfs, err := reg.Gather()
	require.NoError(t, err)

	for _, mf := range mfs {
		if mf.GetName() != "topsrv_swap_bytes" {
			continue
		}
		types := map[string]bool{}
		for _, m := range mf.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "type" {
					types[l.GetValue()] = true
				}
			}
		}
		for _, typ := range []string{"total", "used", "free"} {
			assert.True(t, types[typ], "missing swap type: %s", typ)
		}
		return
	}
	t.Fatal("topsrv_swap_bytes not found")
}
