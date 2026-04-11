package topsrv

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vmkteam/embedlog"
)

func TestNetworkCollector(t *testing.T) {
	c := NewNetworkCollector(embedlog.Logger{})
	assert.Equal(t, "network", c.Name())

	n := collectAndLint(t, c)
	require.NotZero(t, n, "network collector returned no metrics")
}

func TestNetworkCollectorKeyMetrics(t *testing.T) {
	reg := prometheus.NewRegistry()
	reg.MustRegister(NewNetworkCollector(embedlog.Logger{}))

	requireMetric(t, reg, "topsrv_network_bytes_total")
	requireMetric(t, reg, "topsrv_network_packets_total")
	requireMetric(t, reg, "topsrv_network_errors_total")
	requireMetric(t, reg, "topsrv_network_drops_total")
	requireMetric(t, reg, "topsrv_network_info")
}

func TestNetworkCollectorDirectionLabels(t *testing.T) {
	reg := prometheus.NewRegistry()
	reg.MustRegister(NewNetworkCollector(embedlog.Logger{}))

	mfs, err := reg.Gather()
	require.NoError(t, err)

	for _, mf := range mfs {
		if mf.GetName() != "topsrv_network_bytes_total" {
			continue
		}
		directions := map[string]bool{}
		for _, m := range mf.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "direction" {
					directions[l.GetValue()] = true
				}
			}
		}
		assert.True(t, directions["rx"], "missing direction: rx")
		assert.True(t, directions["tx"], "missing direction: tx")
		return
	}
	t.Fatal("topsrv_network_bytes_total not found")
}

func TestNetworkCollectorInterfaceInfo(t *testing.T) {
	reg := prometheus.NewRegistry()
	reg.MustRegister(NewNetworkCollector(embedlog.Logger{}))

	mfs, err := reg.Gather()
	require.NoError(t, err)

	for _, mf := range mfs {
		if mf.GetName() != "topsrv_network_info" {
			continue
		}
		require.NotEmpty(t, mf.GetMetric())

		// Check labels: interface, mac, address, mtu, operstate.
		labels := mf.GetMetric()[0].GetLabel()
		labelNames := make([]string, len(labels))
		for i, l := range labels {
			labelNames[i] = l.GetName()
		}
		assert.Contains(t, labelNames, "interface")
		assert.Contains(t, labelNames, "mac")
		assert.Contains(t, labelNames, "mtu")
		assert.Contains(t, labelNames, "operstate")
		return
	}
	t.Fatal("topsrv_network_info not found")
}
