package topsrv

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vmkteam/embedlog"
)

func TestNetstatCollector(t *testing.T) {
	c := NewNetstatCollector(embedlog.Logger{})
	assert.Equal(t, "netstat", c.Name())

	n := collectAndLint(t, c)
	t.Logf("netstat collector returned %d metric families", n)
}

func TestNetstatCollectorTCPConnections(t *testing.T) {
	reg := prometheus.NewRegistry()
	reg.MustRegister(NewNetstatCollector(embedlog.Logger{}))

	mfs, err := reg.Gather()
	require.NoError(t, err)

	for _, mf := range mfs {
		if mf.GetName() != "topsrv_netstat_tcp_connections" {
			continue
		}

		// Check direction labels: inbound/outbound.
		directions := map[string]bool{}
		states := map[string]bool{}
		for _, m := range mf.GetMetric() {
			for _, l := range m.GetLabel() {
				switch l.GetName() {
				case "direction":
					directions[l.GetValue()] = true
				case "state":
					states[l.GetValue()] = true
				}
			}
		}

		// At least LISTEN should be present on any system.
		assert.True(t, states["LISTEN"], "missing TCP state: LISTEN")
		assert.True(t, directions["inbound"], "missing direction: inbound")
		t.Logf("TCP states: %v, directions: %v", states, directions)
		return
	}
	t.Log("topsrv_netstat_tcp_connections not found (may require elevated permissions)")
}

func TestNetstatCollectorProtoCounters(t *testing.T) {
	reg := prometheus.NewRegistry()
	reg.MustRegister(NewNetstatCollector(embedlog.Logger{}))

	mfs, err := reg.Gather()
	require.NoError(t, err)

	names := map[string]bool{}
	for _, mf := range mfs {
		names[mf.GetName()] = true
	}

	// Proto counters may not be available on macOS.
	if names["topsrv_netstat_tcp_retransmits_total"] {
		requireMetric(t, reg, "topsrv_netstat_tcp_retransmits_total")
		requireMetric(t, reg, "topsrv_netstat_tcp_in_errs_total")
		requireMetric(t, reg, "topsrv_netstat_tcp_out_rsts_total")
		t.Log("protocol counters present")
	} else {
		t.Log("protocol counters not available on this system, skipping")
	}
}

func TestNetstatCollectorConnectionsByPort(t *testing.T) {
	reg := prometheus.NewRegistry()
	reg.MustRegister(NewNetstatCollector(embedlog.Logger{}))

	mfs, err := reg.Gather()
	require.NoError(t, err)

	for _, mf := range mfs {
		if mf.GetName() != "topsrv_netstat_tcp_connections_by_port" {
			continue
		}
		require.NotEmpty(t, mf.GetMetric())

		// Check port label exists.
		labels := mf.GetMetric()[0].GetLabel()
		labelNames := make([]string, len(labels))
		for i, l := range labels {
			labelNames[i] = l.GetName()
		}
		assert.Contains(t, labelNames, "port")
		return
	}
	t.Log("topsrv_netstat_tcp_connections_by_port not found (may require elevated permissions)")
}
