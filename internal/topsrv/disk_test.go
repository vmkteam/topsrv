package topsrv

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vmkteam/embedlog"
)

func TestDiskCollector(t *testing.T) {
	c := NewDiskCollector(embedlog.Logger{})
	assert.Equal(t, "disk", c.Name())

	n := collectAndLint(t, c)
	require.NotZero(t, n, "disk collector returned no metrics")
}

func TestDiskCollectorKeyMetrics(t *testing.T) {
	reg := prometheus.NewRegistry()
	reg.MustRegister(NewDiskCollector(embedlog.Logger{}))

	// Filesystem metrics (always present).
	requireMetric(t, reg, "topsrv_filesystem_bytes")
	requireMetric(t, reg, "topsrv_filesystem_inodes")
}

func TestDiskCollectorIOMetrics(t *testing.T) {
	reg := prometheus.NewRegistry()
	reg.MustRegister(NewDiskCollector(embedlog.Logger{}))

	mfs, err := reg.Gather()
	require.NoError(t, err)

	// IO metrics may be absent on some systems (e.g., macOS without physical disks).
	ioNames := map[string]bool{}
	for _, mf := range mfs {
		ioNames[mf.GetName()] = true
	}

	if ioNames["topsrv_disk_read_bytes_total"] {
		requireMetric(t, reg, "topsrv_disk_read_bytes_total")
		requireMetric(t, reg, "topsrv_disk_write_bytes_total")
		requireMetric(t, reg, "topsrv_disk_read_ops_total")
		requireMetric(t, reg, "topsrv_disk_write_ops_total")
		requireMetric(t, reg, "topsrv_disk_read_time_seconds_total")
		requireMetric(t, reg, "topsrv_disk_write_time_seconds_total")
		requireMetric(t, reg, "topsrv_disk_io_time_seconds_total")
		requireMetric(t, reg, "topsrv_disk_io_time_weighted_seconds_total")
	} else {
		t.Log("disk IO metrics not available on this system, skipping IO checks")
	}
}

func TestDiskCollectorFilesystemLabels(t *testing.T) {
	reg := prometheus.NewRegistry()
	reg.MustRegister(NewDiskCollector(embedlog.Logger{}))

	mfs, err := reg.Gather()
	require.NoError(t, err)

	for _, mf := range mfs {
		if mf.GetName() != "topsrv_filesystem_bytes" {
			continue
		}
		require.NotEmpty(t, mf.GetMetric())

		// Check labels: mountpoint, device, fstype, type.
		labels := mf.GetMetric()[0].GetLabel()
		labelNames := make([]string, len(labels))
		for i, l := range labels {
			labelNames[i] = l.GetName()
		}
		assert.Contains(t, labelNames, "mountpoint")
		assert.Contains(t, labelNames, "device")
		assert.Contains(t, labelNames, "fstype")
		assert.Contains(t, labelNames, "type")

		// Check type values: total, used, free.
		types := map[string]bool{}
		for _, m := range mf.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "type" {
					types[l.GetValue()] = true
				}
			}
		}
		for _, typ := range []string{"total", "used", "free"} {
			assert.True(t, types[typ], "missing filesystem type: %s", typ)
		}
		return
	}
	t.Fatal("topsrv_filesystem_bytes not found")
}

func TestMsToSec(t *testing.T) {
	tests := []struct {
		ms   uint64
		want float64
	}{
		{0, 0},
		{1000, 1.0},
		{500, 0.5},
		{1, 0.001},
	}
	for _, tt := range tests {
		assert.InDelta(t, tt.want, float64(tt.ms)*msToSec, 1e-15)
	}
}
