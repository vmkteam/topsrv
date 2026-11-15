package topsrv

import (
	"context"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/vmkteam/embedlog"
)

const msToSec = 1e-3

// DiskCollector collects disk device and filesystem metrics.
type DiskCollector struct {
	embedlog.Logger

	readBytes  *prometheus.Desc
	writeBytes *prometheus.Desc
	readOps    *prometheus.Desc
	writeOps   *prometheus.Desc
	readTime   *prometheus.Desc
	writeTime  *prometheus.Desc
	ioTime     *prometheus.Desc
	weightedIO *prometheus.Desc
	fsBytes    *prometheus.Desc
	fsInodes   *prometheus.Desc
}

func NewDiskCollector(logger embedlog.Logger) *DiskCollector {
	return &DiskCollector{
		Logger:     logger,
		readBytes:  prometheus.NewDesc("topsrv_disk_read_bytes_total", "Total bytes read from disk device.", []string{"device"}, nil),
		writeBytes: prometheus.NewDesc("topsrv_disk_write_bytes_total", "Total bytes written to disk device.", []string{"device"}, nil),
		readOps:    prometheus.NewDesc("topsrv_disk_read_ops_total", "Total read operations on disk device.", []string{"device"}, nil),
		writeOps:   prometheus.NewDesc("topsrv_disk_write_ops_total", "Total write operations on disk device.", []string{"device"}, nil),
		readTime:   prometheus.NewDesc("topsrv_disk_read_time_seconds_total", "Total time spent reading from disk device.", []string{"device"}, nil),
		writeTime:  prometheus.NewDesc("topsrv_disk_write_time_seconds_total", "Total time spent writing to disk device.", []string{"device"}, nil),
		ioTime:     prometheus.NewDesc("topsrv_disk_io_time_seconds_total", "Total time spent doing I/O.", []string{"device"}, nil),
		weightedIO: prometheus.NewDesc("topsrv_disk_io_time_weighted_seconds_total", "Weighted time spent doing I/O (queue depth).", []string{"device"}, nil),
		fsBytes:    prometheus.NewDesc("topsrv_filesystem_bytes", "Filesystem space in bytes.", []string{"mountpoint", "device", "fstype", "type"}, nil),
		fsInodes:   prometheus.NewDesc("topsrv_filesystem_inodes", "Filesystem inodes.", []string{"mountpoint", "type"}, nil),
	}
}

var _ Collector = (*DiskCollector)(nil)

func (c *DiskCollector) Name() string { return "disk" }

func (c *DiskCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.readBytes
	ch <- c.writeBytes
	ch <- c.readOps
	ch <- c.writeOps
	ch <- c.readTime
	ch <- c.writeTime
	ch <- c.ioTime
	ch <- c.weightedIO
	ch <- c.fsBytes
	ch <- c.fsInodes
}

func (c *DiskCollector) Collect(ch chan<- prometheus.Metric) {
	c.collectIO(ch)
	c.collectFilesystems(ch)
}

func (c *DiskCollector) collectIO(ch chan<- prometheus.Metric) {
	counters, err := disk.IOCounters()
	if err != nil {
		c.Print(context.Background(), "disk: IOCounters failed", "error", err)
		return
	}
	for dev, io := range counters {
		ch <- prometheus.MustNewConstMetric(c.readBytes, prometheus.CounterValue, float64(io.ReadBytes), dev)
		ch <- prometheus.MustNewConstMetric(c.writeBytes, prometheus.CounterValue, float64(io.WriteBytes), dev)
		ch <- prometheus.MustNewConstMetric(c.readOps, prometheus.CounterValue, float64(io.ReadCount), dev)
		ch <- prometheus.MustNewConstMetric(c.writeOps, prometheus.CounterValue, float64(io.WriteCount), dev)
		ch <- prometheus.MustNewConstMetric(c.readTime, prometheus.CounterValue, float64(io.ReadTime)*msToSec, dev)
		ch <- prometheus.MustNewConstMetric(c.writeTime, prometheus.CounterValue, float64(io.WriteTime)*msToSec, dev)
		ch <- prometheus.MustNewConstMetric(c.ioTime, prometheus.CounterValue, float64(io.IoTime)*msToSec, dev)
		ch <- prometheus.MustNewConstMetric(c.weightedIO, prometheus.CounterValue, float64(io.WeightedIO)*msToSec, dev)
	}
}

func (c *DiskCollector) collectFilesystems(ch chan<- prometheus.Metric) {
	partitions, err := disk.Partitions(false)
	if err != nil {
		c.Print(context.Background(), "disk: Partitions failed", "error", err)
		return
	}
	// A filesystem mounted at several places reports the same space at each:
	// btrfs subvolumes, a bind of a whole mount (root "/", which gopsutil does
	// not flag). The first mount wins, mountinfo lists them in mount order.
	seen := make(map[string]bool, len(partitions))
	for _, p := range partitions {
		if seen[p.Device] || isEphemeralMount(p) {
			continue
		}
		usage, err := disk.Usage(p.Mountpoint)
		if err != nil {
			continue
		}
		seen[p.Device] = true
		ch <- prometheus.MustNewConstMetric(c.fsBytes, prometheus.GaugeValue, float64(usage.Total), p.Mountpoint, p.Device, p.Fstype, "total")
		ch <- prometheus.MustNewConstMetric(c.fsBytes, prometheus.GaugeValue, float64(usage.Used), p.Mountpoint, p.Device, p.Fstype, "used")
		ch <- prometheus.MustNewConstMetric(c.fsBytes, prometheus.GaugeValue, float64(usage.Free), p.Mountpoint, p.Device, p.Fstype, "free")
		ch <- prometheus.MustNewConstMetric(c.fsInodes, prometheus.GaugeValue, float64(usage.InodesTotal), p.Mountpoint, "total")
		ch <- prometheus.MustNewConstMetric(c.fsInodes, prometheus.GaugeValue, float64(usage.InodesUsed), p.Mountpoint, "used")
		ch <- prometheus.MustNewConstMetric(c.fsInodes, prometheus.GaugeValue, float64(usage.InodesFree), p.Mountpoint, "free")
	}
}

// isEphemeralMount reports ZFS mounts that come and go with containers and
// snapshot browsing. Partitions(false) keeps every ZFS dataset, so without
// this a Docker host on the zfs storage driver would emit a series set per
// running container layer, and every snapshot automounted under .zfs/snapshot
// (source pool/ds@snap) would add one too.
func isEphemeralMount(p disk.PartitionStat) bool {
	if p.Fstype != "zfs" {
		return false
	}
	return strings.Contains(p.Device, "@") || strings.Contains(p.Mountpoint, "/zfs/graph/")
}
