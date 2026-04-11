package topsrv

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/shirou/gopsutil/v4/process"
	"github.com/vmkteam/embedlog"
)

// ProcessCollector collects per-process-group metrics (grouped by name).
type ProcessCollector struct {
	embedlog.Logger

	cpuSeconds     *prometheus.Desc
	memBytes       *prometheus.Desc
	diskReadBytes  *prometheus.Desc
	diskWriteBytes *prometheus.Desc
	diskReadOps    *prometheus.Desc
	diskWriteOps   *prometheus.Desc
	procCount      *prometheus.Desc
	threads        *prometheus.Desc
	openFDs        *prometheus.Desc
	worstFDRatio   *prometheus.Desc
	majorFaults    *prometheus.Desc
}

func NewProcessCollector(logger embedlog.Logger) *ProcessCollector {
	return &ProcessCollector{
		Logger:         logger,
		cpuSeconds:     prometheus.NewDesc("topsrv_process_cpu_seconds_total", "CPU time consumed by process group.", []string{"group"}, nil),
		memBytes:       prometheus.NewDesc("topsrv_process_memory_bytes", "Memory usage by process group.", []string{"group", "type"}, nil),
		diskReadBytes:  prometheus.NewDesc("topsrv_process_disk_read_bytes_total", "Disk bytes read by process group.", []string{"group"}, nil),
		diskWriteBytes: prometheus.NewDesc("topsrv_process_disk_write_bytes_total", "Disk bytes written by process group.", []string{"group"}, nil),
		diskReadOps:    prometheus.NewDesc("topsrv_process_disk_read_ops_total", "Disk read operations by process group.", []string{"group"}, nil),
		diskWriteOps:   prometheus.NewDesc("topsrv_process_disk_write_ops_total", "Disk write operations by process group.", []string{"group"}, nil),
		procCount:      prometheus.NewDesc("topsrv_process_num_procs", "Number of processes in group.", []string{"group"}, nil),
		threads:        prometheus.NewDesc("topsrv_process_threads", "Number of threads in process group.", []string{"group"}, nil),
		openFDs:        prometheus.NewDesc("topsrv_process_open_fds", "Number of open file descriptors in process group.", []string{"group"}, nil),
		worstFDRatio:   prometheus.NewDesc("topsrv_process_worst_fd_ratio", "Worst open FD to soft limit ratio in group.", []string{"group"}, nil),
		majorFaults:    prometheus.NewDesc("topsrv_process_major_page_faults_total", "Major page faults by process group.", []string{"group"}, nil),
	}
}

var _ Collector = (*ProcessCollector)(nil)

func (c *ProcessCollector) Name() string { return "process" }

func (c *ProcessCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.cpuSeconds
	ch <- c.memBytes
	ch <- c.diskReadBytes
	ch <- c.diskWriteBytes
	ch <- c.diskReadOps
	ch <- c.diskWriteOps
	ch <- c.procCount
	ch <- c.threads
	ch <- c.openFDs
	ch <- c.worstFDRatio
	ch <- c.majorFaults
}

func (c *ProcessCollector) Collect(ch chan<- prometheus.Metric) {
	procs, err := process.Processes()
	if err != nil {
		c.Errorf("process: Processes failed: %v", err)
		return
	}

	groups := make(map[string]*procGroup, 64)

	for _, p := range procs {
		name, err := p.Name()
		if err != nil || name == "" {
			continue
		}

		g, ok := groups[name]
		if !ok {
			g = &procGroup{}
			groups[name] = g
		}
		g.count++

		c.collectProcess(p, g)
	}

	for name, g := range groups {
		ch <- prometheus.MustNewConstMetric(c.cpuSeconds, prometheus.CounterValue, g.cpuUser+g.cpuSystem, name)
		ch <- prometheus.MustNewConstMetric(c.memBytes, prometheus.GaugeValue, float64(g.rss), name, "rss")
		ch <- prometheus.MustNewConstMetric(c.memBytes, prometheus.GaugeValue, float64(g.vms), name, "vms")
		ch <- prometheus.MustNewConstMetric(c.memBytes, prometheus.GaugeValue, float64(g.swap), name, "swap")
		ch <- prometheus.MustNewConstMetric(c.procCount, prometheus.GaugeValue, float64(g.count), name)
		ch <- prometheus.MustNewConstMetric(c.threads, prometheus.GaugeValue, float64(g.threads), name)
		ch <- prometheus.MustNewConstMetric(c.majorFaults, prometheus.CounterValue, float64(g.majorFaults), name)

		// Linux only — emit only when data was collected.
		if g.hasDiskIO {
			ch <- prometheus.MustNewConstMetric(c.diskReadBytes, prometheus.CounterValue, float64(g.readBytes), name)
			ch <- prometheus.MustNewConstMetric(c.diskWriteBytes, prometheus.CounterValue, float64(g.writeBytes), name)
			ch <- prometheus.MustNewConstMetric(c.diskReadOps, prometheus.CounterValue, float64(g.readOps), name)
			ch <- prometheus.MustNewConstMetric(c.diskWriteOps, prometheus.CounterValue, float64(g.writeOps), name)
		}
		if g.hasFDs {
			ch <- prometheus.MustNewConstMetric(c.openFDs, prometheus.GaugeValue, float64(g.openFDs), name)
			ch <- prometheus.MustNewConstMetric(c.worstFDRatio, prometheus.GaugeValue, g.worstFDRatio, name)
		}
	}
}

// collectProcess accumulates metrics from a single process into its group.
func (c *ProcessCollector) collectProcess(p *process.Process, g *procGroup) {
	if times, err := p.Times(); err == nil {
		g.cpuUser += times.User
		g.cpuSystem += times.System
	}

	if mem, err := p.MemoryInfo(); err == nil {
		g.rss += mem.RSS
		g.vms += mem.VMS
		g.swap += mem.Swap
	}

	if pf, err := p.PageFaults(); err == nil {
		g.majorFaults += pf.MajorFaults
	}

	if threads, err := p.NumThreads(); err == nil {
		g.threads += int(threads)
	}

	// Linux only: disk IO.
	if io, err := p.IOCounters(); err == nil {
		g.hasDiskIO = true
		g.readBytes += io.ReadBytes
		g.writeBytes += io.WriteBytes
		g.readOps += io.ReadCount
		g.writeOps += io.WriteCount
	}

	// Linux only: file descriptors.
	if fds, err := p.NumFDs(); err == nil { //nolint:nestif
		g.hasFDs = true
		g.openFDs += int(fds)

		// worst_fd_ratio: max(open/soft_limit) across group.
		if rlimits, err := p.RlimitUsage(false); err == nil {
			for _, r := range rlimits {
				if r.Resource == process.RLIMIT_NOFILE && r.Soft > 0 {
					ratio := float64(fds) / float64(r.Soft)
					if ratio > g.worstFDRatio {
						g.worstFDRatio = ratio
					}
					break
				}
			}
		}
	}
}

type procGroup struct {
	cpuUser, cpuSystem    float64
	rss, vms, swap        uint64
	readBytes, writeBytes uint64
	readOps, writeOps     uint64
	majorFaults           uint64
	count, threads        int
	openFDs               int
	worstFDRatio          float64
	hasDiskIO, hasFDs     bool
}
