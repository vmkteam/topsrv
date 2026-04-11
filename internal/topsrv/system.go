package topsrv

import (
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"
	"github.com/vmkteam/embedlog"
)

// SystemCollector collects CPU, memory, load average, swap, uptime, and host info metrics.
type SystemCollector struct {
	embedlog.Logger

	cpuSeconds  *prometheus.Desc
	cpuCount    *prometheus.Desc
	loadAvg     *prometheus.Desc
	memBytes    *prometheus.Desc
	swapBytes   *prometheus.Desc
	swapIO      *prometheus.Desc
	uptime      *prometheus.Desc
	bootTime    *prometheus.Desc
	hostInfo    *prometheus.Desc
	ctxSwitches *prometheus.Desc
	procsState  *prometheus.Desc

	// cached at construction (never change during process lifetime)
	cpuIDs         []string
	cachedBootTime float64
	cachedHostInfo *host.InfoStat
}

func NewSystemCollector(logger embedlog.Logger) *SystemCollector {
	cnt, _ := cpu.Counts(true)
	cpuIDs := make([]string, cnt)
	for i := range cpuIDs {
		cpuIDs[i] = strconv.Itoa(i)
	}

	bt, _ := host.BootTime()
	hi, _ := host.Info()

	return &SystemCollector{
		Logger:      logger,
		cpuSeconds:  prometheus.NewDesc("topsrv_cpu_seconds_total", "CPU time spent in each mode.", []string{"cpu", "mode"}, nil),
		cpuCount:    prometheus.NewDesc("topsrv_cpu_cores", "Number of logical CPUs.", nil, nil),
		loadAvg:     prometheus.NewDesc("topsrv_load_average", "System load average.", []string{"interval"}, nil),
		memBytes:    prometheus.NewDesc("topsrv_memory_bytes", "Memory usage in bytes.", []string{"type"}, nil),
		swapBytes:   prometheus.NewDesc("topsrv_swap_bytes", "Swap usage in bytes.", []string{"type"}, nil),
		swapIO:      prometheus.NewDesc("topsrv_swap_io_bytes_total", "Swap I/O in bytes.", []string{"direction"}, nil),
		uptime:      prometheus.NewDesc("topsrv_uptime_seconds", "System uptime in seconds.", nil, nil),
		bootTime:    prometheus.NewDesc("topsrv_boot_time_seconds", "System boot time as Unix timestamp.", nil, nil),
		hostInfo:    prometheus.NewDesc("topsrv_host_info", "Host information.", []string{"hostname", "os", "platform", "platform_version", "kernel_version", "kernel_arch"}, nil),
		ctxSwitches: prometheus.NewDesc("topsrv_context_switches_total", "Total context switches.", nil, nil),
		procsState:  prometheus.NewDesc("topsrv_procs", "Number of processes by state.", []string{"state"}, nil),

		cpuIDs:         cpuIDs,
		cachedBootTime: float64(bt),
		cachedHostInfo: hi,
	}
}

var _ Collector = (*SystemCollector)(nil)

func (c *SystemCollector) Name() string { return "system" }

func (c *SystemCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.cpuSeconds
	ch <- c.cpuCount
	ch <- c.loadAvg
	ch <- c.memBytes
	ch <- c.swapBytes
	ch <- c.swapIO
	ch <- c.uptime
	ch <- c.bootTime
	ch <- c.hostInfo
	ch <- c.ctxSwitches
	ch <- c.procsState
}

func (c *SystemCollector) Collect(ch chan<- prometheus.Metric) {
	c.collectCPU(ch)
	c.collectMemory(ch)
	c.collectLoad(ch)
	c.collectSwap(ch)
	c.collectHost(ch)
}

func (c *SystemCollector) collectCPU(ch chan<- prometheus.Metric) {
	times, err := cpu.Times(true)
	if err != nil {
		c.Printf("system: cpu.Times failed: %v", err)
		return
	}
	if len(times) == 0 {
		return
	}
	for i, t := range times {
		var id string
		if i < len(c.cpuIDs) {
			id = c.cpuIDs[i]
		} else {
			id = strconv.Itoa(i)
		}
		ch <- prometheus.MustNewConstMetric(c.cpuSeconds, prometheus.CounterValue, t.User, id, "user")
		ch <- prometheus.MustNewConstMetric(c.cpuSeconds, prometheus.CounterValue, t.System, id, "system")
		ch <- prometheus.MustNewConstMetric(c.cpuSeconds, prometheus.CounterValue, t.Idle, id, "idle")
		ch <- prometheus.MustNewConstMetric(c.cpuSeconds, prometheus.CounterValue, t.Iowait, id, "iowait")
		ch <- prometheus.MustNewConstMetric(c.cpuSeconds, prometheus.CounterValue, t.Steal, id, "steal")
		ch <- prometheus.MustNewConstMetric(c.cpuSeconds, prometheus.CounterValue, t.Irq, id, "irq")
		ch <- prometheus.MustNewConstMetric(c.cpuSeconds, prometheus.CounterValue, t.Softirq, id, "softirq")
		ch <- prometheus.MustNewConstMetric(c.cpuSeconds, prometheus.CounterValue, t.Nice, id, "nice")
	}

	cnt, err := cpu.Counts(true)
	if err == nil {
		ch <- prometheus.MustNewConstMetric(c.cpuCount, prometheus.GaugeValue, float64(cnt))
	}
}

func (c *SystemCollector) collectMemory(ch chan<- prometheus.Metric) {
	v, err := mem.VirtualMemory()
	if err != nil {
		c.Printf("system: VirtualMemory failed: %v", err)
		return
	}
	ch <- prometheus.MustNewConstMetric(c.memBytes, prometheus.GaugeValue, float64(v.Total), "total")
	ch <- prometheus.MustNewConstMetric(c.memBytes, prometheus.GaugeValue, float64(v.Used), "used")
	ch <- prometheus.MustNewConstMetric(c.memBytes, prometheus.GaugeValue, float64(v.Free), "free")
	ch <- prometheus.MustNewConstMetric(c.memBytes, prometheus.GaugeValue, float64(v.Buffers), "buffers")
	ch <- prometheus.MustNewConstMetric(c.memBytes, prometheus.GaugeValue, float64(v.Cached), "cached")
	ch <- prometheus.MustNewConstMetric(c.memBytes, prometheus.GaugeValue, float64(v.Available), "available")
}

func (c *SystemCollector) collectLoad(ch chan<- prometheus.Metric) {
	l, err := load.Avg()
	if err != nil {
		c.Printf("system: load.Avg failed: %v", err)
		return
	}
	ch <- prometheus.MustNewConstMetric(c.loadAvg, prometheus.GaugeValue, l.Load1, "1m")
	ch <- prometheus.MustNewConstMetric(c.loadAvg, prometheus.GaugeValue, l.Load5, "5m")
	ch <- prometheus.MustNewConstMetric(c.loadAvg, prometheus.GaugeValue, l.Load15, "15m")

	// context switches + procs (Linux /proc/stat; macOS returns error — skipped)
	if m, err := load.Misc(); err == nil {
		ch <- prometheus.MustNewConstMetric(c.ctxSwitches, prometheus.CounterValue, float64(m.Ctxt))
		ch <- prometheus.MustNewConstMetric(c.procsState, prometheus.GaugeValue, float64(m.ProcsRunning), "running")
		ch <- prometheus.MustNewConstMetric(c.procsState, prometheus.GaugeValue, float64(m.ProcsBlocked), "blocked")
	}
}

func (c *SystemCollector) collectSwap(ch chan<- prometheus.Metric) {
	s, err := mem.SwapMemory()
	if err != nil {
		c.Printf("system: SwapMemory failed: %v", err)
		return
	}
	ch <- prometheus.MustNewConstMetric(c.swapBytes, prometheus.GaugeValue, float64(s.Total), "total")
	ch <- prometheus.MustNewConstMetric(c.swapBytes, prometheus.GaugeValue, float64(s.Used), "used")
	ch <- prometheus.MustNewConstMetric(c.swapBytes, prometheus.GaugeValue, float64(s.Free), "free")
	ch <- prometheus.MustNewConstMetric(c.swapIO, prometheus.CounterValue, float64(s.Sin), "in")
	ch <- prometheus.MustNewConstMetric(c.swapIO, prometheus.CounterValue, float64(s.Sout), "out")
}

func (c *SystemCollector) collectHost(ch chan<- prometheus.Metric) {
	u, err := host.Uptime()
	if err == nil {
		ch <- prometheus.MustNewConstMetric(c.uptime, prometheus.GaugeValue, float64(u))
	}

	if c.cachedBootTime > 0 {
		ch <- prometheus.MustNewConstMetric(c.bootTime, prometheus.GaugeValue, c.cachedBootTime)
	}

	if c.cachedHostInfo != nil {
		ch <- prometheus.MustNewConstMetric(c.hostInfo, prometheus.GaugeValue, 1,
			c.cachedHostInfo.Hostname, c.cachedHostInfo.OS, c.cachedHostInfo.Platform,
			c.cachedHostInfo.PlatformVersion, c.cachedHostInfo.KernelVersion, c.cachedHostInfo.KernelArch)
	}
}
