package smart

import (
	"context"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/vmkteam/embedlog"
)

const defaultInterval = 5 * time.Minute

// Config configures S.M.A.R.T. disk monitoring.
type Config struct {
	Disabled bool   // set true to disable SMART collector
	Interval string // polling interval (default "5m")
}

// Collector collects S.M.A.R.T. disk health metrics.
// Devices are auto-discovered via /sys/block/ on Linux.
// S.M.A.R.T. data is read using direct ioctl (github.com/anatol/smart.go).
type Collector struct {
	embedlog.Logger

	interval time.Duration

	// common
	deviceInfo   *prometheus.Desc
	healthy      *prometheus.Desc
	temperature  *prometheus.Desc
	powerOnHours *prometheus.Desc
	bytesWritten *prometheus.Desc

	// ATA SMART attributes (critical only)
	attrRawValue *prometheus.Desc

	// NVMe
	nvmeCritWarn        *prometheus.Desc
	nvmeAvailSpare      *prometheus.Desc
	nvmeSpareThresh     *prometheus.Desc
	nvmePercentUsed     *prometheus.Desc
	nvmeMediaErrors     *prometheus.Desc
	nvmeUnsafeShutdowns *prometheus.Desc
	nvmeWarnTempTime    *prometheus.Desc
	nvmeCritTempTime    *prometheus.Desc

	mu      sync.Mutex
	cache   []prometheus.Metric
	scanned bool //nolint:unused // used in smart_linux.go (build-tagged)
}

// NewCollector creates a new S.M.A.R.T. collector.
func NewCollector(logger embedlog.Logger, interval string) *Collector {
	dur, err := time.ParseDuration(interval)
	if err != nil || dur < time.Second {
		dur = defaultInterval
	}

	return &Collector{
		Logger:   logger,
		interval: dur,

		deviceInfo:   prometheus.NewDesc("topsrv_smart_device_info", "S.M.A.R.T. device information.", []string{"device", "type", "model", "serial", "firmware"}, nil),
		healthy:      prometheus.NewDesc("topsrv_smart_device_healthy", "S.M.A.R.T. overall health: 1=healthy, 0=unhealthy.", []string{"device"}, nil),
		temperature:  prometheus.NewDesc("topsrv_smart_device_temperature_celsius", "Device temperature in Celsius.", []string{"device"}, nil),
		powerOnHours: prometheus.NewDesc("topsrv_smart_device_power_on_hours", "Total power-on hours.", []string{"device"}, nil),
		bytesWritten: prometheus.NewDesc("topsrv_smart_device_bytes_written_total", "Total bytes written to device.", []string{"device"}, nil),

		attrRawValue: prometheus.NewDesc("topsrv_smart_attr_raw_value", "ATA S.M.A.R.T. critical attribute raw value.", []string{"device", "id", "name"}, nil),

		nvmeCritWarn:        prometheus.NewDesc("topsrv_smart_nvme_critical_warning", "NVMe critical warning bitmask.", []string{"device"}, nil),
		nvmeAvailSpare:      prometheus.NewDesc("topsrv_smart_nvme_available_spare_percent", "NVMe available spare capacity percentage.", []string{"device"}, nil),
		nvmeSpareThresh:     prometheus.NewDesc("topsrv_smart_nvme_available_spare_threshold_percent", "NVMe available spare threshold percentage.", []string{"device"}, nil),
		nvmePercentUsed:     prometheus.NewDesc("topsrv_smart_nvme_percentage_used", "NVMe estimated percentage of life used (can exceed 100).", []string{"device"}, nil),
		nvmeMediaErrors:     prometheus.NewDesc("topsrv_smart_nvme_media_errors_total", "NVMe media and data integrity error count.", []string{"device"}, nil),
		nvmeUnsafeShutdowns: prometheus.NewDesc("topsrv_smart_nvme_unsafe_shutdowns_total", "NVMe unsafe shutdown count.", []string{"device"}, nil),
		nvmeWarnTempTime:    prometheus.NewDesc("topsrv_smart_nvme_warning_temp_time_minutes", "Total minutes above warning temperature threshold.", []string{"device"}, nil),
		nvmeCritTempTime:    prometheus.NewDesc("topsrv_smart_nvme_critical_temp_time_minutes", "Total minutes above critical temperature threshold.", []string{"device"}, nil),
	}
}

func (c *Collector) Name() string { return "smart" }

func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.deviceInfo
	ch <- c.healthy
	ch <- c.temperature
	ch <- c.powerOnHours
	ch <- c.bytesWritten
	ch <- c.attrRawValue
	ch <- c.nvmeCritWarn
	ch <- c.nvmeAvailSpare
	ch <- c.nvmeSpareThresh
	ch <- c.nvmePercentUsed
	ch <- c.nvmeMediaErrors
	ch <- c.nvmeUnsafeShutdowns
	ch <- c.nvmeWarnTempTime
	ch <- c.nvmeCritTempTime
}

func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, m := range c.cache {
		ch <- m
	}
}

// Run starts the background scan loop. Blocks until ctx is cancelled.
func (c *Collector) Run(ctx context.Context) {
	c.Printf("smart: started, interval=%s", c.interval)

	c.scan()

	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			c.Printf("smart: stopped")
			return
		case <-ticker.C:
			c.scan()
		}
	}
}
