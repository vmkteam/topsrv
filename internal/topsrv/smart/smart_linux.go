//go:build linux

package smart

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"

	sm "github.com/anatol/smart.go"
	"github.com/prometheus/client_golang/prometheus"
)

// skipBlockPrefixes lists /sys/block/ device prefixes to ignore (virtual, RAID, etc.).
var skipBlockPrefixes = [...]string{"loop", "dm-", "ram", "zram", "sr", "fd", "nbd", "md"}

// discoverBlockDevices returns names of physical block devices from /sys/block/.
func discoverBlockDevices() []string {
	entries, err := os.ReadDir("/sys/block")
	if err != nil {
		return nil
	}

	var devices []string
	for _, e := range entries {
		name := e.Name()

		skip := false
		for _, prefix := range skipBlockPrefixes {
			if strings.HasPrefix(name, prefix) {
				skip = true
				break
			}
		}
		if skip {
			continue
		}

		// Skip zero-size devices.
		data, err := os.ReadFile(filepath.Join("/sys/block", name, "size"))
		if err != nil || strings.TrimSpace(string(data)) == "0" {
			continue
		}

		devices = append(devices, name)
	}
	return devices
}

func (c *Collector) scan() {
	devices := discoverBlockDevices()

	var metrics []prometheus.Metric
	scanned := 0

	for _, name := range devices {
		m, err := c.collectFromDevice(name)
		if err != nil {
			continue
		}
		metrics = append(metrics, m...)
		scanned++
	}

	if scanned > 0 {
		c.Printf("smart: scanned %d devices, %d metrics", scanned, len(metrics))
	}

	c.mu.Lock()
	c.cache = metrics
	c.mu.Unlock()
}

func (c *Collector) collectFromDevice(name string) ([]prometheus.Metric, error) {
	dev, err := sm.Open("/dev/" + name)
	if err != nil {
		return nil, err
	}
	defer dev.Close()

	var metrics []prometheus.Metric

	// Common metrics from generic attributes.
	if ga, err := dev.ReadGenericAttributes(); err == nil {
		if ga.Temperature > 0 {
			metrics = append(metrics, prometheus.MustNewConstMetric(c.temperature, prometheus.GaugeValue, float64(ga.Temperature), name))
		}
		if ga.PowerOnHours > 0 {
			metrics = append(metrics, prometheus.MustNewConstMetric(c.powerOnHours, prometheus.GaugeValue, float64(ga.PowerOnHours), name))
		}
		if ga.PowerCycles > 0 {
			metrics = append(metrics, prometheus.MustNewConstMetric(c.powerCycles, prometheus.GaugeValue, float64(ga.PowerCycles), name))
		}
		if ga.Read > 0 {
			metrics = append(metrics, prometheus.MustNewConstMetric(c.bytesRead, prometheus.GaugeValue, float64(ga.Read), name))
		}
		if ga.Written > 0 {
			metrics = append(metrics, prometheus.MustNewConstMetric(c.bytesWritten, prometheus.GaugeValue, float64(ga.Written), name))
		}
	}

	// Type-specific metrics.
	switch d := dev.(type) {
	case *sm.SataDevice:
		metrics = append(metrics, c.collectSata(name, d)...)
	case *sm.NVMeDevice:
		metrics = append(metrics, c.collectNVMe(name, d)...)
	}

	return metrics, nil
}

func (c *Collector) collectSata(device string, dev *sm.SataDevice) []prometheus.Metric {
	var metrics []prometheus.Metric

	// Device info from ATA Identify.
	var model, serial, firmware string
	if id, err := dev.Identify(); err == nil {
		model = strings.TrimSpace(id.ModelNumber())
		serial = strings.TrimSpace(id.SerialNumber())
		firmware = strings.TrimSpace(id.FirmwareRevision())
	}
	metrics = append(metrics, prometheus.MustNewConstMetric(c.deviceInfo, prometheus.GaugeValue, 1, device, "sata", model, serial, firmware))

	// SMART attributes.
	page, err := dev.ReadSMARTData()
	if err != nil {
		metrics = append(metrics, prometheus.MustNewConstMetric(c.healthy, prometheus.GaugeValue, 1, device))
		return metrics
	}

	for _, attr := range page.Attrs {
		idStr := strconv.Itoa(int(attr.Id))
		attrName := attr.Name
		if attrName == "" {
			attrName = "attr_" + idStr
		}
		metrics = append(metrics,
			prometheus.MustNewConstMetric(c.attrValue, prometheus.GaugeValue, float64(attr.Current), device, idStr, attrName),
			prometheus.MustNewConstMetric(c.attrRawValue, prometheus.GaugeValue, float64(attr.ValueRaw), device, idStr, attrName),
			prometheus.MustNewConstMetric(c.attrWorst, prometheus.GaugeValue, float64(attr.Worst), device, idStr, attrName),
		)
	}

	// SATA healthy: default 1; users should alert on individual attributes (5, 187, 188, 197, 198).
	metrics = append(metrics, prometheus.MustNewConstMetric(c.healthy, prometheus.GaugeValue, 1, device))

	return metrics
}

func (c *Collector) collectNVMe(device string, dev *sm.NVMeDevice) []prometheus.Metric {
	var metrics []prometheus.Metric

	// Device info from NVMe Identify Controller.
	var model, serial, firmware string
	if id, _, err := dev.Identify(); err == nil {
		model = id.ModelNumber()
		serial = id.SerialNumber()
		firmware = id.FirmwareRev()
	}
	metrics = append(metrics, prometheus.MustNewConstMetric(c.deviceInfo, prometheus.GaugeValue, 1, device, "nvme", model, serial, firmware))

	// NVMe SMART log.
	log, err := dev.ReadSMART()
	if err != nil {
		metrics = append(metrics, prometheus.MustNewConstMetric(c.healthy, prometheus.GaugeValue, 1, device))
		return metrics
	}

	healthy := float64(1)
	if log.CritWarning != 0 {
		healthy = 0
	}

	metrics = append(metrics,
		prometheus.MustNewConstMetric(c.healthy, prometheus.GaugeValue, healthy, device),
		prometheus.MustNewConstMetric(c.nvmeCritWarn, prometheus.GaugeValue, float64(log.CritWarning), device),
		prometheus.MustNewConstMetric(c.nvmeAvailSpare, prometheus.GaugeValue, float64(log.AvailSpare), device),
		prometheus.MustNewConstMetric(c.nvmeSpareThresh, prometheus.GaugeValue, float64(log.SpareThresh), device),
		prometheus.MustNewConstMetric(c.nvmePercentUsed, prometheus.GaugeValue, float64(log.PercentUsed), device),
		prometheus.MustNewConstMetric(c.nvmeMediaErrors, prometheus.GaugeValue, float64(log.MediaErrors.Val[0]), device),
		prometheus.MustNewConstMetric(c.nvmeUnsafeShutdowns, prometheus.GaugeValue, float64(log.UnsafeShutdowns.Val[0]), device),
		prometheus.MustNewConstMetric(c.nvmeWarnTempTime, prometheus.GaugeValue, float64(log.WarningTempTime), device),
		prometheus.MustNewConstMetric(c.nvmeCritTempTime, prometheus.GaugeValue, float64(log.CritCompTime), device),
	)

	return metrics
}
