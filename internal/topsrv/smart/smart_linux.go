//go:build linux

package smart

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	sm "github.com/anatol/smart.go"
	"github.com/prometheus/client_golang/prometheus"
)

// criticalAttrIDs lists ATA SMART attribute IDs worth monitoring.
// "Big 5" HDD/SSD degradation + SSD wear indicators.
var criticalAttrIDs = map[uint8]bool{
	5: true, 187: true, 188: true, 197: true, 198: true, // Big 5
	171: true, 172: true, 173: true, 177: true, 202: true, 233: true, // SSD wear
}

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
	ctx := context.Background()
	if len(devices) == 0 {
		c.Print(ctx, "smart: no block devices found")
		return
	}

	var metrics []prometheus.Metric
	scanned := 0

	for _, name := range devices {
		m, err := c.collectFromDevice(ctx, name)
		if err != nil {
			c.Error(ctx, "smart: device scan failed", "device", name, "error", err)
			continue
		}
		metrics = append(metrics, m...)
		scanned++
	}

	if !c.scanned {
		c.Print(ctx, "smart: initial scan complete", "scanned", scanned, "total", len(devices), "metrics", len(metrics))
	}

	c.mu.Lock()
	c.cache = metrics
	c.scanned = true
	c.mu.Unlock()
}

func (c *Collector) collectFromDevice(ctx context.Context, name string) ([]prometheus.Metric, error) {
	dev, err := sm.Open("/dev/" + name)
	if err != nil {
		return nil, err
	}
	defer dev.Close()

	var metrics []prometheus.Metric

	// Common metrics from generic attributes.
	ga, gaErr := dev.ReadGenericAttributes()
	if gaErr != nil && !c.scanned {
		c.Error(ctx, "smart: ReadGenericAttributes failed", "device", name, "error", gaErr)
	}
	if gaErr == nil {
		if ga.Temperature > 0 {
			metrics = append(metrics, prometheus.MustNewConstMetric(c.temperature, prometheus.GaugeValue, float64(ga.Temperature), name))
		}
		if ga.PowerOnHours > 0 {
			metrics = append(metrics, prometheus.MustNewConstMetric(c.powerOnHours, prometheus.GaugeValue, float64(ga.PowerOnHours), name))
		}
		if ga.Written > 0 {
			metrics = append(metrics, prometheus.MustNewConstMetric(c.bytesWritten, prometheus.GaugeValue, float64(ga.Written), name))
		}
	}

	// Type-specific metrics.
	switch d := dev.(type) {
	case *sm.SataDevice:
		if !c.scanned {
			c.Print(ctx, "smart: detected device", "device", name, "type", "sata")
		}
		metrics = append(metrics, c.collectSata(name, d)...)
	case *sm.NVMeDevice:
		if !c.scanned {
			c.Print(ctx, "smart: detected device", "device", name, "type", "nvme")
		}
		metrics = append(metrics, c.collectNVMe(name, d)...)
	case *sm.ScsiDevice:
		if !c.scanned {
			c.Print(ctx, "smart: detected device", "device", name, "type", "scsi")
		}
		metrics = append(metrics, c.collectScsi(name, d)...)
	default:
		c.Print(ctx, "smart: unsupported device type, skipping", "device", name, "type", dev)
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
		if !criticalAttrIDs[attr.Id] {
			continue
		}
		idStr := strconv.Itoa(int(attr.Id))
		attrName := attr.Name
		if attrName == "" {
			attrName = "attr_" + idStr
		}
		metrics = append(metrics,
			prometheus.MustNewConstMetric(c.attrRawValue, prometheus.GaugeValue, float64(attr.ValueRaw), device, idStr, attrName),
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

func (c *Collector) collectScsi(device string, dev *sm.ScsiDevice) []prometheus.Metric {
	var metrics []prometheus.Metric

	var model, serial, firmware string
	if inq, err := dev.Inquiry(); err == nil {
		model = strings.TrimSpace(string(inq.VendorIdent[:]) + " " + string(inq.ProductIdent[:]))
		firmware = strings.TrimSpace(string(inq.ProductRev[:]))
	}
	if sn, err := dev.SerialNumber(); err == nil {
		serial = strings.TrimSpace(sn)
	}
	metrics = append(metrics, prometheus.MustNewConstMetric(c.deviceInfo, prometheus.GaugeValue, 1, device, "scsi", model, serial, firmware))
	metrics = append(metrics, prometheus.MustNewConstMetric(c.healthy, prometheus.GaugeValue, 1, device))

	return metrics
}
