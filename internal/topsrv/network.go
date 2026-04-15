package topsrv

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/shirou/gopsutil/v4/net"
	"github.com/vmkteam/embedlog"
)

const mbpsToBytes = 1_000_000 / 8 // Mbit/s → bytes/s

// NetworkCollector collects network interface metrics (IO + metadata).
type NetworkCollector struct {
	embedlog.Logger

	netBytes   *prometheus.Desc
	netPackets *prometheus.Desc
	netErrors  *prometheus.Desc
	netDrops   *prometheus.Desc
	netSpeed   *prometheus.Desc
	ifaceInfo  *prometheus.Desc
}

func NewNetworkCollector(logger embedlog.Logger) *NetworkCollector {
	return &NetworkCollector{
		Logger:     logger,
		netBytes:   prometheus.NewDesc("topsrv_network_bytes_total", "Total bytes transferred.", []string{"interface", "direction"}, nil),
		netPackets: prometheus.NewDesc("topsrv_network_packets_total", "Total packets transferred.", []string{"interface", "direction"}, nil),
		netErrors:  prometheus.NewDesc("topsrv_network_errors_total", "Total network errors.", []string{"interface", "direction"}, nil),
		netDrops:   prometheus.NewDesc("topsrv_network_drops_total", "Total dropped packets.", []string{"interface", "direction"}, nil),
		netSpeed:   prometheus.NewDesc("topsrv_network_speed_bytes", "Network interface link speed in bytes per second.", []string{"interface"}, nil),
		ifaceInfo:  prometheus.NewDesc("topsrv_network_info", "Network interface information.", []string{"interface", "mac", "address", "mtu", "operstate"}, nil),
	}
}

var _ Collector = (*NetworkCollector)(nil)

func (c *NetworkCollector) Name() string { return "network" }

func (c *NetworkCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.netBytes
	ch <- c.netPackets
	ch <- c.netErrors
	ch <- c.netDrops
	ch <- c.netSpeed
	ch <- c.ifaceInfo
}

func (c *NetworkCollector) Collect(ch chan<- prometheus.Metric) {
	c.collectIO(ch)
	c.collectInterfaces(ch)
	c.collectSpeed(ch)
}

func (c *NetworkCollector) collectIO(ch chan<- prometheus.Metric) {
	counters, err := net.IOCounters(true)
	if err != nil {
		c.Printf("network: IOCounters failed: %v", err)
		return
	}
	for _, io := range counters {
		ch <- prometheus.MustNewConstMetric(c.netBytes, prometheus.CounterValue, float64(io.BytesRecv), io.Name, "rx")
		ch <- prometheus.MustNewConstMetric(c.netBytes, prometheus.CounterValue, float64(io.BytesSent), io.Name, "tx")
		ch <- prometheus.MustNewConstMetric(c.netPackets, prometheus.CounterValue, float64(io.PacketsRecv), io.Name, "rx")
		ch <- prometheus.MustNewConstMetric(c.netPackets, prometheus.CounterValue, float64(io.PacketsSent), io.Name, "tx")
		ch <- prometheus.MustNewConstMetric(c.netErrors, prometheus.CounterValue, float64(io.Errin), io.Name, "rx")
		ch <- prometheus.MustNewConstMetric(c.netErrors, prometheus.CounterValue, float64(io.Errout), io.Name, "tx")
		ch <- prometheus.MustNewConstMetric(c.netDrops, prometheus.CounterValue, float64(io.Dropin), io.Name, "rx")
		ch <- prometheus.MustNewConstMetric(c.netDrops, prometheus.CounterValue, float64(io.Dropout), io.Name, "tx")
	}
}

func (c *NetworkCollector) collectInterfaces(ch chan<- prometheus.Metric) {
	ifaces, err := net.Interfaces()
	if err != nil {
		c.Printf("network: Interfaces failed: %v", err)
		return
	}
	for _, iface := range ifaces {
		// first IPv4 address
		addr := ""
		for _, a := range iface.Addrs {
			if strings.Contains(a.Addr, ".") {
				addr = a.Addr
				break
			}
		}

		operstate := "down"
		for _, f := range iface.Flags {
			if f == "up" {
				operstate = "up"
				break
			}
		}

		ch <- prometheus.MustNewConstMetric(c.ifaceInfo, prometheus.GaugeValue, 1,
			iface.Name, iface.HardwareAddr, addr, strconv.Itoa(iface.MTU), operstate)
	}
}

// collectSpeed reads link speed from /sys/class/net/<iface>/speed for physical NICs (Linux only).
// Virtual interfaces (veth, bridge, loopback, etc.) are skipped — they report fake speed values.
// Physical NIC is detected by the presence of /sys/class/net/<iface>/device symlink (points to PCI device).
func (c *NetworkCollector) collectSpeed(ch chan<- prometheus.Metric) {
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return // non-Linux or no sysfs
	}

	for _, e := range entries {
		ifPath := filepath.Join("/sys/class/net", e.Name())

		// Only physical NICs have a "device" symlink to their PCI/USB bus device.
		if _, err := os.Stat(filepath.Join(ifPath, "device")); err != nil {
			continue
		}

		data, err := os.ReadFile(filepath.Join(ifPath, "speed"))
		if err != nil {
			continue
		}
		mbps, err := strconv.Atoi(strings.TrimSpace(string(data)))
		if err != nil || mbps <= 0 {
			continue // down or unknown (-1)
		}
		ch <- prometheus.MustNewConstMetric(c.netSpeed, prometheus.GaugeValue, float64(mbps)*float64(mbpsToBytes), e.Name())
	}
}
