package topsrv

import (
	"context"
	"encoding/hex"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
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
	addrInfo   *prometheus.Desc
}

func NewNetworkCollector(logger embedlog.Logger) *NetworkCollector {
	return &NetworkCollector{
		Logger:     logger,
		netBytes:   prometheus.NewDesc("topsrv_network_bytes_total", "Total bytes transferred.", []string{labelInterface, "direction"}, nil),
		netPackets: prometheus.NewDesc("topsrv_network_packets_total", "Total packets transferred.", []string{labelInterface, "direction"}, nil),
		netErrors:  prometheus.NewDesc("topsrv_network_errors_total", "Total network errors.", []string{labelInterface, "direction"}, nil),
		netDrops:   prometheus.NewDesc("topsrv_network_drops_total", "Total dropped packets.", []string{labelInterface, "direction"}, nil),
		netSpeed:   prometheus.NewDesc("topsrv_network_speed_bytes", "Network interface link speed in bytes per second.", []string{labelInterface}, nil),
		ifaceInfo:  prometheus.NewDesc("topsrv_network_info", "Network interface information.", []string{labelInterface, "mac", labelAddress, "mtu", "operstate"}, nil),
		addrInfo: prometheus.NewDesc("topsrv_network_address_info",
			"Addresses of a network interface, one series each: IPv4 and IPv6, link-local and temporary left out.",
			[]string{labelInterface, labelAddress, "family"}, nil),
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
	ch <- c.addrInfo
}

func (c *NetworkCollector) Collect(ch chan<- prometheus.Metric) {
	c.collectIO(ch)
	c.collectInterfaces(ch)
	c.collectSpeed(ch)
}

// Labels of the network metrics.
const (
	labelInterface = "interface"
	labelAddress   = "address"
)

func (c *NetworkCollector) collectIO(ch chan<- prometheus.Metric) {
	counters, err := net.IOCounters(true)
	if err != nil {
		c.Print(context.Background(), "network: IOCounters failed", "error", err)
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
		c.Print(context.Background(), "network: Interfaces failed", "error", err)
		return
	}
	transient := transientIPv6()
	for _, iface := range ifaces {
		// first IPv4 address: one series per interface, what the backend
		// reads; every address is in topsrv_network_address_info
		addr := ""
		for _, a := range iface.Addrs {
			if strings.Contains(a.Addr, ".") {
				addr = a.Addr
				break
			}
		}

		operstate := "down"
		if slices.Contains(iface.Flags, "up") {
			operstate = "up"
		}

		ch <- prometheus.MustNewConstMetric(c.ifaceInfo, prometheus.GaugeValue, 1,
			iface.Name, iface.HardwareAddr, addr, strconv.Itoa(iface.MTU), operstate)
		for _, a := range ifaceAddresses(iface.Addrs, transient) {
			family := "ipv4"
			if strings.Contains(a, ":") {
				family = "ipv6"
			}
			ch <- prometheus.MustNewConstMetric(c.addrInfo, prometheus.GaugeValue, 1, iface.Name, a, family)
		}
	}
}

// IPv6 address flags of /proc/net/if_inet6 (linux/if_addr.h): a privacy
// address changes daily, a deprecated one lingers for days — a new series
// each time.
const (
	ifaFTemporary  = 0x01
	ifaFDeprecated = 0x20
)

// transientIPv6 lists the temporary and deprecated IPv6 addresses; nil off
// Linux.
func transientIPv6() map[netip.Addr]bool {
	b, err := os.ReadFile("/proc/net/if_inet6")
	if err != nil {
		return nil
	}
	return parseIfInet6(b)
}

// parseIfInet6 reads "address ifindex prefixlen scope flags name" lines,
// the address as 32 hex digits.
func parseIfInet6(b []byte) map[netip.Addr]bool {
	out := map[netip.Addr]bool{}
	for line := range strings.SplitSeq(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 5 || len(f[0]) != 32 {
			continue
		}
		flags, err := strconv.ParseUint(f[4], 16, 32)
		raw, herr := hex.DecodeString(f[0])
		if err != nil || herr != nil || flags&(ifaFTemporary|ifaFDeprecated) == 0 {
			continue
		}
		out[netip.AddrFrom16([16]byte(raw))] = true
	}
	return out
}

// maxIfaceAddrs caps the addresses reported per interface: kube-ipvs0 of an
// IPVS node holds the ClusterIP of every Service.
const maxIfaceAddrs = 16

// ifaceAddresses lists the addresses of an interface as reported ("10.0.0.5/24"),
// IPv4 and IPv6, link-local and transient IPv6 left out, at most
// maxIfaceAddrs: the first address is often a floating IP and not where
// traffic goes from.
func ifaceAddresses(addrs []net.InterfaceAddr, transient map[netip.Addr]bool) []string {
	var out []string
	for _, a := range addrs {
		if len(out) == maxIfaceAddrs {
			break
		}
		if p, err := netip.ParsePrefix(a.Addr); err == nil && !p.Addr().IsLinkLocalUnicast() && !transient[p.Addr()] {
			out = append(out, a.Addr)
		}
	}
	return out
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
