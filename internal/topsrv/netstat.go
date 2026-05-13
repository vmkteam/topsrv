package topsrv

import (
	"context"
	"net"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
	psnet "github.com/shirou/gopsutil/v4/net"
	psproc "github.com/shirou/gopsutil/v4/process"
	"github.com/vmkteam/embedlog"
)

// NetstatCollector collects TCP/UDP/IP protocol metrics and TCP connections.
type NetstatCollector struct {
	embedlog.Logger

	tcpConns       *prometheus.Desc
	tcpConnsByPort *prometheus.Desc
	listenPorts    *prometheus.Desc

	// Protocol counters from /proc/net/snmp (Linux) or netstat -s (macOS).
	tcpRetrans        *prometheus.Desc
	tcpInErrs         *prometheus.Desc
	tcpOutRsts        *prometheus.Desc
	udpNoPorts        *prometheus.Desc
	udpInErrors       *prometheus.Desc
	udpSndbufErrors   *prometheus.Desc
	ipInUnknownProtos *prometheus.Desc
}

func NewNetstatCollector(logger embedlog.Logger) *NetstatCollector {
	return &NetstatCollector{
		Logger:            logger,
		tcpConns:          prometheus.NewDesc("topsrv_netstat_tcp_connections", "TCP connections by state and direction.", []string{"state", "direction"}, nil),
		tcpConnsByPort:    prometheus.NewDesc("topsrv_netstat_tcp_connections_by_port", "TCP connections per listen port.", []string{"port"}, nil),
		listenPorts:       prometheus.NewDesc("topsrv_netstat_listening_ports", "Active TCP listen sockets. value=1 per (port, family, scope, process) tuple. scope=loopback bound only to 127.0.0.0/8 or ::1; scope=private bound to an RFC1918/ULA/link-local address (reachable only on the private network); scope=public bound to a routable address or to the 0.0.0.0/:: wildcard (potentially reachable from anywhere). process is the owning binary name (empty when the PID is hidden by kernel ACL — root needed on Linux to read /proc/<pid>/comm of other users).", []string{"port", "family", "scope", "process"}, nil),
		tcpRetrans:        prometheus.NewDesc("topsrv_netstat_tcp_retransmits_total", "Total TCP retransmitted segments.", nil, nil),
		tcpInErrs:         prometheus.NewDesc("topsrv_netstat_tcp_in_errs_total", "Total TCP segments received in error.", nil, nil),
		tcpOutRsts:        prometheus.NewDesc("topsrv_netstat_tcp_out_rsts_total", "Total TCP segments sent with RST.", nil, nil),
		udpNoPorts:        prometheus.NewDesc("topsrv_netstat_udp_no_ports_total", "Total UDP datagrams to unknown port.", nil, nil),
		udpInErrors:       prometheus.NewDesc("topsrv_netstat_udp_in_errors_total", "Total UDP receive errors.", nil, nil),
		udpSndbufErrors:   prometheus.NewDesc("topsrv_netstat_udp_sndbuf_errors_total", "Total UDP send buffer errors.", nil, nil),
		ipInUnknownProtos: prometheus.NewDesc("topsrv_netstat_ip_unknown_protos_total", "Total IP datagrams with unknown protocol.", nil, nil),
	}
}

var _ Collector = (*NetstatCollector)(nil)

func (c *NetstatCollector) Name() string { return "netstat" }

func (c *NetstatCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.tcpConns
	ch <- c.tcpConnsByPort
	ch <- c.listenPorts
	ch <- c.tcpRetrans
	ch <- c.tcpInErrs
	ch <- c.tcpOutRsts
	ch <- c.udpNoPorts
	ch <- c.udpInErrors
	ch <- c.udpSndbufErrors
	ch <- c.ipInUnknownProtos
}

func (c *NetstatCollector) Collect(ch chan<- prometheus.Metric) {
	c.collectTCP(ch)
	c.collectProtoCounters(ch)
}

const (
	tcpStateListen = "LISTEN"

	familyIPv4 = "ipv4"
	familyIPv6 = "ipv6"

	scopeLoopback = "loopback" // 127.0.0.0/8 or ::1 — host-only
	scopePrivate  = "private"  // RFC1918, RFC4193 ULA, RFC6598 CGNAT, link-local
	scopePublic   = "public"   // routable internet IP, or wildcard (0.0.0.0 / ::) — treat as worst case

	// maxListenSeries caps how many distinct LISTEN tuples we emit per
	// scrape. Realistic hosts sit at 10-50; the cap exists so a misbehaving
	// (or compromised) box with thousands of listening sockets cannot blow
	// up Prometheus cardinality budgets.
	maxListenSeries = 256
)

// listenKey is the label-tuple identity of a LISTEN socket. Two sockets with
// the same port but different bind families (e.g. 0.0.0.0:80 and [::]:80)
// emit two distinct series so dashboards see them both.
type listenKey struct {
	port    uint32
	family  string // familyIPv4 | familyIPv6
	scope   string // scopeLoopback | scopePrivate | scopePublic
	process string // owning binary name; "" if PID resolution failed
}

func (c *NetstatCollector) collectTCP(ch chan<- prometheus.Metric) {
	conns, err := psnet.Connections("tcp")
	if err != nil {
		c.Print(context.Background(), "netstat: Connections failed", "error", err)
		return
	}

	// Find listen ports and capture each LISTEN socket's identity for the
	// listening_ports metric.
	listenPorts := make(map[uint32]bool, 32)
	listenSet := make(map[listenKey]struct{}, 32)
	procCache := make(map[int32]string, 32)
	var truncated int
	for _, conn := range conns {
		if conn.Status != tcpStateListen {
			continue
		}
		listenPorts[conn.Laddr.Port] = true
		if len(listenSet) >= maxListenSeries {
			truncated++
			continue
		}
		family, scope := classifyAddr(conn.Laddr.IP)
		listenSet[listenKey{
			port:    conn.Laddr.Port,
			family:  family,
			scope:   scope,
			process: c.resolveProcName(conn.Pid, procCache),
		}] = struct{}{}
	}
	if truncated > 0 {
		c.Print(context.Background(), "netstat: listening_ports truncated",
			"emitted", len(listenSet), "dropped", truncated, "cap", maxListenSeries)
	}

	// Count by state + direction.
	type key struct{ state, direction string }
	stateCounts := make(map[key]int, 20) // ~10 TCP states × 2 directions
	portCounts := make(map[uint32]int, len(listenPorts))

	for _, conn := range conns {
		direction := "outbound"
		if conn.Status == tcpStateListen || listenPorts[conn.Laddr.Port] {
			direction = "inbound"
		}
		stateCounts[key{conn.Status, direction}]++

		// Per-port: count non-LISTEN inbound connections.
		if conn.Status != tcpStateListen && listenPorts[conn.Laddr.Port] {
			portCounts[conn.Laddr.Port]++
		}
	}

	for k, count := range stateCounts {
		ch <- prometheus.MustNewConstMetric(c.tcpConns, prometheus.GaugeValue, float64(count), k.state, k.direction)
	}
	for port, count := range portCounts {
		ch <- prometheus.MustNewConstMetric(c.tcpConnsByPort, prometheus.GaugeValue, float64(count), strconv.FormatUint(uint64(port), 10))
	}
	for k := range listenSet {
		ch <- prometheus.MustNewConstMetric(c.listenPorts, prometheus.GaugeValue, 1,
			strconv.FormatUint(uint64(k.port), 10), k.family, k.scope, k.process)
	}
}

// classifyAddr extracts both the family and reachability scope of a bind
// address in one net.ParseIP pass.
//
// family: ipv4 / ipv6 (empty or unparseable → ipv4, the historical default
// for ambiguous gopsutil rows).
//
// scope:
//   - loopback: 127.0.0.0/8 or ::1 — host-only, never reachable off-box.
//   - private:  RFC1918 (10/8, 172.16/12, 192.168/16), RFC4193 ULA
//     (fc00::/7), RFC6598 CGNAT (100.64/10), and link-local
//     (169.254/16, fe80::/10). Reachable only on the private/carrier
//     network the host sits on.
//   - public:   any routable address, plus 0.0.0.0 / :: wildcards (treated
//     as worst case so a missing public interface doesn't hide an exposed
//     listener), plus unparseable garbage.
func classifyAddr(ip string) (family, scope string) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return familyIPv4, scopePublic
	}
	ip4 := parsed.To4()
	if ip4 != nil {
		family = familyIPv4
	} else {
		family = familyIPv6
	}
	switch {
	case parsed.IsLoopback():
		scope = scopeLoopback
	case parsed.IsPrivate(), parsed.IsLinkLocalUnicast(), isCGNAT(ip4):
		scope = scopePrivate
	default:
		scope = scopePublic
	}
	return family, scope
}

// isCGNAT reports whether the address falls inside RFC6598 100.64.0.0/10 —
// the Carrier-Grade NAT range Go's net.IP.IsPrivate doesn't cover.
func isCGNAT(ip4 net.IP) bool {
	return ip4 != nil && ip4[0] == 100 && ip4[1] >= 64 && ip4[1] < 128
}

// resolveProcName maps a PID to its process name, cached per scrape so two
// listen sockets owned by the same process (IPv4 + IPv6) only cost one
// /proc lookup. Empty string when the PID is 0 (kernel hid it — typical
// for non-root scrapes of other users' sockets) or when the process exited
// between Connections() returning and our lookup.
func (c *NetstatCollector) resolveProcName(pid int32, cache map[int32]string) string {
	if pid == 0 {
		return ""
	}
	if name, ok := cache[pid]; ok {
		return name
	}
	p, err := psproc.NewProcess(pid)
	if err != nil {
		cache[pid] = ""
		return ""
	}
	name, err := p.Name()
	if err != nil {
		name = ""
	}
	cache[pid] = name
	return name
}

func (c *NetstatCollector) collectProtoCounters(ch chan<- prometheus.Metric) {
	counters, err := psnet.ProtoCounters([]string{"tcp", "udp", "ip"})
	if err != nil {
		c.Print(context.Background(), "netstat: ProtoCounters failed", "error", err)
		return
	}
	for _, proto := range counters {
		switch proto.Protocol {
		case "tcp":
			c.emitCounter(ch, c.tcpRetrans, proto.Stats, "RetransSegs")
			c.emitCounter(ch, c.tcpInErrs, proto.Stats, "InErrs")
			c.emitCounter(ch, c.tcpOutRsts, proto.Stats, "OutRsts")
		case "udp":
			c.emitCounter(ch, c.udpNoPorts, proto.Stats, "NoPorts")
			c.emitCounter(ch, c.udpInErrors, proto.Stats, "InErrors")
			c.emitCounter(ch, c.udpSndbufErrors, proto.Stats, "SndbufErrors")
		case "ip":
			c.emitCounter(ch, c.ipInUnknownProtos, proto.Stats, "InUnknownProtos")
		}
	}
}

func (c *NetstatCollector) emitCounter(ch chan<- prometheus.Metric, desc *prometheus.Desc, stats map[string]int64, key string) {
	if v, ok := stats[key]; ok {
		ch <- prometheus.MustNewConstMetric(desc, prometheus.CounterValue, float64(v))
	}
}
