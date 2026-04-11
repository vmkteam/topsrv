package topsrv

import (
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/shirou/gopsutil/v4/net"
	"github.com/vmkteam/embedlog"
)

// NetstatCollector collects TCP/UDP/IP protocol metrics and TCP connections.
type NetstatCollector struct {
	embedlog.Logger

	tcpConns       *prometheus.Desc
	tcpConnsByPort *prometheus.Desc

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

const tcpStateListen = "LISTEN"

func (c *NetstatCollector) collectTCP(ch chan<- prometheus.Metric) {
	conns, err := net.Connections("tcp")
	if err != nil {
		c.Printf("netstat: Connections failed: %v", err)
		return
	}

	// Find listen ports.
	listenPorts := make(map[uint32]bool, 32)
	for _, conn := range conns {
		if conn.Status == tcpStateListen {
			listenPorts[conn.Laddr.Port] = true
		}
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
}

func (c *NetstatCollector) collectProtoCounters(ch chan<- prometheus.Metric) {
	counters, err := net.ProtoCounters([]string{"tcp", "udp", "ip"})
	if err != nil {
		c.Printf("netstat: ProtoCounters failed: %v", err)
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
