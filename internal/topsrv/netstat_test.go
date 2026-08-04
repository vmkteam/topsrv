package topsrv

import (
	"syscall"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	psnet "github.com/shirou/gopsutil/v4/net"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vmkteam/embedlog"
)

func TestNetstatCollector(t *testing.T) {
	c := NewNetstatCollector(embedlog.Logger{})
	assert.Equal(t, "netstat", c.Name())

	n := collectAndLint(t, c)
	t.Logf("netstat collector returned %d metric families", n)
}

func TestNetstatCollectorTCPConnections(t *testing.T) {
	reg := prometheus.NewRegistry()
	reg.MustRegister(NewNetstatCollector(embedlog.Logger{}))

	mfs, err := reg.Gather()
	require.NoError(t, err)

	for _, mf := range mfs {
		if mf.GetName() != "topsrv_netstat_tcp_connections" {
			continue
		}

		// Check direction labels: inbound/outbound + remote_scope present.
		directions := map[string]bool{}
		states := map[string]bool{}
		remoteScopes := map[string]bool{}
		for _, m := range mf.GetMetric() {
			for _, l := range m.GetLabel() {
				switch l.GetName() {
				case "direction":
					directions[l.GetValue()] = true
				case "state":
					states[l.GetValue()] = true
				case "remote_scope":
					remoteScopes[l.GetValue()] = true
				}
			}
		}

		// At least LISTEN should be present on any system; LISTEN ⇒ remote_scope=none.
		assert.True(t, states["LISTEN"], "missing TCP state: LISTEN")
		assert.True(t, directions["inbound"], "missing direction: inbound")
		assert.True(t, remoteScopes["none"], "LISTEN sockets must carry remote_scope=none")
		t.Logf("TCP states: %v, directions: %v, remote_scope: %v", states, directions, remoteScopes)
		return
	}
	t.Log("topsrv_netstat_tcp_connections not found (may require elevated permissions)")
}

func TestNetstatCollectorProtoCounters(t *testing.T) {
	reg := prometheus.NewRegistry()
	reg.MustRegister(NewNetstatCollector(embedlog.Logger{}))

	mfs, err := reg.Gather()
	require.NoError(t, err)

	names := map[string]bool{}
	for _, mf := range mfs {
		names[mf.GetName()] = true
	}

	// Proto counters may not be available on macOS.
	if names["topsrv_netstat_tcp_retransmits_total"] {
		requireMetric(t, reg, "topsrv_netstat_tcp_retransmits_total")
		requireMetric(t, reg, "topsrv_netstat_tcp_in_errs_total")
		requireMetric(t, reg, "topsrv_netstat_tcp_out_rsts_total")
		// Denominators live in the same Tcp: line of /proc/net/snmp as RetransSegs,
		// so a host reporting retransmits must report these too. An alert dividing
		// by a missing out_segs silently drops the series instead of firing.
		requireMetric(t, reg, "topsrv_netstat_tcp_in_segs_total")
		requireMetric(t, reg, "topsrv_netstat_tcp_out_segs_total")
		t.Log("protocol counters present")
	} else {
		t.Log("protocol counters not available on this system, skipping")
	}
}

func TestNetstatCollectorConnectionsByPort(t *testing.T) {
	reg := prometheus.NewRegistry()
	reg.MustRegister(NewNetstatCollector(embedlog.Logger{}))

	mfs, err := reg.Gather()
	require.NoError(t, err)

	for _, mf := range mfs {
		if mf.GetName() != "topsrv_netstat_tcp_connections_by_port" {
			continue
		}
		require.NotEmpty(t, mf.GetMetric())

		// Check port label exists.
		labels := mf.GetMetric()[0].GetLabel()
		labelNames := make([]string, len(labels))
		for i, l := range labels {
			labelNames[i] = l.GetName()
		}
		assert.Contains(t, labelNames, "port")
		return
	}
	t.Log("topsrv_netstat_tcp_connections_by_port not found (may require elevated permissions)")
}

func TestClassifyAddr(t *testing.T) {
	cases := []struct {
		ip         string
		wantFamily string
		wantScope  string
	}{
		// Loopback: 127.0.0.0/8 and ::1.
		{"127.0.0.1", familyIPv4, scopeLoopback},
		{"127.10.20.30", familyIPv4, scopeLoopback},
		{"::1", familyIPv6, scopeLoopback},

		// Private: RFC1918 IPv4.
		{"10.0.0.5", familyIPv4, scopePrivate},
		{"10.255.255.254", familyIPv4, scopePrivate},
		{"172.16.0.1", familyIPv4, scopePrivate},
		{"172.31.255.254", familyIPv4, scopePrivate},
		{"192.168.0.1", familyIPv4, scopePrivate},
		{"192.168.255.254", familyIPv4, scopePrivate},
		// Just outside RFC1918 → public.
		{"172.32.0.1", familyIPv4, scopePublic},
		{"172.15.255.254", familyIPv4, scopePublic},

		// Private: link-local IPv4 (169.254.0.0/16) and IPv6 (fe80::/10).
		{"169.254.1.1", familyIPv4, scopePrivate},
		{"fe80::1", familyIPv6, scopePrivate},

		// Private: ULA (fc00::/7).
		{"fc00::1", familyIPv6, scopePrivate},
		{"fd12:3456:789a::1", familyIPv6, scopePrivate},

		// Private: CGNAT (RFC6598, 100.64.0.0/10) — net.IP.IsPrivate misses it.
		{"100.64.0.1", familyIPv4, scopePrivate},
		{"100.127.255.254", familyIPv4, scopePrivate},
		// Just outside CGNAT → public.
		{"100.63.255.254", familyIPv4, scopePublic},
		{"100.128.0.1", familyIPv4, scopePublic},

		// Public: routable IPv4/IPv6 + the 0.0.0.0/:: wildcards (worst case).
		{"0.0.0.0", familyIPv4, scopePublic},
		{"::", familyIPv6, scopePublic},
		{"203.0.113.5", familyIPv4, scopePublic},
		{"8.8.8.8", familyIPv4, scopePublic},
		{"2001:db8::1", familyIPv6, scopePublic},

		// Unparseable → worst-case public so operator notices; family defaults to ipv4.
		{"", familyIPv4, scopePublic},
		{"garbage", familyIPv4, scopePublic},
	}
	for _, tc := range cases {
		family, scope := classifyAddr(tc.ip)
		assert.Equal(t, tc.wantFamily, family, "classifyAddr(%q) family", tc.ip)
		assert.Equal(t, tc.wantScope, scope, "classifyAddr(%q) scope", tc.ip)
	}
}

// TestResolveProcNamePIDZero — PID 0 is what the kernel returns for sockets
// hidden by ACL (non-root scraping other users' sockets). Resolver must
// short-circuit without calling psproc.NewProcess and must NOT pollute the
// cache so other callers' PID 0 lookups stay just as cheap.
func TestResolveProcNamePIDZero(t *testing.T) {
	c := &NetstatCollector{}
	cache := make(map[int32]string)

	got := c.resolveProcName(0, cache)
	assert.Empty(t, got)
	assert.NotContains(t, cache, int32(0), "cache must not be populated for PID=0 path")
}

// TestResolveProcNameMissingPID — a PID that disappeared between Connections()
// returning and our lookup (process exit race) must yield "" and negatively
// cache so a second listen socket from the same vanished PID doesn't repeat
// the failing psproc.NewProcess call.
func TestResolveProcNameMissingPID(t *testing.T) {
	c := &NetstatCollector{}
	cache := make(map[int32]string)
	const missing int32 = 2147483646 // unlikely to exist; PID_MAX is normally 2^22

	got := c.resolveProcName(missing, cache)
	assert.Empty(t, got)
	cached, ok := cache[missing]
	assert.True(t, ok, "missing PID must be negatively cached")
	assert.Empty(t, cached)
}

// BenchmarkNetstatCollect measures the per-scrape cost of the full netstat
// collector against the host's real socket table. Useful for spotting
// regressions after we added process-name resolution per LISTEN socket.
func BenchmarkNetstatCollect(b *testing.B) {
	c := NewNetstatCollector(embedlog.Logger{})
	b.ResetTimer()
	for range b.N {
		ch := make(chan prometheus.Metric, 4096)
		done := make(chan struct{})
		go func() {
			for range ch {
			}
			close(done)
		}()
		c.Collect(ch)
		close(ch)
		<-done
	}
}

// BenchmarkNetstatConnectionsOnly isolates the gopsutil Connections call so
// we can tell the dominant cost (kernel socket-table walk) from our own
// PID-name resolution work.
func BenchmarkNetstatConnectionsOnly(b *testing.B) {
	for range b.N {
		_, _ = psnet.Connections("tcp")
	}
}

// BenchmarkResolveProcName measures the per-PID process-name lookup cost,
// covering both the cold lookup and the warm cache hit.
func BenchmarkResolveProcName(b *testing.B) {
	c := &NetstatCollector{}
	// Use the current test process PID — guaranteed to exist for the run.
	pid := int32(syscall.Getpid())
	cache := make(map[int32]string, 1)

	b.Run("cold", func(b *testing.B) {
		for range b.N {
			delete(cache, pid)
			_ = c.resolveProcName(pid, cache)
		}
	})
	b.Run("cached", func(b *testing.B) {
		_ = c.resolveProcName(pid, cache) // warm
		for range b.N {
			_ = c.resolveProcName(pid, cache)
		}
	})
}

// TestNetstatCollectorListenPorts verifies the new metric is registered and
// emits at least one series — every Linux/macOS host has SOMETHING listening
// (sshd, mDNS, etc), and the metric must label by port/family/scope/process.
func TestNetstatCollectorListenPorts(t *testing.T) {
	reg := prometheus.NewRegistry()
	reg.MustRegister(NewNetstatCollector(embedlog.Logger{}))

	mfs, err := reg.Gather()
	require.NoError(t, err)

	for _, mf := range mfs {
		if mf.GetName() != "topsrv_netstat_listening_ports" {
			continue
		}
		require.NotEmpty(t, mf.GetMetric(), "host must have at least one listening socket")

		// Verify the full label set is present on every series.
		want := map[string]bool{"proto": true, "port": true, "family": true, "scope": true, "process": true}
		for _, m := range mf.GetMetric() {
			got := make(map[string]bool, len(m.GetLabel()))
			for _, l := range m.GetLabel() {
				got[l.GetName()] = true
				switch l.GetName() {
				case "proto":
					assert.Contains(t, []string{protoTCP, protoUDP}, l.GetValue())
				case "family":
					assert.Contains(t, []string{familyIPv4, familyIPv6}, l.GetValue())
				case "scope":
					assert.Contains(t, []string{scopeLoopback, scopePrivate, scopePublic}, l.GetValue())
				}
			}
			for k := range want {
				assert.True(t, got[k], "missing label %q on listening_ports series", k)
			}
			// Value must be 1 — it's a presence marker, not a count.
			assert.InDelta(t, 1.0, m.GetGauge().GetValue(), 1e-9)
		}
		return
	}
	t.Log("topsrv_netstat_listening_ports not found (may require elevated permissions)")
}
