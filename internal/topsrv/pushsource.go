package topsrv

import (
	"cmp"
	"net"
	"net/http/httptrace"
	"net/url"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// pushSourceInterval is how often the source address towards the push
// endpoint is looked up again; a failed send looks it up at once.
const pushSourceInterval = 5 * time.Minute

// pushSourceDialTimeout bounds the lookup, name resolution included: it
// runs on the push loop, and a failed send is when DNS may be down too.
const pushSourceDialTimeout = 2 * time.Second

// pushSource is the local address the host reaches the push endpoint from.
// A host that stops pushing is diagnosed by it: replies to one of its
// addresses may be lost on the way while another address works, and the
// first address of an interface is often a floating IP, not the source.
type pushSource struct {
	target  string // host:port of the push endpoint; "" when it does not parse
	desc    *prometheus.Desc
	now     func() time.Time
	dial    func(network, address string) (net.Conn, error)
	ifaceOf func(net.IP) string

	mu        sync.Mutex
	address   string
	iface     string
	checkedAt time.Time
	// observed is the ip:port the HTTP transport last connected to, or tried
	// to: with happy eyeballs it may be IPv4 while DNS lists IPv6 first.
	observed string
}

func newPushSource(endpoint string) *pushSource {
	s := &pushSource{
		desc: prometheus.NewDesc("topsrv_push_source_info",
			"Local address and interface the host reaches the push endpoint from.", []string{"address", labelInterface}, nil),
		now:     time.Now,
		dial:    (&net.Dialer{Timeout: pushSourceDialTimeout}).Dial,
		ifaceOf: interfaceOf,
	}
	if u, err := url.Parse(endpoint); err == nil && u.Hostname() != "" {
		port := u.Port()
		switch {
		case port != "":
		case u.Scheme == "http":
			port = "80"
		case u.Scheme == "https":
			port = "443"
		}
		if port != "" {
			s.target = net.JoinHostPort(u.Hostname(), port)
		}
	}
	return s
}

// trace records where the pusher's connections go: the address it dials
// (also when the dial fails — the case to diagnose) and the one it got.
func (s *pushSource) trace() *httptrace.ClientTrace {
	return &httptrace.ClientTrace{
		ConnectStart: func(_, addr string) { s.observe(addr) },
		GotConn: func(info httptrace.GotConnInfo) {
			if info.Conn != nil {
				s.observe(info.Conn.RemoteAddr().String())
			}
		},
	}
}

func (s *pushSource) observe(addr string) {
	s.mu.Lock()
	s.observed = addr
	s.mu.Unlock()
}

// current returns the source address, looked up again when older than
// pushSourceInterval or when force is set. A UDP "connection" sends no
// packet: the kernel only picks the route and the source address. The
// lookup runs outside the lock, so /metrics never waits on DNS; the
// interface is looked up only when the address changes.
func (s *pushSource) current(force bool) string {
	s.mu.Lock()
	address, iface := s.address, s.iface
	target := cmp.Or(s.observed, s.target) // the transport's IP: no DNS, and the family it really uses
	due := target != "" && (force || s.now().Sub(s.checkedAt) >= pushSourceInterval)
	if due {
		s.checkedAt = s.now()
	}
	s.mu.Unlock()
	if !due {
		return address
	}
	ip := s.lookup(target)
	switch {
	case ip == nil:
		address, iface = "", ""
	case ip.String() != address:
		address, iface = ip.String(), s.ifaceOf(ip)
	}
	s.mu.Lock()
	s.address, s.iface = address, iface
	s.mu.Unlock()
	return address
}

func (s *pushSource) lookup(target string) net.IP {
	conn, err := s.dial("udp", target)
	if err != nil {
		return nil
	}
	defer conn.Close()
	if la, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		return la.IP
	}
	return nil
}

// interfaceOf names the interface that holds ip.
func interfaceOf(ip net.IP) string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, ifc := range ifaces {
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP.Equal(ip) {
				return ifc.Name
			}
		}
	}
	return ""
}

func (s *pushSource) Describe(ch chan<- *prometheus.Desc) { ch <- s.desc }

func (s *pushSource) Collect(ch chan<- prometheus.Metric) {
	s.mu.Lock()
	address, iface := s.address, s.iface
	s.mu.Unlock()
	if address != "" {
		ch <- prometheus.MustNewConstMetric(s.desc, prometheus.GaugeValue, 1, address, iface)
	}
}
