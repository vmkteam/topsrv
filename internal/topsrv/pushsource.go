package topsrv

import (
	"net"
	"net/url"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// labelInterface is the interface label of the network metrics.
const labelInterface = "interface"

// pushSourceInterval is how often the source address towards the push
// endpoint is looked up again; a failed send looks it up at once.
const pushSourceInterval = 5 * time.Minute

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
}

func newPushSource(endpoint string) *pushSource {
	s := &pushSource{
		desc: prometheus.NewDesc("topsrv_push_source_info",
			"Local address and interface the host reaches the push endpoint from.", []string{"address", labelInterface}, nil),
		now:     time.Now,
		dial:    net.Dial,
		ifaceOf: interfaceOf,
	}
	if u, err := url.Parse(endpoint); err == nil && u.Hostname() != "" {
		port := u.Port()
		if port == "" {
			port = map[string]string{"http": "80", "https": "443"}[u.Scheme]
		}
		if port != "" {
			s.target = net.JoinHostPort(u.Hostname(), port)
		}
	}
	return s
}

// current returns the source address, looked up again when older than
// pushSourceInterval or when force is set. A UDP "connection" sends no
// packet: the kernel only picks the route and the source address.
func (s *pushSource) current(force bool) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.target == "" || !force && s.now().Sub(s.checkedAt) < pushSourceInterval {
		return s.address
	}
	s.checkedAt = s.now()
	s.address, s.iface = "", ""
	conn, err := s.dial("udp", s.target)
	if err != nil {
		return ""
	}
	defer conn.Close()
	la, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return ""
	}
	s.address, s.iface = la.IP.String(), s.ifaceOf(la.IP)
	return s.address
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
