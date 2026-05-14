package nginx

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/vmkteam/topsrv/internal/topsrv"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/vmkteam/embedlog"
)

var _ topsrv.Collector = (*SSLCollector)(nil)

const sslRefreshInterval = 5 * time.Minute

// certInfo holds cached certificate metadata. domains is the deduplicated
// union of Subject.CommonName and DNSNames (CN first); SAN-multi-host certs
// from angie ACME are surfaced via topsrv_ssl_certificate_san_info — the
// expiry metric stays one series per cert so its value (NotAfter) isn't
// duplicated across N domain rows.
type certInfo struct {
	path    string
	cn      string
	issuer  string
	expiry  float64 // NotAfter as Unix timestamp
	domains []string
}

// SSLCollector reads SSL certificate files and exposes expiry as a Prometheus gauge.
// Certificates are re-read every 5 minutes to detect renewals.
type SSLCollector struct {
	embedlog.Logger

	certPaths []string
	expiry    *prometheus.Desc
	sanInfo   *prometheus.Desc

	mu          sync.Mutex
	cached      []certInfo
	lastRefresh time.Time
}

func NewSSLCollector(logger embedlog.Logger, certPaths []string) *SSLCollector {
	c := &SSLCollector{
		Logger:    logger,
		certPaths: certPaths,
		expiry: prometheus.NewDesc(
			"topsrv_ssl_certificate_expiry_seconds",
			"SSL certificate NotAfter as Unix timestamp (one series per certificate file).",
			[]string{"path", "cn", "issuer"},
			nil,
		),
		// Info metric (value=1), one series per DNS name in CN ∪ SANs. Consumers
		// join with expiry by `path` to display per-domain rows. Following the
		// blackbox_exporter convention for probe_ssl_last_chain_info.
		sanInfo: prometheus.NewDesc(
			"topsrv_ssl_certificate_san_info",
			"SSL certificate DNS name (value always 1); one series per name in CN ∪ SANs. Join with topsrv_ssl_certificate_expiry_seconds on `path`.",
			[]string{"path", "domain"},
			nil,
		),
	}
	c.refresh()
	return c
}

func (c *SSLCollector) Name() string { return "ssl" }

func (c *SSLCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.expiry
	ch <- c.sanInfo
}

func (c *SSLCollector) Collect(ch chan<- prometheus.Metric) {
	c.mu.Lock()
	if time.Since(c.lastRefresh) > sslRefreshInterval {
		c.refresh()
	}
	certs := c.cached
	c.mu.Unlock()

	for _, ci := range certs {
		ch <- prometheus.MustNewConstMetric(c.expiry, prometheus.GaugeValue, ci.expiry, ci.path, ci.cn, ci.issuer)
		for _, d := range ci.domains {
			ch <- prometheus.MustNewConstMetric(c.sanInfo, prometheus.GaugeValue, 1, ci.path, d)
		}
	}
}

func (c *SSLCollector) refresh() {
	certs := make([]certInfo, 0, len(c.certPaths))
	for _, path := range c.certPaths {
		cert, err := readCertificate(path)
		if err != nil {
			c.Error(context.Background(), "ssl: failed to read certificate", "path", path, "error", err)
			continue
		}
		certs = append(certs, certInfo{
			path:    path,
			cn:      cert.Subject.CommonName,
			issuer:  cert.Issuer.CommonName,
			expiry:  float64(cert.NotAfter.Unix()),
			domains: certDomains(cert.Subject.CommonName, cert.DNSNames),
		})
	}
	c.cached = certs
	c.lastRefresh = time.Now()
	c.Print(context.Background(), "ssl: refreshed certificates", "count", len(certs))
}

// certDomains returns the deduplicated union of CN and SAN DNSNames with CN
// first so the primary subject appears as the leading series. Empty entries
// are skipped; result is empty when the cert has no CN and no SANs (rare,
// expiry metric still appears for such certs — only san_info is suppressed).
func certDomains(cn string, sans []string) []string {
	seen := make(map[string]struct{}, len(sans)+1)
	out := make([]string, 0, len(sans)+1)
	if cn != "" {
		seen[cn] = struct{}{}
		out = append(out, cn)
	}
	for _, s := range sans {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// readCertificate reads and parses the first certificate from a PEM file.
func readCertificate(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}
	return x509.ParseCertificate(block.Bytes)
}
