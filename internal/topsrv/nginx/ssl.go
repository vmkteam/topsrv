package nginx

import (
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

// certInfo holds cached certificate metadata.
type certInfo struct {
	path   string
	cn     string
	issuer string
	expiry float64 // NotAfter as Unix timestamp
}

// SSLCollector reads SSL certificate files and exposes expiry as a Prometheus gauge.
// Certificates are re-read every 5 minutes to detect renewals.
type SSLCollector struct {
	embedlog.Logger

	certPaths []string
	expiry    *prometheus.Desc

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
			"SSL certificate NotAfter as Unix timestamp.",
			[]string{"path", "cn", "issuer"},
			nil,
		),
	}
	c.refresh()
	return c
}

func (c *SSLCollector) Name() string { return "ssl" }

func (c *SSLCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.expiry
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
	}
}

func (c *SSLCollector) refresh() {
	certs := make([]certInfo, 0, len(c.certPaths))
	for _, path := range c.certPaths {
		cert, err := readCertificate(path)
		if err != nil {
			c.Printf("ssl: failed to read %s: %v", path, err)
			continue
		}
		certs = append(certs, certInfo{
			path:   path,
			cn:     cert.Subject.CommonName,
			issuer: cert.Issuer.CommonName,
			expiry: float64(cert.NotAfter.Unix()),
		})
	}
	c.cached = certs
	c.lastRefresh = time.Now()
	c.Printf("ssl: refreshed %d certificates", len(certs))
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
