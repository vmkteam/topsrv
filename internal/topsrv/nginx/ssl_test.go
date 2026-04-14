package nginx

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vmkteam/embedlog"
)

// generateTestCert creates a self-signed certificate PEM file and returns its path.
func generateTestCert(t *testing.T, cn string, notAfter time.Time) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn, Organization: []string{"topsrv-test"}},
		Issuer:       pkix.Name{CommonName: "topsrv-test CA"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	path := filepath.Join(t.TempDir(), cn+".pem")
	f, err := os.Create(path)
	require.NoError(t, err)
	defer f.Close()

	require.NoError(t, pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: der}))
	return path
}

func TestSSLCollector(t *testing.T) {
	expiry := time.Now().Add(30 * 24 * time.Hour).Truncate(time.Second)
	certPath := generateTestCert(t, "example.com", expiry)

	c := NewSSLCollector(embedlog.Logger{}, []string{certPath})
	assert.Equal(t, "ssl", c.Name())

	reg := prometheus.NewRegistry()
	reg.MustRegister(c)

	mfs, err := reg.Gather()
	require.NoError(t, err)

	var found bool
	for _, mf := range mfs {
		if mf.GetName() != "topsrv_ssl_certificate_expiry_seconds" {
			continue
		}
		found = true
		require.Len(t, mf.GetMetric(), 1)

		m := mf.GetMetric()[0]
		assert.InDelta(t, float64(expiry.Unix()), m.GetGauge().GetValue(), 0)

		labels := map[string]string{}
		for _, l := range m.GetLabel() {
			labels[l.GetName()] = l.GetValue()
		}
		assert.Equal(t, certPath, labels["path"])
		assert.Equal(t, "example.com", labels["cn"])
		assert.Equal(t, "example.com", labels["issuer"]) // self-signed: issuer == subject
	}
	assert.True(t, found, "topsrv_ssl_certificate_expiry_seconds not found")
}

func TestSSLCollectorMultipleCerts(t *testing.T) {
	expiry1 := time.Now().Add(30 * 24 * time.Hour).Truncate(time.Second)
	expiry2 := time.Now().Add(90 * 24 * time.Hour).Truncate(time.Second)
	path1 := generateTestCert(t, "a.example.com", expiry1)
	path2 := generateTestCert(t, "b.example.com", expiry2)

	c := NewSSLCollector(embedlog.Logger{}, []string{path1, path2})

	reg := prometheus.NewRegistry()
	reg.MustRegister(c)

	mfs, err := reg.Gather()
	require.NoError(t, err)

	var count int
	for _, mf := range mfs {
		if mf.GetName() == "topsrv_ssl_certificate_expiry_seconds" {
			count = len(mf.GetMetric())
		}
	}
	assert.Equal(t, 2, count, "expected 2 certificate metrics")
}

func TestSSLCollectorUnreadable(t *testing.T) {
	c := NewSSLCollector(embedlog.Logger{}, []string{"/nonexistent/cert.pem"})

	reg := prometheus.NewRegistry()
	reg.MustRegister(c)

	mfs, err := reg.Gather()
	require.NoError(t, err)

	for _, mf := range mfs {
		if mf.GetName() == "topsrv_ssl_certificate_expiry_seconds" {
			assert.Empty(t, mf.GetMetric(), "should not emit metric for unreadable cert")
		}
	}
}

func TestSSLCollectorInvalidPEM(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.pem")
	os.WriteFile(path, []byte("not a PEM file"), 0644)

	c := NewSSLCollector(embedlog.Logger{}, []string{path})

	reg := prometheus.NewRegistry()
	reg.MustRegister(c)

	mfs, err := reg.Gather()
	require.NoError(t, err)

	for _, mf := range mfs {
		if mf.GetName() == "topsrv_ssl_certificate_expiry_seconds" {
			assert.Empty(t, mf.GetMetric(), "should not emit metric for invalid PEM")
		}
	}
}

func TestReadCertificate(t *testing.T) {
	expiry := time.Now().Add(60 * 24 * time.Hour).Truncate(time.Second)
	path := generateTestCert(t, "test.local", expiry)

	cert, err := readCertificate(path)
	require.NoError(t, err)
	assert.Equal(t, "test.local", cert.Subject.CommonName)
	assert.Equal(t, expiry.Unix(), cert.NotAfter.Unix())
}

func TestDiscoverSSLCertificates(t *testing.T) {
	cases := []struct {
		name      string
		conf      string
		wantCerts []string
	}{
		{
			name: "single server with ssl",
			conf: `http {
    server {
        listen 443 ssl;
        ssl_certificate /etc/ssl/example.com.pem;
        ssl_certificate_key /etc/ssl/example.com.key;
    }
}`,
			wantCerts: []string{"/etc/ssl/example.com.pem"},
		},
		{
			name: "multiple servers with SNI",
			conf: `http {
    server {
        ssl_certificate /etc/ssl/a.pem;
        ssl_certificate_key /etc/ssl/a.key;
    }
    server {
        ssl_certificate /etc/ssl/b.pem;
        ssl_certificate_key /etc/ssl/b.key;
    }
}`,
			wantCerts: []string{"/etc/ssl/a.pem", "/etc/ssl/b.pem"},
		},
		{
			name: "deduplicate same cert",
			conf: `http {
    server { ssl_certificate /etc/ssl/shared.pem; }
    server { ssl_certificate /etc/ssl/shared.pem; }
}`,
			wantCerts: []string{"/etc/ssl/shared.pem"},
		},
		{
			name: "commented out",
			conf: `http {
    server {
        # ssl_certificate /etc/ssl/old.pem;
    }
}`,
			wantCerts: nil,
		},
		{
			name: "ssl_certificate_key excluded",
			conf: `http {
    server {
        ssl_certificate_key /etc/ssl/only-key.pem;
    }
}`,
			wantCerts: nil,
		},
		{
			name: "nginx variable skipped",
			conf: `http {
    server {
        ssl_certificate $acme_cert_example;
        ssl_certificate_key $acme_cert_example_key;
    }
}`,
			wantCerts: nil,
		},
		{
			name: "quoted path",
			conf: `http {
    server {
        ssl_certificate "/etc/ssl/my site/cert.pem";
        ssl_certificate_key "/etc/ssl/my site/cert.key";
    }
}`,
			wantCerts: []string{"/etc/ssl/my site/cert.pem"},
		},
		{
			name:      "no ssl directives",
			conf:      `http { server { listen 80; } }`,
			wantCerts: nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			os.WriteFile(filepath.Join(dir, "nginx.conf"), []byte(tc.conf), 0644)

			result, err := DiscoverConfig(filepath.Join(dir, "nginx.conf"))
			require.NoError(t, err)

			if tc.wantCerts == nil {
				assert.Empty(t, result.SSLCertificates)
			} else {
				assert.Equal(t, tc.wantCerts, result.SSLCertificates)
			}
		})
	}
}

func TestDiscoverSSLCertificatesWithInclude(t *testing.T) {
	dir := t.TempDir()

	mainConf := `http {
    include ` + filepath.Join(dir, "sites", "*.conf") + `;
}`
	os.WriteFile(filepath.Join(dir, "nginx.conf"), []byte(mainConf), 0644)

	os.MkdirAll(filepath.Join(dir, "sites"), 0755)
	siteConf := `server {
    listen 443 ssl;
    ssl_certificate /etc/ssl/site.pem;
    ssl_certificate_key /etc/ssl/site.key;
}`
	os.WriteFile(filepath.Join(dir, "sites", "site.conf"), []byte(siteConf), 0644)

	result, err := DiscoverConfig(filepath.Join(dir, "nginx.conf"))
	require.NoError(t, err)

	assert.Equal(t, []string{"/etc/ssl/site.pem"}, result.SSLCertificates)
}

func TestSSLCollectorCacheRefresh(t *testing.T) {
	expiry := time.Now().Add(30 * 24 * time.Hour).Truncate(time.Second)
	certPath := generateTestCert(t, "cache-test.com", expiry)

	c := NewSSLCollector(embedlog.Logger{}, []string{certPath})
	assert.Len(t, c.cached, 1)

	// Simulate stale cache by setting lastRefresh in the past.
	c.mu.Lock()
	c.lastRefresh = time.Now().Add(-10 * time.Minute)
	c.mu.Unlock()

	// Generate a new cert to the same path with different expiry.
	newExpiry := time.Now().Add(60 * 24 * time.Hour).Truncate(time.Second)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "cache-test.com"},
		Issuer:       pkix.Name{CommonName: "topsrv-test CA"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     newExpiry,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	f, _ := os.Create(certPath)
	pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	f.Close()

	// Collect should trigger refresh and pick up new expiry.
	reg := prometheus.NewRegistry()
	reg.MustRegister(c)
	mfs, _ := reg.Gather()

	for _, mf := range mfs {
		if mf.GetName() == "topsrv_ssl_certificate_expiry_seconds" {
			got := mf.GetMetric()[0].GetGauge().GetValue()
			assert.InDelta(t, float64(newExpiry.Unix()), got, 0, "should reflect updated cert after cache refresh")
		}
	}

	// Verify lastRefresh was updated.
	c.mu.Lock()
	assert.Less(t, time.Since(c.lastRefresh), time.Second, "lastRefresh should be recent")
	c.mu.Unlock()
}

func TestExtractSSLCertificatesDoesNotMatchKey(t *testing.T) {
	content := strings.Join([]string{
		"ssl_certificate /etc/ssl/cert.pem;",
		"ssl_certificate_key /etc/ssl/cert.key;",
	}, "\n")

	result := &DiscoverResult{}
	extractSSLCertificates(content, result)

	assert.Equal(t, []string{"/etc/ssl/cert.pem"}, result.SSLCertificates)
}
