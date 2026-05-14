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
	return generateTestCertSAN(t, cn, nil, notAfter)
}

// generateTestCertSAN creates a self-signed certificate with the given SAN
// DNSNames in addition to CN. Used to exercise multi-host (SAN) certificates.
func generateTestCertSAN(t *testing.T, cn string, dnsNames []string, notAfter time.Time) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn, Organization: []string{"topsrv-test"}},
		Issuer:       pkix.Name{CommonName: "topsrv-test CA"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		DNSNames:     dnsNames,
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

// TestSSLCollectorSANInfo — multi-host (SAN) cert emits one san_info series
// per unique DNS name (CN ∪ DNSNames). Without this, angie ACME multi-domain
// certs show only the CN in dashboards even though the cert serves N domains.
// expiry metric stays one series per cert (NotAfter value isn't duplicated).
func TestSSLCollectorSANInfo(t *testing.T) {
	expiry := time.Now().Add(30 * 24 * time.Hour).Truncate(time.Second)
	// CN duplicated in DNSNames is common in real certs (e.g. Let's Encrypt);
	// must be deduplicated.
	certPath := generateTestCertSAN(t, "a.example.com",
		[]string{"a.example.com", "example.com", "www.example.com"}, expiry)

	c := NewSSLCollector(embedlog.Logger{}, []string{certPath})
	reg := prometheus.NewRegistry()
	reg.MustRegister(c)

	mfs, err := reg.Gather()
	require.NoError(t, err)

	var expiryCount int
	var sanDomains []string
	for _, mf := range mfs {
		switch mf.GetName() {
		case "topsrv_ssl_certificate_expiry_seconds":
			expiryCount = len(mf.GetMetric())
		case "topsrv_ssl_certificate_san_info":
			for _, m := range mf.GetMetric() {
				assert.InDelta(t, 1.0, m.GetGauge().GetValue(), 0, "san_info value must be 1")
				for _, l := range m.GetLabel() {
					if l.GetName() == "domain" {
						sanDomains = append(sanDomains, l.GetValue())
					}
				}
			}
		}
	}
	assert.Equal(t, 1, expiryCount, "expiry stays one series per cert regardless of SAN count")
	assert.ElementsMatch(t,
		[]string{"a.example.com", "example.com", "www.example.com"}, sanDomains,
		"expected one san_info per unique CN/SAN domain")
}

// TestSSLCollectorNoCNorSAN — pathological cert (empty CN, empty SANs) still
// emits expiry so path/issuer stay visible; san_info is suppressed because
// there are no names to enumerate.
func TestSSLCollectorNoCNorSAN(t *testing.T) {
	expiry := time.Now().Add(30 * 24 * time.Hour).Truncate(time.Second)
	certPath := generateTestCertSAN(t, "", nil, expiry)

	c := NewSSLCollector(embedlog.Logger{}, []string{certPath})
	reg := prometheus.NewRegistry()
	reg.MustRegister(c)

	mfs, err := reg.Gather()
	require.NoError(t, err)

	var expiryCount, sanCount int
	for _, mf := range mfs {
		switch mf.GetName() {
		case "topsrv_ssl_certificate_expiry_seconds":
			expiryCount = len(mf.GetMetric())
		case "topsrv_ssl_certificate_san_info":
			sanCount = len(mf.GetMetric())
		}
	}
	assert.Equal(t, 1, expiryCount, "expiry visible even without CN/SAN")
	assert.Equal(t, 0, sanCount, "san_info suppressed when no domains")
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
	extractSSLCertificates(content, "/etc/nginx", result)

	assert.Equal(t, []string{"/etc/ssl/cert.pem"}, result.SSLCertificates)
}

func TestDiscoverSSLRelativePath(t *testing.T) {
	dir := t.TempDir()
	conf := `http {
    server {
        ssl_certificate ssl/myshows.me.fullchain.cer;
        ssl_certificate_key ssl/myshows.me.key;
    }
}`
	os.WriteFile(filepath.Join(dir, "nginx.conf"), []byte(conf), 0644)

	result, err := DiscoverConfig(filepath.Join(dir, "nginx.conf"))
	require.NoError(t, err)

	require.Len(t, result.SSLCertificates, 1)
	assert.Equal(t, filepath.Join(dir, "ssl/myshows.me.fullchain.cer"), result.SSLCertificates[0])
}

// withTestACMEStatePath redirects defaultACMEStatePath to a t.TempDir with cleanup.
func withTestACMEStatePath(t *testing.T) string {
	t.Helper()
	tmp := t.TempDir()
	orig := defaultACMEStatePath
	defaultACMEStatePath = tmp
	t.Cleanup(func() { defaultACMEStatePath = orig })
	return tmp
}

// writeACMEClientCert plants a self-signed certificate.pem in the angie
// state-path layout: <statePath>/<client>/certificate.pem.
func writeACMEClientCert(t *testing.T, statePath, client, cn string) {
	t.Helper()
	dir := filepath.Join(statePath, client)
	require.NoError(t, os.MkdirAll(dir, 0o755))
	certFile := filepath.Join(dir, "certificate.pem")

	src := generateTestCert(t, cn, time.Now().Add(60*24*time.Hour))
	data, err := os.ReadFile(src)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(certFile, data, 0o600))
}

// TestExtractACMECertificatesPicksUpRealLayout — regression: `ssl_certificate
// $var` defeats the static-path regex, so we must fall through to the
// default state-path layout to find ACME-managed certs.
func TestExtractACMECertificatesPicksUpRealLayout(t *testing.T) {
	tmp := withTestACMEStatePath(t)

	// Plant two ACME client certs the way angie actually lays them out
	// (verified on a real angie 1.x install).
	writeACMEClientCert(t, tmp, "client_alpha", "alpha.example")
	writeACMEClientCert(t, tmp, "client_beta", "beta.example")

	// Minimal angie.conf with two acme_client directives + the variable-
	// based ssl_certificate that defeats static-path discovery.
	content := strings.Join([]string{
		"acme_client client_alpha https://acme-v02.api.letsencrypt.org/directory;",
		"acme_client client_beta https://acme-v02.api.letsencrypt.org/directory;",
		"ssl_certificate $acme_cert_client_alpha;",
	}, "\n")

	result := &DiscoverResult{}
	extractACMECertificates(content, result)

	assert.ElementsMatch(t, []string{
		filepath.Join(tmp, "client_alpha", "certificate.pem"),
		filepath.Join(tmp, "client_beta", "certificate.pem"),
	}, result.SSLCertificates)
}

// TestExtractACMECertificatesSkipsMissingFiles — acme_client exists in the
// config but the cert isn't on disk yet (e.g. angie hasn't issued it).
// Discovery must silently skip rather than emitting a bad path.
func TestExtractACMECertificatesSkipsMissingFiles(t *testing.T) {
	withTestACMEStatePath(t) // empty tmp — no certs on disk

	content := "acme_client absent_client https://acme-v02.api.letsencrypt.org/directory;"
	result := &DiscoverResult{}
	extractACMECertificates(content, result)

	assert.Empty(t, result.SSLCertificates)
}

// TestExtractACMECertificatesDedupes — if the same cert path is already
// present (e.g. operator pinned it via a literal ssl_certificate too),
// don't add it twice.
func TestExtractACMECertificatesDedupes(t *testing.T) {
	tmp := withTestACMEStatePath(t)
	writeACMEClientCert(t, tmp, "shared", "shared.example")
	pinnedPath := filepath.Join(tmp, "shared", "certificate.pem")

	content := "acme_client shared https://acme-v02.api.letsencrypt.org/directory;"
	result := &DiscoverResult{SSLCertificates: []string{pinnedPath}}
	extractACMECertificates(content, result)

	assert.Equal(t, []string{pinnedPath}, result.SSLCertificates)
}

// TestExtractACMECertificatesSkipsCommented — operators frequently leave
// commented-out `# acme_client old_name ...;` lines after migration; the
// regex must not match them, otherwise a stale cert directory left on
// disk would resurrect as a monitored series.
func TestExtractACMECertificatesSkipsCommented(t *testing.T) {
	tmp := withTestACMEStatePath(t)
	writeACMEClientCert(t, tmp, "old_client", "old.example")

	content := strings.Join([]string{
		"# acme_client old_client https://acme-v02.api.letsencrypt.org/directory;",
		"  #acme_client also_commented https://acme-v02.api.letsencrypt.org/directory;",
	}, "\n")

	result := &DiscoverResult{}
	found, picked := extractACMECertificates(content, result)

	assert.Empty(t, result.SSLCertificates)
	assert.Zero(t, found, "commented directives must not count")
	assert.Zero(t, picked)
}

// TestExtractACMECertificatesRejectsTraversal — defense in depth: a name
// containing path separators or .. would let a misconfigured acme_client
// escape defaultACMEStatePath when filepath.Join cleans the path. Skip
// such names rather than serving up arbitrary paths.
func TestExtractACMECertificatesRejectsTraversal(t *testing.T) {
	withTestACMEStatePath(t)

	content := strings.Join([]string{
		"acme_client ../escape https://acme-v02.api.letsencrypt.org/directory;",
		"acme_client a/b https://acme-v02.api.letsencrypt.org/directory;",
		`acme_client a\b https://acme-v02.api.letsencrypt.org/directory;`,
		"acme_client . https://acme-v02.api.letsencrypt.org/directory;",
	}, "\n")

	result := &DiscoverResult{}
	found, _ := extractACMECertificates(content, result)

	assert.Empty(t, result.SSLCertificates)
	assert.Zero(t, found, "traversal-shaped names must be rejected before counting")
}
