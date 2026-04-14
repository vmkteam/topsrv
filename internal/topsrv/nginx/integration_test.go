//go:build integration

package nginx

import (
	"bufio"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vmkteam/embedlog"
)

func nginxContainerName() string {
	if v := os.Getenv("TEST_NGINX_CONTAINER"); v != "" {
		return v
	}
	return "vmkteam-topsrv-nginx-1"
}

func angieContainerName() string {
	if v := os.Getenv("TEST_ANGIE_CONTAINER"); v != "" {
		return v
	}
	return "vmkteam-topsrv-angie-1"
}

// readContainerFile reads a file from a running Docker container via `docker exec cat`.
func readContainerFile(t *testing.T, container, path string) string {
	t.Helper()
	out, err := exec.Command("docker", "exec", container, "cat", path).Output()
	if err != nil {
		return ""
	}
	return string(out)
}

func parseJSONLogFromContainer(t *testing.T, container, logPath string, extraLabels []string) (*LogCollector, int) {
	t.Helper()

	logData := readContainerFile(t, container, logPath)
	require.NotEmpty(t, logData, "JSON access log is empty — check container %s path %s", container, logPath)

	c := NewLogCollector(embedlog.Logger{}, LogConfig{
		LogPaths:    []string{"/dev/null"},
		JSONPaths:   map[string]bool{"/dev/null": true},
		ExtraLabels: extraLabels,
	})

	var lineCount int
	scanner := bufio.NewScanner(strings.NewReader(logData))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		c.ParseJSONLine(line)
		lineCount++
	}
	return c, lineCount
}

func TestIntegrationNginxJSONLog(t *testing.T) {
	container := nginxContainerName()

	// Generate traffic so nginx writes JSON log lines.
	for range 10 {
		r, _ := http.Get("http://127.0.0.1:18080/")
		if r != nil {
			r.Body.Close()
		}
		r, _ = http.Get("http://127.0.0.1:18080/nonexistent")
		if r != nil {
			r.Body.Close()
		}
	}

	time.Sleep(500 * time.Millisecond)

	c, lineCount := parseJSONLogFromContainer(t, container, "/var/log/nginx/json/access.log", nil)
	require.Greater(t, lineCount, 0, "no JSON log lines found")

	reg := prometheus.NewRegistry()
	reg.MustRegister(c)
	mfs, err := reg.Gather()
	require.NoError(t, err)

	names := map[string]bool{}
	for _, mf := range mfs {
		names[mf.GetName()] = true
	}

	assert.True(t, names["topsrv_nginx_request_duration_seconds"], "missing request duration histogram")
	assert.True(t, names["topsrv_nginx_http_requests_total"], "missing http requests counter")
	assert.True(t, names["topsrv_nginx_response_bytes_total"], "missing response bytes counter")

	t.Logf("nginx JSON log integration: %d lines parsed, %d metric families", lineCount, len(mfs))
}

func TestIntegrationNginxJSONLogExtraLabels(t *testing.T) {
	container := nginxContainerName()

	// Generate traffic.
	for range 5 {
		r, _ := http.Get("http://127.0.0.1:18080/")
		if r != nil {
			r.Body.Close()
		}
	}

	time.Sleep(500 * time.Millisecond)

	c, lineCount := parseJSONLogFromContainer(t, container, "/var/log/nginx/json/access.log", []string{"host"})
	require.Greater(t, lineCount, 0, "no JSON log lines found")

	// With ExtraLabels, statusCounts should be empty and taggedCounts should have entries.
	assert.Empty(t, c.statusCounts, "statusCounts should be empty when ExtraLabels are used")
	assert.NotEmpty(t, c.taggedCounts, "taggedCounts should have entries with ExtraLabels")

	// Verify the "host" label appears in Prometheus output.
	reg := prometheus.NewRegistry()
	reg.MustRegister(c)
	mfs, err := reg.Gather()
	require.NoError(t, err)

	var foundHostLabel bool
	for _, mf := range mfs {
		if mf.GetName() != "topsrv_nginx_http_requests_total" {
			continue
		}
		for _, m := range mf.GetMetric() {
			for _, lp := range m.GetLabel() {
				if lp.GetName() == "host" && lp.GetValue() != "" {
					foundHostLabel = true
				}
			}
		}
	}
	assert.True(t, foundHostLabel, "http_requests_total should have 'host' label from ExtraLabels")

	t.Logf("nginx JSON log extra labels: %d lines, %d tagged combos", lineCount, len(c.taggedCounts))
}

func TestIntegrationAngieJSONLog(t *testing.T) {
	container := angieContainerName()

	// Generate traffic so angie writes JSON log lines.
	for range 10 {
		r, _ := http.Get("http://127.0.0.1:18081/")
		if r != nil {
			r.Body.Close()
		}
		r, _ = http.Get("http://127.0.0.1:18081/nonexistent")
		if r != nil {
			r.Body.Close()
		}
	}

	time.Sleep(500 * time.Millisecond)

	c, lineCount := parseJSONLogFromContainer(t, container, "/var/log/angie/json/access.log", nil)
	require.Greater(t, lineCount, 0, "no JSON log lines found")

	reg := prometheus.NewRegistry()
	reg.MustRegister(c)
	mfs, err := reg.Gather()
	require.NoError(t, err)

	names := map[string]bool{}
	for _, mf := range mfs {
		names[mf.GetName()] = true
	}

	assert.True(t, names["topsrv_nginx_request_duration_seconds"], "missing request duration histogram")
	assert.True(t, names["topsrv_nginx_http_requests_total"], "missing http requests counter")
	assert.True(t, names["topsrv_nginx_response_bytes_total"], "missing response bytes counter")

	t.Logf("angie JSON log integration: %d lines parsed, %d metric families", lineCount, len(mfs))
}

func TestIntegrationAngieJSONLogExtraLabels(t *testing.T) {
	container := angieContainerName()

	for range 5 {
		r, _ := http.Get("http://127.0.0.1:18081/")
		if r != nil {
			r.Body.Close()
		}
	}

	time.Sleep(500 * time.Millisecond)

	c, lineCount := parseJSONLogFromContainer(t, container, "/var/log/angie/json/access.log", []string{"host"})
	require.Greater(t, lineCount, 0, "no JSON log lines found")

	assert.Empty(t, c.statusCounts, "statusCounts should be empty when ExtraLabels are used")
	assert.NotEmpty(t, c.taggedCounts, "taggedCounts should have entries with ExtraLabels")

	reg := prometheus.NewRegistry()
	reg.MustRegister(c)
	mfs, err := reg.Gather()
	require.NoError(t, err)

	var foundHostLabel bool
	for _, mf := range mfs {
		if mf.GetName() != "topsrv_nginx_http_requests_total" {
			continue
		}
		for _, m := range mf.GetMetric() {
			for _, lp := range m.GetLabel() {
				if lp.GetName() == "host" && lp.GetValue() != "" {
					foundHostLabel = true
				}
			}
		}
	}
	assert.True(t, foundHostLabel, "http_requests_total should have 'host' label from ExtraLabels")

	t.Logf("angie JSON log extra labels: %d lines, %d tagged combos", lineCount, len(c.taggedCounts))
}

func TestIntegrationNginxSSLCertificate(t *testing.T) {
	container := nginxContainerName()

	// Read the generated cert from the container.
	certData := readContainerFile(t, container, "/etc/nginx/ssl/test.pem")
	require.NotEmpty(t, certData, "SSL cert not found — check that gen-test-cert.sh ran in container %s", container)

	// Write cert to temp dir so SSLCollector can read it locally.
	dir := t.TempDir()
	certPath := filepath.Join(dir, "test.pem")
	os.WriteFile(certPath, []byte(certData), 0644)

	c := NewSSLCollector(embedlog.Logger{}, []string{certPath})
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
		require.NotEmpty(t, mf.GetMetric())
		m := mf.GetMetric()[0]

		assert.Greater(t, m.GetGauge().GetValue(), float64(time.Now().Unix()), "cert should not be expired")

		labels := map[string]string{}
		for _, l := range m.GetLabel() {
			labels[l.GetName()] = l.GetValue()
		}
		assert.Equal(t, "test.example.com", labels["cn"])
		assert.NotEmpty(t, labels["path"])
		assert.NotEmpty(t, labels["issuer"])
	}
	assert.True(t, found, "topsrv_ssl_certificate_expiry_seconds not found")
	t.Log("nginx SSL certificate integration: ok")
}

func TestIntegrationAngieSSLCertificate(t *testing.T) {
	container := angieContainerName()

	certData := readContainerFile(t, container, "/etc/angie/ssl/test.pem")
	require.NotEmpty(t, certData, "SSL cert not found — check that gen-test-cert.sh ran in container %s", container)

	dir := t.TempDir()
	certPath := filepath.Join(dir, "test.pem")
	os.WriteFile(certPath, []byte(certData), 0644)

	c := NewSSLCollector(embedlog.Logger{}, []string{certPath})
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
		m := mf.GetMetric()[0]
		assert.Greater(t, m.GetGauge().GetValue(), float64(time.Now().Unix()), "cert should not be expired")
	}
	assert.True(t, found, "topsrv_ssl_certificate_expiry_seconds not found")
	t.Log("angie SSL certificate integration: ok")
}

func TestIntegrationDiscoverNginxSSL(t *testing.T) {
	container := nginxContainerName()
	confData := readContainerFile(t, container, "/etc/nginx/nginx.conf")
	require.NotEmpty(t, confData)

	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "nginx.conf"), []byte(confData), 0644)

	result, err := DiscoverConfig(filepath.Join(dir, "nginx.conf"))
	require.NoError(t, err)

	assert.NotEmpty(t, result.SSLCertificates, "should discover ssl_certificate paths from nginx.conf")
	assert.Contains(t, result.SSLCertificates, "/etc/nginx/ssl/test.pem")
	t.Logf("nginx SSL discover: %v", result.SSLCertificates)
}
