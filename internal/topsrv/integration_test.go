//go:build integration

package topsrv

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/expfmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vmkteam/embedlog"
)

func nginxStubURL() string {
	if v := os.Getenv("TEST_NGINX_STUB"); v != "" {
		return v
	}
	return "http://127.0.0.1:18080/stub_status"
}

func vmURL() string {
	if v := os.Getenv("TEST_VM_URL"); v != "" {
		return v
	}
	return "http://127.0.0.1:18428"
}

func TestIntegrationNginxStub(t *testing.T) {
	resp, err := http.Get(nginxStubURL())
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, 200, resp.StatusCode)

	t.Log("nginx stub_status reachable")
}

func TestIntegrationPushToVM(t *testing.T) {
	vm := vmURL()

	resp, err := http.Get(vm + "/health")
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, 200, resp.StatusCode)

	reg := prometheus.NewRegistry()
	reg.MustRegister(NewSystemCollector(embedlog.Logger{}, "test"))

	mfs, err := reg.Gather()
	require.NoError(t, err)

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	enc := expfmt.NewEncoder(gz, expfmt.NewFormat(expfmt.TypeTextPlain))
	for _, mf := range mfs {
		require.NoError(t, enc.Encode(mf))
	}
	gz.Close()

	req, _ := http.NewRequestWithContext(context.Background(), "POST", vm+"/api/v1/import/prometheus", &buf)
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("Content-Type", "text/plain")

	pushResp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	body, _ := io.ReadAll(pushResp.Body)
	pushResp.Body.Close()
	require.Equal(t, 204, pushResp.StatusCode, "push failed: %s", string(body))

	queryURL := fmt.Sprintf("%s/api/v1/query?query=topsrv_uptime_seconds", vm)

	var qBody []byte
	found := false
	for range 10 {
		forceResp, _ := http.Get(vm + "/internal/force_flush")
		if forceResp != nil {
			forceResp.Body.Close()
		}
		time.Sleep(500 * time.Millisecond)

		qResp, err := http.Get(queryURL)
		require.NoError(t, err)
		qBody, _ = io.ReadAll(qResp.Body)
		qResp.Body.Close()

		require.Equal(t, 200, qResp.StatusCode)
		if bytes.Contains(qBody, []byte("topsrv_uptime_seconds")) {
			found = true
			break
		}
	}

	assert.True(t, found, "metric not found in VM after push: %s", string(qBody))
	t.Logf("push → VM → query: OK (%d bytes response)", len(qBody))
}
