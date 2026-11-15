package topsrv

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vmkteam/embedlog"
)

// udpConn is a net.Conn with a fixed local address.
type udpConn struct {
	net.Conn
	local net.Addr
}

func (c udpConn) LocalAddr() net.Addr { return c.local }
func (c udpConn) Close() error        { return nil }

func TestNewPushSource(t *testing.T) {
	for endpoint, want := range map[string]string{
		"https://push.example.com/v1/write": "push.example.com:443",
		"http://push.example.com/v1/write":  "push.example.com:80",
		"https://push.example.com:8443/v1":  "push.example.com:8443",
		"https://[2001:db8::1]/v1/write":    "[2001:db8::1]:443",
		"":                                  "",
		"ftp://push.example.com/":           "",
		"://bad":                            "",
	} {
		t.Run(endpoint, func(t *testing.T) {
			assert.Equal(t, want, newPushSource(endpoint).target)
		})
	}
}

func TestPushSourceCurrent(t *testing.T) {
	now := time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC)
	dials := 0
	s := newPushSource("https://push.example.com/v1/write")
	s.now = func() time.Time { return now }
	s.dial = func(network, address string) (net.Conn, error) {
		dials++
		assert.Equal(t, "udp", network, "no TCP connection, no packet")
		assert.Equal(t, "push.example.com:443", address)
		return udpConn{local: &net.UDPAddr{IP: net.ParseIP("203.0.113.5"), Port: 40000}}, nil
	}
	s.ifaceOf = func(ip net.IP) string { return "eth0" }

	assert.Equal(t, "203.0.113.5", s.current(false))
	assert.Equal(t, "203.0.113.5", s.current(false))
	assert.Equal(t, 1, dials, "cached within the interval")

	now = now.Add(pushSourceInterval)
	s.current(false)
	assert.Equal(t, 2, dials, "looked up again after the interval")

	s.current(true)
	assert.Equal(t, 3, dials, "a failed send looks it up at once")

	assert.Equal(t, 1, testutil.CollectAndCount(s))
	assert.InDelta(t, 1.0, testutil.ToFloat64(s), 0)

	s.dial = func(string, string) (net.Conn, error) { return nil, errors.New("no route") }
	assert.Empty(t, s.current(true))
	assert.Equal(t, 0, testutil.CollectAndCount(s), "no series without an address")
}

func TestPushSourceLoopback(t *testing.T) {
	s := newPushSource("http://127.0.0.1:9/v1/write")

	assert.Equal(t, "127.0.0.1", s.current(true))
	assert.NotEmpty(t, s.iface, "the loopback interface holds it")
}

func TestPusherSourceAfterFailedSend(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)
	reg := prometheus.NewRegistry()
	p := NewPusher(embedlog.Logger{}, "topsrv", "test", PushConfig{Endpoint: srv.URL + "/v1/write", Interval: "1s", SpoolDir: t.TempDir()}, reg)

	p.push(t.Context())

	mfs, err := reg.Gather()
	require.NoError(t, err)
	var labels []string
	for _, mf := range mfs {
		if mf.GetName() == "topsrv_push_source_info" {
			for _, l := range mf.GetMetric()[0].GetLabel() {
				labels = append(labels, l.GetName()+"="+l.GetValue())
			}
		}
	}
	assert.Contains(t, strings.Join(labels, ","), "address=127.0.0.1")
}
