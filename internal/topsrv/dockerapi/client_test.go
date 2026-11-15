package dockerapi

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// serve runs h on a unix socket and returns its path, relative to a temp
// directory made the working one: a socket path is limited to 104 bytes on
// macOS, and its temp directories are long.
func serve(t *testing.T, h http.Handler) string {
	t.Helper()
	t.Chdir(t.TempDir())
	const sock = "docker.sock"
	l, err := net.Listen("unix", sock)
	require.NoError(t, err)
	srv := &http.Server{Handler: h, ReadHeaderTimeout: time.Second}
	go func() {
		if err := srv.Serve(l); !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("test server: %v", err)
		}
	}()
	t.Cleanup(func() { srv.Close() })
	return sock
}

// write answers a test request. The client may stop reading (at the end
// of the JSON value, or at its limit), and the server closes when the test
// ends: neither is a failure.
func write(t *testing.T, w http.ResponseWriter, b []byte) {
	_, err := w.Write(b)
	if err != nil && !errors.Is(err, syscall.EPIPE) && !errors.Is(err, syscall.ECONNRESET) && !errors.Is(err, net.ErrClosed) {
		t.Errorf("test server: %v", err)
	}
}

// fixtureEngine serves what a dockerd version returned: /_ping with its
// headers, /info and /containers/json under /v{api}/.
func fixtureEngine(t *testing.T, dir string) (http.Handler, string) {
	t.Helper()
	headers, err := os.ReadFile(filepath.Join(dir, "ping.headers"))
	require.NoError(t, err)
	var api string
	for line := range strings.SplitSeq(string(headers), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), ":"); ok && strings.EqualFold(k, "Api-Version") {
			api = strings.TrimSpace(v)
		}
	}
	require.NotEmpty(t, api)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /_ping", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Api-Version", api)
		fmt.Fprint(w, "OK")
	})
	for _, ep := range []string{"info", "containers/json"} {
		body, err := os.ReadFile(filepath.Join(dir, strings.ReplaceAll(ep, "/json", "")+".json"))
		require.NoError(t, err)
		mux.HandleFunc("GET /v"+api+"/"+ep, func(w http.ResponseWriter, _ *http.Request) { write(t, w, body) })
	}
	return mux, api
}

// inspectPorts reads the oracle: `docker inspect` NetworkSettings.Ports of
// the same containers, "name ip:public->private/type" per published port.
func inspectPorts(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	require.NoError(t, err)
	defer f.Close()
	var out []string
	s := bufio.NewScanner(f)
	for s.Scan() {
		name, ports, ok := strings.Cut(s.Text(), " ")
		require.True(t, ok)
		var bindings map[string][]struct {
			HostIP   string `json:"HostIp"`
			HostPort string
		}
		require.NoError(t, json.Unmarshal([]byte(ports), &bindings))
		for port, bs := range bindings {
			for _, b := range bs {
				out = append(out, fmt.Sprintf("%s %s:%s->%s", strings.Trim(name, `"/`), b.HostIP, b.HostPort, port))
			}
		}
	}
	slices.Sort(out)
	return out
}

func TestClientEngines(t *testing.T) {
	cases := []struct {
		version, firewall string
	}{
		{"27", ""}, // FirewallBackend comes with API 1.49
		{"28", "iptables"},
		{"29", "iptables"},
	}
	for _, tc := range cases {
		t.Run("docker "+tc.version, func(t *testing.T) {
			dir, err := filepath.Abs(filepath.Join("testdata", "docker-"+tc.version)) // serve changes the working directory
			require.NoError(t, err)
			h, api := fixtureEngine(t, dir)
			c := New(serve(t, h))
			got, err := c.Ping(t.Context())
			require.NoError(t, err)
			assert.Equal(t, api, got)

			info, err := c.Info(t.Context())
			require.NoError(t, err)
			assert.True(t, strings.HasPrefix(info.ServerVersion, tc.version+"."), info.ServerVersion)
			assert.Equal(t, tc.firewall, info.FirewallBackend)
			assert.Equal(t, []string{"seccomp", "cgroupns"}, info.SecurityOptions)
			require.NotNil(t, info.ContainersRunning)
			assert.Equal(t, 3, *info.ContainersRunning)

			list, skipped, err := c.Containers(t.Context())
			require.NoError(t, err)
			assert.Zero(t, skipped)
			var published []string
			for _, ct := range list {
				for _, p := range ct.Ports {
					if p.PublicPort > 0 {
						published = append(published, fmt.Sprintf("%s %s:%d->%d/%s", strings.TrimPrefix(ct.Names[0], "/"), p.IP, p.PublicPort, p.PrivatePort, p.Type))
					}
				}
			}
			slices.Sort(published)
			assert.Equal(t, inspectPorts(t, filepath.Join(dir, "inspect-ports.txt")), published, "the same ports docker inspect shows")
		})
	}
}

func TestClientContainersStream(t *testing.T) {
	t.Run("an answer at the limit is read", func(t *testing.T) {
		body := `[{"Names": ["/a"], "Ports": []}]`
		body += strings.Repeat(" ", MaxResponseSize-len(body))
		c := New(serve(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { write(t, w, []byte(body)) })))
		list, _, err := c.Containers(t.Context())
		require.NoError(t, err)
		assert.Len(t, list, 1)
	})
	t.Run("past the limit inside the list", func(t *testing.T) {
		big := `[{"Names": ["/a"]}, {"Names": ["/` + strings.Repeat("b", MaxResponseSize) + `"]}]` // fast under -race too
		c := New(serve(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { write(t, w, []byte(big)) })))
		_, _, err := c.Containers(t.Context())
		require.ErrorIs(t, err, ErrTooLarge)
	})
	t.Run("not a list", func(t *testing.T) {
		c := New(serve(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { write(t, w, []byte(`{"message": "x"}`)) })))
		_, _, err := c.Containers(t.Context())
		require.ErrorIs(t, err, errNotList)
	})
}

func TestClientRefuses(t *testing.T) {
	t.Run("a redirect is not followed", func(t *testing.T) {
		c := New(serve(t, http.RedirectHandler("http://192.0.2.1/", http.StatusFound)))
		_, err := c.Ping(t.Context())
		var se *StatusError
		require.ErrorAs(t, err, &se)
		assert.Equal(t, http.StatusFound, se.Code)
	})
	t.Run("an answer past the limit", func(t *testing.T) {
		c := New(serve(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			write(t, w, []byte(`{"ServerVersion": "`+strings.Repeat("a", MaxResponseSize)+`"}`)) // valid JSON, to the end
		})))
		_, err := c.Info(t.Context())
		require.ErrorIs(t, err, ErrTooLarge)
	})
	t.Run("a daemon that does not answer", func(t *testing.T) {
		block := make(chan struct{})
		t.Cleanup(func() { close(block) })
		c := New(serve(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-block })))
		ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
		defer cancel()
		start := time.Now()
		_, err := c.Ping(ctx)
		require.ErrorIs(t, err, context.DeadlineExceeded)
		assert.Less(t, time.Since(start), RequestTimeout, "the caller's deadline holds")
	})
	t.Run("no socket", func(t *testing.T) {
		_, err := New("/nonexistent/docker.sock").Ping(t.Context())
		require.Error(t, err)
	})
	t.Run("a proxy of the environment is not used", func(t *testing.T) {
		t.Setenv("HTTP_PROXY", "http://192.0.2.1:3128")
		h, _ := fixtureEngine(t, filepath.Join("testdata", "docker-29"))
		_, err := New(serve(t, h)).Ping(t.Context())
		require.NoError(t, err)
	})
	t.Run("odd fields cost only themselves", func(t *testing.T) {
		c := New(serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/info":
				fmt.Fprint(w, `{"ServerVersion": 28, "FirewallBackend": {"Driver": "nftables"}, "SecurityOptions": "x"}`)
			case "/containers/json":
				fmt.Fprint(w, `[{"Names": ["/a"], "Ports": [{"IP": "0.0.0.0", "PublicPort": 80, "PrivatePort": 80, "Type": "tcp"}]}, {"Names": 7}]`)
			}
		})))
		info, err := c.Info(t.Context()) // no Ping: unversioned paths
		require.NoError(t, err)
		assert.Equal(t, Info{FirewallBackend: "nftables"}, info)
		list, skipped, err := c.Containers(t.Context())
		require.NoError(t, err)
		assert.Len(t, list, 1)
		assert.Equal(t, 1, skipped)
	})
}
