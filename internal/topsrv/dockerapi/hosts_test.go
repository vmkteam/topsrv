package dockerapi

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParseHost follows ParseDaemonHost of moby (opts/hosts_test.go).
func TestParseHost(t *testing.T) {
	cases := []struct {
		in   string
		want string // "" for an error
	}{
		{"fd://", "fd://"},
		{"fd://3", "fd://3"},
		{"unix://", "unix:///var/run/docker.sock"},
		{"unix:///run/docker.sock", "unix:///run/docker.sock"},
		{"tcp://0.0.0.0:2375", "tcp://0.0.0.0:2375"},
		{"tcp://:2375", "tcp://localhost:2375"},
		{"tcp://", "tcp://localhost:2375"},
		{"tcp://[::]:2376", "tcp://[::]:2376"},
		{"tcp://192.0.2.1", "tcp://192.0.2.1:2375"},
		{"0.0.0.0:2375", "tcp://0.0.0.0:2375"}, // no scheme: TCP
		{":2375", "tcp://localhost:2375"},
		{" tcp://host.test.local:2376 ", "tcp://host.test.local:2376"},
		{"tcp://0.0.0.0:2375/path", ""},
		{"tcp://0.0.0.0:0", ""},
		{"tcp://0.0.0.0:99999", ""},
		{"tcp://u:SENTINEL@host:2375", "tcp://host:2375"}, // dockerd ignores the user part
		{"unix://tcp://x", ""},
		{"ssh://host", ""}, // a client address
		{"bogus://x", ""},
	}
	for _, tc := range cases {
		h, err := ParseHost(tc.in)
		if tc.want == "" {
			require.Error(t, err, tc.in)
			continue
		}
		require.NoError(t, err, tc.in)
		assert.Equal(t, tc.want, h.String(), tc.in)
	}
}

func TestListenStreamHost(t *testing.T) {
	for in, want := range map[string]string{
		"/run/docker.sock": "unix:///run/docker.sock",
		"@docker":          "unix://@docker",
		"2375":             "tcp://[::]:2375", // a port alone: every address
		"127.0.0.1:2375":   "tcp://127.0.0.1:2375",
		"[::1]:2375":       "tcp://[::1]:2375",
	} {
		h, err := ListenStreamHost(in)
		require.NoError(t, err, in)
		assert.Equal(t, want, h.String(), in)
	}
	_, err := ListenStreamHost("")
	assert.Error(t, err)
}

func TestDefaultHosts(t *testing.T) {
	assert.Equal(t, "unix:///var/run/docker.sock", DefaultHosts(false)[0].String())
	assert.Equal(t, "tcp://localhost:2376", DefaultHosts(true)[0].String(), "--tls without -H")
}
