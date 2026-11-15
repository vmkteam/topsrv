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

func TestResolveHosts(t *testing.T) {
	type rh struct{ host, source string }
	resolve := func(flags, file Settings, listens ...string) []rh {
		hosts := ResolveHosts(flags, file, listens)
		out := make([]rh, 0, len(hosts))
		for _, h := range hosts {
			s := h.String()
			if h.Err != nil {
				s = "invalid"
			}
			out = append(out, rh{s, h.Source})
		}
		return out
	}
	cases := []struct {
		name        string
		flags, file Settings
		listens     []string
		want        []rh
	}{
		{"-H wins", Settings{Hosts: []string{"unix:///var/run/docker.sock", "tcp://0.0.0.0:2375"}}, Settings{Hosts: []string{"tcp://:2376"}}, nil,
			[]rh{{"unix:///var/run/docker.sock", SourceCmdline}, {"tcp://0.0.0.0:2375", SourceCmdline}}},
		{"hosts of daemon.json", Settings{}, Settings{Hosts: []string{"unix://", "tcp://:2376"}}, nil,
			[]rh{{"unix:///var/run/docker.sock", SourceConfig}, {"tcp://localhost:2376", SourceConfig}}},
		{`"hosts": [] is the default`, Settings{}, Settings{Hosts: []string{}}, nil, []rh{{"unix:///var/run/docker.sock", SourceDefault}}},
		{"blank -H is dropped", Settings{Hosts: []string{" "}}, Settings{}, nil, []rh{{"unix:///var/run/docker.sock", SourceDefault}}},
		{"--tls alone", Settings{TLS: new(true)}, Settings{}, nil, []rh{{"tcp://localhost:2376", SourceDefault}}},
		{"--tlsverify=false still means TLS", Settings{TLSVerify: new(false)}, Settings{}, nil, []rh{{"tcp://localhost:2376", SourceDefault}}},
		{`"tls": true of daemon.json`, Settings{}, Settings{TLS: new(true)}, nil, []rh{{"tcp://localhost:2376", SourceDefault}}},
		{`"tlsverify" of daemon.json alone does not`, Settings{}, Settings{TLSVerify: new(true)}, nil,
			[]rh{{"unix:///var/run/docker.sock", SourceDefault}}},
		{"in input order", Settings{Hosts: []string{"tcp://ok:1", "ssh://x"}}, Settings{}, nil,
			[]rh{{"tcp://ok:1", SourceCmdline}, {"invalid", SourceCmdline}}},
		{"fd:// with the socket unit", Settings{Hosts: []string{"fd://"}}, Settings{}, []string{"/run/docker.sock", "2375"},
			[]rh{{"fd://", SourceCmdline}, {"unix:///run/docker.sock", SourceSocketUnit}, {"tcp://[::]:2375", SourceSocketUnit}}},
		{"fd:// without it", Settings{Hosts: []string{"fd://"}}, Settings{}, nil,
			[]rh{{"fd://", SourceCmdline}, {"unix:///run/docker.sock", SourceDefault}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, resolve(tc.flags, tc.file, tc.listens...))
		})
	}
}

func TestSocket(t *testing.T) {
	hosts := ResolveHosts(Settings{Hosts: []string{"tcp://0.0.0.0:2375", "unix://@abstract", "fd://"}}, Settings{}, []string{"/run/docker.sock"})
	h, ok := Socket(hosts)
	require.True(t, ok)
	assert.Equal(t, "/run/docker.sock", h.Addr, "the first unix socket with a path")
	assert.True(t, h.Systemd, "created by systemd, in the host's mount namespace")

	h, ok = Socket(ResolveHosts(Settings{Hosts: []string{"unix:///var/run/docker.sock"}}, Settings{}, nil))
	require.True(t, ok)
	assert.False(t, h.Systemd, "dockerd's own")
	_, ok = Socket(ResolveHosts(Settings{Hosts: []string{"tcp://0.0.0.0:2375"}}, Settings{}, nil))
	assert.False(t, ok)
}
