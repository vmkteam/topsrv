package dockerapi

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseArgs(t *testing.T) {
	cases := []struct {
		name string
		line string
		want Settings
	}{
		{"Debian and RHEL unit", "/usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock",
			Settings{Hosts: []string{"fd://"}}},
		{"API on TCP, firewall off", "dockerd -H unix:///run/docker.sock --host=tcp://0.0.0.0:2375 --iptables=false " +
			"--userland-proxy=false --ip 127.0.0.1 --config-file /etc/docker/custom.json --tlsverify",
			Settings{Hosts: []string{"unix:///run/docker.sock", "tcp://0.0.0.0:2375"}, ConfigFile: "/etc/docker/custom.json",
				IPTables: new(false), UserlandProxy: new(false), DefaultBindIP: new("127.0.0.1"), TLSVerify: new(true)}},
		{"shorthand forms", "dockerd -Htcp://:2376 -H=fd:// --tls",
			Settings{Hosts: []string{"tcp://:2376", "fd://"}, TLS: new(true)}},
		{"a value of an unknown flag is not a flag", "dockerd --data-root /srv/docker --log-opt max-size=10m -H fd:// --firewall-backend nftables",
			Settings{Hosts: []string{"fd://"}, FirewallBackend: new("nftables")}},
		{"secrets elsewhere are not kept", "dockerd --tlskey /etc/SENTINEL.key --registry-mirror https://u:SENTINELSECRET@example.com --icc=0",
			Settings{ICC: new(false)}},
		{"a bool dockerd refuses", "dockerd --iptables=maybe", Settings{}},
		{"after --", "dockerd -- -H fd://", Settings{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, ParseArgs(strings.Fields(tc.line)))
		})
	}
}

func TestParseConfig(t *testing.T) {
	s, err := ParseConfig([]byte(`{
		"hosts": ["unix:///var/run/docker.sock", "tcp://0.0.0.0:2376"],
		"tls": true, "tlsverify": true, "tlskey": "/etc/SENTINEL.key",
		"userland-proxy": false, "iptables": true, "ip6tables": true, "firewall-backend": "nftables",
		"allow-direct-routing": false, "icc": false, "no-new-privileges": true, "live-restore": true,
		"userns-remap": "default", "ip": "127.0.0.1",
		"registry-mirrors": ["https://u:SENTINELSECRET@example.com"]
	}`))
	require.NoError(t, err)
	assert.Equal(t, Settings{
		Hosts: []string{"unix:///var/run/docker.sock", "tcp://0.0.0.0:2376"}, TLS: new(true), TLSVerify: new(true),
		UserlandProxy: new(false), IPTables: new(true), IP6Tables: new(true), FirewallBackend: new("nftables"),
		AllowDirectRouting: new(false), ICC: new(false), NoNewPrivileges: new(true), LiveRestore: new(true),
		UsernsRemap: new("default"), DefaultBindIP: new("127.0.0.1"),
	}, s)

	t.Run("a value of the wrong type", func(t *testing.T) {
		s, err := ParseConfig([]byte(`{"iptables": "false", "icc": null, "live-restore": true}`))
		require.ErrorIs(t, err, errConfigType, "dockerd refuses the file")
		assert.Equal(t, Settings{LiveRestore: new(true)}, s, "the rest is read")
	})
	t.Run("not JSON", func(t *testing.T) {
		_, err := ParseConfig([]byte(`{"iptables": false,}`))
		require.Error(t, err)
	})
}

func TestMerge(t *testing.T) {
	flags := Settings{Hosts: []string{"fd://"}, IPTables: new(false)}
	file := Settings{Hosts: []string{"tcp://0.0.0.0:2375"}, IPTables: new(true), UserlandProxy: new(false)}
	assert.Equal(t, Settings{Hosts: []string{"fd://"}, IPTables: new(false), UserlandProxy: new(false)}, Merge(flags, file))
	assert.Equal(t, []string{"tcp://0.0.0.0:2375"}, Merge(Settings{}, file).Hosts)
}
