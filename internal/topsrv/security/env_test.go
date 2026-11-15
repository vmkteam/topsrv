package security

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnvironment(t *testing.T) {
	cases := []struct {
		name   string
		files  map[string]string
		want   envData
		status Status
	}{
		{
			name:  "host with systemd and glibc",
			files: merge(hostProc(), map[string]string{"lib64/ld-linux-x86-64.so.2": "", "run/systemd/system/": ""}),
			want:  envData{UserNsHost: true, PidNsHost: true, RootIsHostRoot: true, NetNsHost: true, ContainerKind: containerNone, Libc: "glibc", Init: "systemd"},
		},
		{
			name:  "KVM guest: the hypervisor name is sent, the DMI strings are not",
			files: merge(hostProc(), cpu(cpuinfoGuest, kvmClock), dmi("SENTINEL-1234", "QEMU"), map[string]string{"run/systemd/system/": ""}),
			want:  envData{UserNsHost: true, PidNsHost: true, RootIsHostRoot: true, NetNsHost: true, ContainerKind: containerNone, Virt: virtKVM, Libc: "unknown", Init: "systemd"},
		},
		{
			name: "Alpine host with openrc and musl",
			files: merge(hostProc(), map[string]string{
				"proc/1/comm":             "init\n",
				"run/openrc/":             "",
				"lib/ld-musl-x86_64.so.1": "",
			}),
			want: envData{UserNsHost: true, PidNsHost: true, RootIsHostRoot: true, NetNsHost: true, ContainerKind: containerNone, Libc: "musl", Init: "openrc"},
		},
		{
			name: "docker container",
			files: merge(hostProc(), map[string]string{
				"proc/self/ns/pid": "-> pid:[4026532501]",
				"proc/1/comm":      "topsrv\n",
				".dockerenv":       "",
			}),
			want: envData{UserNsHost: true, ContainerKind: containerDocker, NetNsHost: true, Libc: "unknown", Init: "other"},
		},
		{
			name: "systemd marker wins over a stray .dockerenv",
			files: merge(hostProc(), map[string]string{
				"proc/self/ns/pid":      "-> pid:[4026532501]",
				"run/systemd/container": "lxc\n",
				".dockerenv":            "",
			}),
			want: envData{UserNsHost: true, ContainerKind: containerLXC, NetNsHost: true, Libc: "unknown", Init: "systemd"},
		},
		{
			name: "container= in the environment of PID 1, other variables ignored",
			files: merge(hostProc(), map[string]string{
				"proc/self/ns/pid": "-> pid:[4026532501]",
				"proc/1/environ":   "LD_PRELOAD=/SENTINEL.so\x00container=systemd-nspawn\x00HOME=/",
			}),
			want: envData{UserNsHost: true, ContainerKind: containerNspawn, NetNsHost: true, Libc: "unknown", Init: "systemd"},
		},
		{
			name: "podman",
			files: merge(hostProc(), map[string]string{
				"proc/self/ns/pid":  "-> pid:[4026532501]",
				"run/.containerenv": "",
				"proc/1/comm":       "sh\n",
			}),
			want: envData{UserNsHost: true, ContainerKind: containerPodman, NetNsHost: true, Libc: "unknown", Init: "other"},
		},
		{
			name: "k8s pod",
			files: merge(hostProc(), map[string]string{
				"proc/self/ns/pid": "-> pid:[4026532501]",
				"proc/1/comm":      "pause\n",
				"var/run/secrets/kubernetes.io/serviceaccount/": "",
			}),
			want: envData{UserNsHost: true, ContainerKind: containerK8s, NetNsHost: true, Libc: "unknown", Init: "other"},
		},
		{
			name: "--pid=host container: same pid namespace, another root",
			files: merge(hostProc(), map[string]string{
				"proc/1/root": "-> /",
				".dockerenv":  "",
			}),
			want: envData{UserNsHost: true, PidNsHost: true, ContainerKind: containerDocker, NetNsHost: true, Libc: "unknown", Init: "systemd"},
		},
		{
			name: "own net namespace",
			files: merge(hostProc(), map[string]string{
				"proc/self/ns/net": "-> net:[4026532600]",
			}),
			want: envData{UserNsHost: true, PidNsHost: true, RootIsHostRoot: true, ContainerKind: containerNone, Libc: "unknown", Init: "systemd"},
		},
		{
			name: "container=oci (UBI images) does not end the search",
			files: merge(hostProc(), map[string]string{
				"proc/self/ns/pid": "-> pid:[4026532501]",
				"proc/1/environ":   "container=oci\x00",
				".dockerenv":       "",
			}),
			want: envData{UserNsHost: true, ContainerKind: containerDocker, NetNsHost: true, Libc: "unknown", Init: "systemd"},
		},
		{
			name: "another pid namespace without any marker",
			files: merge(hostProc(), map[string]string{
				"proc/self/ns/pid": "-> pid:[4026532501]",
				"proc/1/environ":   "container=oci\x00",
			}),
			want: envData{UserNsHost: true, ContainerKind: containerUnknown, NetNsHost: true, Libc: "unknown", Init: "systemd"},
		},
		{
			name: "OpenVZ container",
			files: merge(hostProc(), map[string]string{
				"proc/self/ns/pid": "-> pid:[4026532501]",
				"proc/vz/":         "",
			}),
			want: envData{UserNsHost: true, ContainerKind: containerOpenVZ, NetNsHost: true, Libc: "unknown", Init: "systemd"},
		},
		{
			name:  "OpenVZ host: /proc/bc is there",
			files: merge(hostProc(), map[string]string{"proc/vz/": "", "proc/bc/": ""}),
			want:  envData{UserNsHost: true, PidNsHost: true, RootIsHostRoot: true, NetNsHost: true, ContainerKind: containerNone, Libc: "unknown", Init: "systemd"},
		},
		{
			name: "unprivileged container: another user namespace",
			files: merge(hostProc(), map[string]string{
				"proc/self/ns/pid":  "-> pid:[4026532501]",
				"proc/self/ns/user": "-> user:[4026532700]",
				"proc/1/environ":    "container=lxc\x00",
			}),
			want: envData{ContainerKind: containerLXC, NetNsHost: true, Libc: "unknown", Init: "systemd"},
		},
		{
			name: "both loaders on Debian: the musl package",
			files: merge(hostProc(), map[string]string{
				"lib/ld-musl-x86_64.so.1":    "",
				"lib64/ld-linux-x86-64.so.2": "",
				"etc/os-release":             "PRETTY_NAME=\"Debian GNU/Linux 12\"\nID=debian\n",
			}),
			want: envData{UserNsHost: true, PidNsHost: true, RootIsHostRoot: true, NetNsHost: true, ContainerKind: containerNone, Libc: "glibc", Init: "systemd"},
		},
		{
			name: "both loaders on Alpine: gcompat",
			files: merge(hostProc(), map[string]string{
				"lib/ld-musl-x86_64.so.1":    "",
				"lib64/ld-linux-x86-64.so.2": "",
				"etc/os-release":             "ID=alpine\n",
			}),
			want: envData{UserNsHost: true, PidNsHost: true, RootIsHostRoot: true, NetNsHost: true, ContainerKind: containerNone, Libc: "musl", Init: "systemd"},
		},
		{
			name: "PID 1 namespaces unreadable",
			files: map[string]string{
				"proc/self/ns/pid": "-> pid:[4026531836]",
				"proc/self/ns/net": "-> net:[4026531840]",
			},
			want:   envData{PidNsHost: true, ContainerKind: containerUnknown, Libc: "unknown", Init: "other"},
			status: StatusPartial,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.want.Virt == "" {
				tc.want.Virt = virtNone // no DMI or cpuinfo in these fixtures
			}
			sec, env := collectEnvironment(fixture(t, tc.files))

			assert.Equal(t, tc.want, env)
			want := tc.status
			if want == "" {
				want = StatusOK
			}
			assert.Equal(t, want, sec.Status, "gaps: %v", sec.Gaps)
			assert.NotContains(t, toJSON(t, sec), "SENTINEL")
		})
	}

	t.Run("no /proc: unknown", func(t *testing.T) {
		sec, env := collectEnvironment(fixture(t, nil))
		assert.Equal(t, StatusUnknown, sec.Status)
		assert.Equal(t, ReasonNotFound, sec.Reason)
		assert.Equal(t, containerUnknown, env.ContainerKind)
	})
}

func TestAppContainer(t *testing.T) {
	assert.True(t, envData{ContainerKind: containerDocker}.appContainer())
	assert.True(t, envData{ContainerKind: containerK8s}.appContainer())
	assert.True(t, envData{ContainerKind: containerPodman}.appContainer())
	assert.False(t, envData{ContainerKind: containerDocker, RootIsHostRoot: true}.appContainer(), "the host root is visible")
	assert.False(t, envData{ContainerKind: containerLXC}.appContainer(), "a system container is a machine")
	assert.False(t, envData{ContainerKind: containerNone}.appContainer())
	assert.True(t, envData{ContainerKind: containerUnknown}.appContainer(), "another pid namespace, no marker")
	assert.False(t, envData{ContainerKind: containerUnknown, PidNsHost: true}.appContainer(), "the host pid namespace")
	assert.False(t, envData{ContainerKind: containerOpenVZ}.appContainer(), "a system container")
}

func TestAgentInfo(t *testing.T) {
	a, err := readAgent(fixture(t, map[string]string{
		"proc/self/status": "Name:\ttopsrv\nUid:\t1000\t998\t998\t998\nCapEff:\t0000000000081004\n",
	}))
	require.NoError(t, err)
	assert.Equal(t, 998, a.UID, "the effective uid")
	assert.Equal(t, []string{"CAP_DAC_READ_SEARCH", "CAP_NET_ADMIN", "CAP_SYS_PTRACE"}, a.CapEff)

	assert.Equal(t, []string{"CAP_CHOWN", "CAP_41"}, bitNames(1|1<<41, capabilities, "CAP_"))
}
