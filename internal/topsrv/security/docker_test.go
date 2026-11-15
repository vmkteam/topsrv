package security

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vmkteam/topsrv/internal/topsrv/dockerapi"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// dockerFixture is a Debian host with docker-ce: dockerd started by its
// unit with -H fd://, docker.socket listening on /run/docker.sock.
func dockerFixture() map[string]string {
	return merge(hostProc(), map[string]string{
		"proc/1/ns/mnt":                    "-> mnt:[4026531841]",
		"proc/300/exe":                     "-> /usr/bin/dockerd",
		"proc/300/ns/mnt":                  "-> mnt:[4026531841]",
		"proc/300/ns/net":                  "-> net:[4026531840]",
		"proc/300/cmdline":                 "/usr/bin/dockerd\x00-H\x00fd://\x00--containerd=/run/containerd/containerd.sock\x00",
		"proc/300/stat":                    "300 (dockerd) S 1 300 300 0 -1 4194560 2000 0 0 0 1 2 0 0 20 0 1 0 1234500 10000000 2000\n",
		"proc/stat":                        "cpu 1 2 3\nbtime 1794700000\n",
		"usr/bin/dockerd":                  "",
		"run/":                             "",
		"etc/docker/daemon.json":           `{"iptables": true, "userland-proxy": false, "live-restore": true, "log-driver": "journald"}`,
		"lib/systemd/system/docker.socket": "[Socket]\nListenStream=/run/docker.sock\nSocketMode=0660\nSocketGroup=docker\n",
	})
}

// engineHandler serves the answers a dockerd version gave, from the
// fixtures of dockerapi.
func engineHandler(t *testing.T, version string) http.Handler {
	t.Helper()
	dir := filepath.Join("..", "dockerapi", "testdata", "docker-"+version)
	headers, err := os.ReadFile(filepath.Join(dir, "ping.headers"))
	require.NoError(t, err)
	api := ""
	for line := range strings.SplitSeq(string(headers), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), ":"); ok && strings.EqualFold(k, "Api-Version") {
			api = strings.TrimSpace(v)
		}
	}
	info, err := os.ReadFile(filepath.Join(dir, "info.json"))
	require.NoError(t, err)
	containers, err := os.ReadFile(filepath.Join(dir, "containers.json"))
	require.NoError(t, err)
	return apiHandler(t, api, string(info), string(containers))
}

func apiHandler(t *testing.T, api, info, containers string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /_ping", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Api-Version", api)
		reply(t, w, "OK")
	})
	mux.HandleFunc("GET /v"+api+"/info", func(w http.ResponseWriter, _ *http.Request) { reply(t, w, info) })
	mux.HandleFunc("GET /v"+api+"/containers/json", func(w http.ResponseWriter, _ *http.Request) { reply(t, w, containers) })
	return mux
}

func reply(t *testing.T, w http.ResponseWriter, body string) {
	if _, err := fmt.Fprint(w, body); err != nil {
		t.Errorf("test dockerd: %v", err)
	}
}

// serveDocker runs h on a real socket at the fixture's /run/docker.sock
// and points the section at it. The socket is made from inside the
// fixture's /run: its full path would pass the 104 bytes a socket address
// takes on macOS.
func serveDocker(t *testing.T, sc *scanCtx, h http.Handler) {
	t.Helper()
	t.Chdir(filepath.Join(sc.root, "run"))
	l, err := net.Listen("unix", "docker.sock")
	require.NoError(t, err)
	srv := &http.Server{Handler: h, ReadHeaderTimeout: time.Second}
	go func() {
		if err := srv.Serve(l); !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("test dockerd: %v", err)
		}
	}()
	t.Cleanup(func() { srv.Close() })
	sc.dockerClient = func(path string) *dockerapi.Client {
		assert.Equal(t, sc.root+"/run/docker.sock", path, "the socket the section chose")
		return dockerapi.New("docker.sock")
	}
}

func dockerOf(t *testing.T, sc *scanCtx) (Section, dockerData) {
	t.Helper()
	sec := collectDocker(t.Context(), sc)
	d, _ := sec.Data.(dockerData)
	return sec, d
}

func TestDocker(t *testing.T) {
	sc := fixture(t, dockerFixture())
	serveDocker(t, sc, engineHandler(t, "29"))
	sec, d := dockerOf(t, sc)

	require.Equal(t, StatusOK, sec.Status, "gaps: %v", sec.Gaps)
	assert.Equal(t, "docker", d.Engine)
	require.NotNil(t, d.DaemonStartedAt)
	assert.Equal(t, "29.9.3", *d.Version)
	assert.Equal(t, "1.56", *d.APIVersion)
	assert.Equal(t, "iptables", *d.FirewallBackend)
	assert.Equal(t, []string{"seccomp", "cgroupns"}, d.SecurityOptions)
	assert.Equal(t, 3, *d.ContainersRunning)
	assert.Equal(t, []dockerHost{
		{Proto: "fd", Addr: "", Source: dockerapi.SourceCmdline},
		{Proto: "unix", Addr: "/run/docker.sock", Source: dockerapi.SourceSocketUnit},
	}, d.Hosts)
	require.NotNil(t, d.Socket)
	assert.Equal(t, "/run/docker.sock", d.Socket.Path)

	c := d.Config
	require.NotNil(t, c.File)
	assert.True(t, c.File.Valid)
	assert.Equal(t, dockerapi.DefaultConfigFile, c.File.Path)
	assert.True(t, *c.IPTables)
	assert.False(t, *c.UserlandProxy)
	assert.True(t, *c.LiveRestore)
	assert.Nil(t, c.IP6Tables, "not set: the version's default")

	assert.Equal(t, []dockerPort{
		{Container: "v6only", IP: "::", PublicPort: 8443, PrivatePort: 443, Type: "tcp"},
		{Container: "web", IP: "0.0.0.0", PublicPort: 5353, PrivatePort: 53, Type: "udp"},
		{Container: "web", IP: "::", PublicPort: 5353, PrivatePort: 53, Type: "udp"},
		{Container: "web", IP: "0.0.0.0", PublicPort: 8080, PrivatePort: 80, Type: "tcp"},
		{Container: "web", IP: "::", PublicPort: 8080, PrivatePort: 80, Type: "tcp"},
		{Container: "web", IP: "127.0.0.1", PublicPort: 9000, PrivatePort: 9000, Type: "tcp"},
	}, d.Published, "internal publishes nothing")
	assert.False(t, d.PublishedTruncated)

	t.Run("before API 1.49: no firewall backend", func(t *testing.T) {
		sc := fixture(t, dockerFixture())
		serveDocker(t, sc, apiHandler(t, "1.47", `{"ServerVersion": "27.5.1", "FirewallBackend": null}`, `[]`))
		sec, d := dockerOf(t, sc)
		require.Equal(t, StatusOK, sec.Status, "gaps: %v", sec.Gaps)
		assert.Nil(t, d.FirewallBackend, "iptables then, not reported")
		assert.Equal(t, []dockerPort{}, d.Published, "read, nothing published")
	})
}

func TestDockerAbsent(t *testing.T) {
	t.Run("no dockerd: the socket is not touched", func(t *testing.T) {
		files := dockerFixture()
		delete(files, "proc/300/exe")
		delete(files, "proc/300/cmdline")
		sc := fixture(t, files)
		sc.dockerClient = func(string) *dockerapi.Client { t.Fatal("socket-activated: never dial"); return nil }
		sec, _ := dockerOf(t, sc)
		assert.Equal(t, StatusNA, sec.Status)
	})
	t.Run("dockerd of another network namespace", func(t *testing.T) {
		sc := fixture(t, merge(dockerFixture(), map[string]string{"proc/300/ns/net": "-> net:[4026532999]"}))
		sec, _ := dockerOf(t, sc)
		assert.Equal(t, StatusNA, sec.Status, "docker-in-docker publishes nothing on the host")
	})
	t.Run("a dockerd others may change", func(t *testing.T) {
		sc := fixture(t, dockerFixture())
		require.NoError(t, os.Chmod(filepath.Join(sc.root, "usr/bin/dockerd"), 0o777))
		sec, _ := dockerOf(t, sc)
		assert.Equal(t, StatusNA, sec.Status, "not trusted: its -H and daemon.json are not read")
	})
	t.Run("processes hidden", func(t *testing.T) {
		sc := fixture(t, dockerFixture())
		for _, pid := range []string{"1", "300"} { // hidepid=2: root's processes are not listed
			require.NoError(t, os.RemoveAll(filepath.Join(sc.root, "proc", pid)))
		}
		sec, _ := dockerOf(t, sc)
		assert.Equal(t, unknown(ReasonPermissionDenied), sec, "absence is not known")
	})
}

func TestDockerSocket(t *testing.T) {
	t.Run("no socket: the configuration still", func(t *testing.T) {
		sc := fixture(t, dockerFixture())
		sec, d := dockerOf(t, sc)
		assert.Equal(t, StatusPartial, sec.Status)
		assert.Equal(t, []Gap{{Path: "/run/docker.sock", Reason: ReasonNotFound}}, sec.Gaps)
		assert.True(t, *d.Config.IPTables)
		assert.Nil(t, d.Socket)
		assert.Nil(t, d.Published, "null: not read")
	})
	t.Run("not a socket", func(t *testing.T) {
		sc := fixture(t, merge(dockerFixture(), map[string]string{"run/docker.sock": "a file"}))
		sc.dockerClient = func(string) *dockerapi.Client { t.Fatal("never dial a file"); return nil }
		sec, _ := dockerOf(t, sc)
		assert.Equal(t, []Gap{{Path: "/run/docker.sock", Reason: ReasonNotRegular}}, sec.Gaps)
	})
	t.Run("an entry of an odd shape", func(t *testing.T) {
		sc := fixture(t, dockerFixture())
		serveDocker(t, sc, apiHandler(t, "1.51", `{"ServerVersion": "28.5.2"}`,
			`[{"Names": 7}, {"Names": ["/web"], "Ports": [{"IP": "0.0.0.0", "PrivatePort": 80, "PublicPort": 8080, "Type": "tcp"}]}]`))
		sec, d := dockerOf(t, sc)
		assert.Equal(t, []Gap{{Path: "/run/docker.sock", Reason: ReasonParseError}}, sec.Gaps, "the list is not complete")
		assert.Len(t, d.Published, 1, "the rest is kept")
	})
	t.Run("a daemon that refuses", func(t *testing.T) {
		sc := fixture(t, dockerFixture())
		serveDocker(t, sc, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusForbidden) }))
		sec, d := dockerOf(t, sc)
		assert.Equal(t, []Gap{{Path: "/run/docker.sock", Reason: ReasonPermissionDenied}}, sec.Gaps, "an authorization plugin")
		assert.NotNil(t, d.Socket)
		assert.Nil(t, d.Version)
	})
}

func TestDockerHosts(t *testing.T) {
	cases := []struct {
		name    string
		cmdline string
		config  string
		noUnit  bool
		want    []dockerHost
	}{
		{"-H wins over daemon.json", "dockerd\x00-H\x00unix:///var/run/docker.sock\x00-H\x00tcp://0.0.0.0:2375\x00", `{"hosts": ["tcp://:2376"]}`, true,
			[]dockerHost{{"unix", "/var/run/docker.sock", dockerapi.SourceCmdline}, {"tcp", "0.0.0.0:2375", dockerapi.SourceCmdline}}},
		{"hosts of daemon.json", "dockerd\x00", `{"hosts": ["unix://", "tcp://:2376"]}`, true,
			[]dockerHost{{"unix", "/var/run/docker.sock", dockerapi.SourceConfig}, {"tcp", "localhost:2376", dockerapi.SourceConfig}}},
		{"neither", "dockerd\x00", `{}`, true, []dockerHost{{"unix", "/var/run/docker.sock", dockerapi.SourceDefault}}},
		{"--tls alone: TCP", "dockerd\x00--tls\x00", `{}`, true, []dockerHost{{"tcp", "localhost:2376", dockerapi.SourceDefault}}},
		{"an address dockerd refuses", "dockerd\x00-H\x00ssh://host\x00", `{}`, true, []dockerHost{{Proto: valueInvalid, Source: dockerapi.SourceCmdline}}},
		{"docker.socket on TCP too", "dockerd\x00-H\x00fd://\x00", `{}`, false,
			[]dockerHost{{"fd", "", dockerapi.SourceCmdline}, {"unix", "/run/docker.sock", dockerapi.SourceSocketUnit}, {"tcp", "[::]:2375", dockerapi.SourceSocketUnit}}},
		{"fd:// without the unit", "dockerd\x00-H\x00fd://\x00", `{}`, true,
			[]dockerHost{{"fd", "", dockerapi.SourceCmdline}, {"unix", "/run/docker.sock", dockerapi.SourceDefault}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			files := merge(dockerFixture(), map[string]string{"proc/300/cmdline": tc.cmdline, "etc/docker/daemon.json": tc.config})
			if tc.noUnit {
				delete(files, "lib/systemd/system/docker.socket")
			} else {
				files["etc/systemd/system/docker.socket.d/tcp.conf"] = "[Socket]\nListenStream=2375\n"
			}
			_, d := dockerOf(t, fixture(t, files))
			assert.Equal(t, tc.want, d.Hosts)
		})
	}
}

func TestDockerConfig(t *testing.T) {
	t.Run("--config-file, values of a form dockerd refuses", func(t *testing.T) {
		sc := fixture(t, merge(dockerFixture(), map[string]string{
			"proc/300/cmdline": "dockerd\x00--config-file\x00/srv/docker.json\x00--iptables=false\x00",
			"srv/docker.json":  `{"firewall-backend": "SENTINEL", "ip": "SENTINEL", "userns-remap": "dockremap", "icc": "no"}`,
		}))
		_, d := dockerOf(t, sc)
		c := d.Config
		require.NotNil(t, c.File)
		assert.Equal(t, "/srv/docker.json", c.File.Path)
		assert.False(t, c.File.Valid, `"icc": "no" stops dockerd`)
		assert.False(t, *c.IPTables, "the flag")
		assert.Equal(t, valueInvalid, *c.FirewallBackend)
		assert.Equal(t, valueInvalid, *c.DefaultBindIP)
		assert.True(t, c.UsernsRemap, "set; the user is not sent")
		assert.NotContains(t, toJSON(t, d), "SENTINEL")
		assert.NotContains(t, toJSON(t, d), "dockremap")
	})
	t.Run("no daemon.json", func(t *testing.T) {
		files := dockerFixture()
		delete(files, "etc/docker/daemon.json")
		_, d := dockerOf(t, fixture(t, files))
		assert.Nil(t, d.Config.File)
	})
}

func TestDockerAPIValues(t *testing.T) {
	ports := make([]string, 0, maxPublished+1)
	for i := range maxPublished + 1 {
		ports = append(ports, fmt.Sprintf(`{"IP": "0.0.0.0", "PrivatePort": 80, "PublicPort": %d, "Type": "tcp"}`, 1000+i))
	}
	containers := `[
		{"Names": ["/SENTINEL web"], "Image": "registry.example.com/SENTINEL", "Command": "/bin/SENTINEL --token SENTINELSECRET",
		 "Labels": {"secret": "SENTINELSECRET"}, "Ports": [{"IP": "SENTINEL", "PrivatePort": 1, "PublicPort": 2, "Type": "SENTINEL"}]},
		{"Names": ["/exposed"], "Ports": [{"IP": "", "PrivatePort": 9009, "Type": "tcp"}]},
		{"Names": ["/many"], "Ports": [` + strings.Join(ports, ",") + `]}
	]`
	sc := fixture(t, dockerFixture())
	serveDocker(t, sc, apiHandler(t, "1.51", `{"ServerVersion": "SENTINEL 1", "SecurityOptions": ["name=SENTINEL VALUE"],
		"FirewallBackend": {"Driver": "nftables"}, "Name": "SENTINEL"}`, containers))
	sec, d := dockerOf(t, sc)
	require.Equal(t, StatusOK, sec.Status, "gaps: %v", sec.Gaps)
	assert.Equal(t, valueInvalid, *d.Version)
	assert.Equal(t, []string{valueInvalid}, d.SecurityOptions)
	assert.Equal(t, "nftables", *d.FirewallBackend)
	assert.Equal(t, dockerPort{Container: valueInvalid, IP: valueInvalid, PublicPort: 2, PrivatePort: 1, Type: valueInvalid}, d.Published[0],
		"sorted first; an EXPOSE without -p (\"exposed\") is not published")
	assert.Len(t, d.Published, maxPublished)
	assert.True(t, d.PublishedTruncated)
	assert.NotContains(t, strings.ToUpper(toJSON(t, d)), "SENTINEL")
}
