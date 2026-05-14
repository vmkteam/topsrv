package nginx

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDiscoverAngieEdgeCases(t *testing.T) {
	cases := []struct {
		name         string
		conf         string
		wantAPI      string
		wantAPIPort  int
		wantAPIHost  string
		wantStub     string
		wantStubPort int
		wantStubHost string
		wantLogs     int
		wantFormats  int
	}{
		{
			name: "api on non-standard path",
			conf: `http {
    server {
        listen 9090;
        location /monitoring/ {
            api /api/v1/status/;
        }
    }
}`,
			wantAPI: "/api/v1/status/", wantAPIPort: 9090,
		},
		{
			name: "listen with IP:port",
			conf: `http {
    server {
        listen 127.0.0.1:8080;
        location /status/ {
            api /status/;
        }
    }
}`,
			wantAPI: "/status/", wantAPIPort: 8080, wantAPIHost: "127.0.0.1",
		},
		{
			name: "listen with IP:port and ssl param",
			conf: `http {
    server {
        listen 10.0.0.1:8443 ssl;
        location /status/ {
            api /status/;
        }
    }
}`,
			wantAPI: "/status/", wantAPIPort: 8443, wantAPIHost: "10.0.0.1",
		},
		{
			name: "listen with non-loopback IP",
			conf: `http {
    server {
        listen 10.10.1.1:81;
        location /status/ {
            api /status/;
        }
    }
}`,
			wantAPI: "/status/", wantAPIPort: 81, wantAPIHost: "10.10.1.1",
		},
		{
			name: "commented out api — should NOT match",
			conf: `http {
    server {
        listen 8080;
        location /status/ {
            # api /status/;
        }
    }
}`,
			wantAPI: "", wantAPIPort: 0,
		},
		{
			name: "api without trailing slash",
			conf: `http {
    server {
        listen 8080;
        location /status {
            api /status;
        }
    }
}`,
			wantAPI: "/status", wantAPIPort: 8080,
		},
		{
			name: "multiple listen — non-ssl wins over ssl",
			conf: `http {
    server {
        listen 80;
        listen 443 ssl;
        location /status/ {
            api /status/;
        }
    }
}`,
			wantAPI: "/status/", wantAPIPort: 80,
		},
		{
			name: "ssl listen declared first — non-ssl still wins",
			conf: `http {
    server {
        listen 443 ssl;
        listen 80;
        location /status/ {
            api /status/;
        }
    }
}`,
			wantAPI: "/status/", wantAPIPort: 80,
		},
		{
			name: "ssl flag among other listen params (http2)",
			conf: `http {
    server {
        listen 443 ssl http2;
        listen 80;
        location /status/ {
            api /status/;
        }
    }
}`,
			wantAPI: "/status/", wantAPIPort: 80,
		},
		{
			name: "location with = prefix",
			conf: `http {
    server {
        listen 8080;
        location = /status/ {
            api /status/;
        }
    }
}`,
			wantAPI: "/status/", wantAPIPort: 8080,
		},
		{
			name: "no listen — port is 0",
			conf: `http {
    server {
        location /status/ {
            api /status/;
        }
    }
}`,
			wantAPI: "/status/", wantAPIPort: 0,
		},
		{
			name: "full config with logs and different hosts",
			conf: `http {
    log_format timed '$remote_addr [$time_local] "$request" $status $request_time';
    access_log /var/log/angie/access.log timed;
    server {
        listen 192.168.1.1:80;
        location /stub_status { stub_status; }
    }
    server {
        listen 10.10.1.1:8080;
        location /status/ { api /status/; }
    }
}`,
			wantAPI: "/status/", wantAPIPort: 8080, wantAPIHost: "10.10.1.1",
			wantStub: "/stub_status", wantStubPort: 80, wantStubHost: "192.168.1.1",
			wantLogs: 1, wantFormats: 1,
		},
		{
			name: "api directive with extra spaces",
			conf: `http {
    server {
        listen 8080;
        location /status/ {
            api   /status/  ;
        }
    }
}`,
			wantAPI: "/status/", wantAPIPort: 8080,
		},
		{
			name: "listen port only — host is empty",
			conf: `http {
    server {
        listen 8080;
        location /status/ {
            api /status/;
        }
    }
}`,
			wantAPI: "/status/", wantAPIPort: 8080, wantAPIHost: "",
		},
		{
			name: "listen 0.0.0.0:port",
			conf: `http {
    server {
        listen 0.0.0.0:9090;
        location /status/ {
            api /status/;
        }
    }
}`,
			wantAPI: "/status/", wantAPIPort: 9090, wantAPIHost: "0.0.0.0",
		},
	}

	// Test: listen directive in included snippet should resolve host and port.
	t.Run("listen in include snippet", func(t *testing.T) {
		dir := t.TempDir()

		snippetDir := filepath.Join(dir, "snippets")
		require.NoError(t, os.MkdirAll(snippetDir, 0755))
		require.NoError(t, os.WriteFile(filepath.Join(snippetDir, "listen-internal.conf"), []byte("listen 127.0.0.1:9113;\n"), 0644))

		conf := `http {
    server {
        include ` + filepath.Join(snippetDir, "listen-internal.conf") + `;
        location /status/ {
            api /status/;
        }
    }
}`
		confPath := filepath.Join(dir, "angie.conf")
		require.NoError(t, os.WriteFile(confPath, []byte(conf), 0644))

		result, err := DiscoverConfig(confPath)
		require.NoError(t, err)
		assert.Equal(t, "/status/", result.APIStatusPath)
		assert.Equal(t, 9113, result.APIStatusPort, "port should come from included snippet")
		assert.Equal(t, "127.0.0.1", result.APIStatusHost, "host should come from included snippet")
	})

	// Test: included snippet with non-loopback IP (reproduces the original bug).
	t.Run("listen in include snippet with non-loopback IP", func(t *testing.T) {
		dir := t.TempDir()

		snippetDir := filepath.Join(dir, "snippets")
		require.NoError(t, os.MkdirAll(snippetDir, 0755))
		require.NoError(t, os.WriteFile(
			filepath.Join(snippetDir, "http-ip-internal.conf"),
			[]byte("listen 10.10.1.1:81;\n"),
			0644,
		))

		conf := `http {
    server {
        include ` + filepath.Join(snippetDir, "http-ip-internal.conf") + `;

        location =/metrics {
           prometheus all;
        }

        location /status/ {
            api /status/;
        }
    }
}`
		confPath := filepath.Join(dir, "angie.conf")
		require.NoError(t, os.WriteFile(confPath, []byte(conf), 0644))

		result, err := DiscoverConfig(confPath)
		require.NoError(t, err)
		assert.Equal(t, "/status/", result.APIStatusPath)
		assert.Equal(t, 81, result.APIStatusPort, "port should come from included snippet")
		assert.Equal(t, "10.10.1.1", result.APIStatusHost, "host should come from included snippet, not default to 127.0.0.1")
	})

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			confPath := filepath.Join(dir, "angie.conf")
			require.NoError(t, os.WriteFile(confPath, []byte(tc.conf), 0644))

			result, err := DiscoverConfig(confPath)
			require.NoError(t, err)

			assert.Equal(t, tc.wantAPI, result.APIStatusPath, "APIStatusPath")
			assert.Equal(t, tc.wantAPIPort, result.APIStatusPort, "APIStatusPort")
			assert.Equal(t, tc.wantAPIHost, result.APIStatusHost, "APIStatusHost")
			assert.Equal(t, tc.wantStub, result.StubStatusPath, "StubStatusPath")
			assert.Equal(t, tc.wantStubPort, result.StubStatusPort, "StubStatusPort")
			assert.Equal(t, tc.wantStubHost, result.StubStatusHost, "StubStatusHost")
			if tc.wantLogs > 0 {
				assert.Len(t, result.AccessLogs, tc.wantLogs, "AccessLogs")
			}
			if tc.wantFormats > 0 {
				assert.Len(t, result.LogFormats, tc.wantFormats, "LogFormats")
			}
		})
	}
}
