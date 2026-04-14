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
		wantStub     string
		wantStubPort int
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
			wantAPI: "/status/", wantAPIPort: 8080,
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
			wantAPI: "/status/", wantAPIPort: 8443,
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
			name: "multiple listen — last wins",
			conf: `http {
    server {
        listen 80;
        listen 443 ssl;
        location /status/ {
            api /status/;
        }
    }
}`,
			wantAPI: "/status/", wantAPIPort: 443,
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
			name: "full config with logs",
			conf: `http {
    log_format timed '$remote_addr [$time_local] "$request" $status $request_time';
    access_log /var/log/angie/access.log timed;
    server {
        listen 80;
        location /stub_status { stub_status; }
    }
    server {
        listen 8080;
        location /status/ { api /status/; }
    }
}`,
			wantAPI: "/status/", wantAPIPort: 8080,
			wantStub: "/stub_status", wantStubPort: 80,
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
	}

	// Test: listen directive in included snippet should be resolved.
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
			assert.Equal(t, tc.wantStub, result.StubStatusPath, "StubStatusPath")
			assert.Equal(t, tc.wantStubPort, result.StubStatusPort, "StubStatusPort")
			if tc.wantLogs > 0 {
				assert.Len(t, result.AccessLogs, tc.wantLogs, "AccessLogs")
			}
			if tc.wantFormats > 0 {
				assert.Len(t, result.LogFormats, tc.wantFormats, "LogFormats")
			}
		})
	}
}
