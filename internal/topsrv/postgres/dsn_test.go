package postgres

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDerivePassword(t *testing.T) {
	// Must match gatesrv useCrypto.ts:derivePassword("ts_secret")
	assert.Equal(t, "b28423ba90973d071092f9902c424dc1", DerivePassword("ts_secret"))

	p1, p2 := DerivePassword("token"), DerivePassword("token")
	assert.Equal(t, p1, p2)

	assert.NotEqual(t, DerivePassword("a"), DerivePassword("b"))

	assert.Len(t, DerivePassword("any-token"), 32)
	assert.Len(t, DerivePassword(""), 32)
}

func TestBuildDSN(t *testing.T) {
	cases := []struct {
		name     string
		instance string
		token    string
		want     string
	}{
		{
			name:     "with token",
			instance: "127.0.0.1:5432",
			token:    "ts_secret",
			want:     "postgres://topsrv:b28423ba90973d071092f9902c424dc1@127.0.0.1:5432/postgres?sslmode=disable",
		},
		{
			name:     "without token",
			instance: "127.0.0.1:5432",
			token:    "",
			want:     "postgres://topsrv@127.0.0.1:5432/postgres?sslmode=disable",
		},
		{
			name:     "custom port",
			instance: "127.0.0.1:5433",
			token:    "ts_secret",
			want:     "postgres://topsrv:b28423ba90973d071092f9902c424dc1@127.0.0.1:5433/postgres?sslmode=disable",
		},
		{
			name:     "custom host",
			instance: "10.10.1.1:5432",
			token:    "tok",
			want:     "postgres://topsrv:" + DerivePassword("tok") + "@10.10.1.1:5432/postgres?sslmode=disable",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, BuildDSN(tc.instance, tc.token))
		})
	}
}

func TestParsePostgresPort(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    int
	}{
		{name: "standard port", content: "port = 5432\n", want: 5432},
		{name: "custom port", content: "port = 5433\n", want: 5433},
		{name: "commented out", content: "#port = 5433\n", want: 0},
		{name: "with spaces", content: "  port = 5434  \n", want: 5434},
		{name: "no port line", content: "listen_addresses = '*'\nmax_connections = 100\n", want: 0},
		{name: "multiple — last wins", content: "port = 5432\nport = 5433\n", want: 5433},
		{name: "commented then uncommented", content: "#port = 5432\nport = 5433\n", want: 5433},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "postgresql.conf")
			require.NoError(t, os.WriteFile(path, []byte(tc.content), 0644))
			assert.Equal(t, tc.want, parsePostgresPort(path))
		})
	}

	t.Run("missing file", func(t *testing.T) {
		assert.Equal(t, 0, parsePostgresPort("/nonexistent/postgresql.conf"))
	})
}

func TestUpdateInstance(t *testing.T) {
	dir := t.TempDir()

	t.Run("overrides port from config", func(t *testing.T) {
		path := filepath.Join(dir, "pg1.conf")
		require.NoError(t, os.WriteFile(path, []byte("port = 5433\n"), 0644))
		assert.Equal(t, "127.0.0.1:5433", UpdateInstance("127.0.0.1:5432", path))
	})

	t.Run("keeps default when no port in config", func(t *testing.T) {
		path := filepath.Join(dir, "pg2.conf")
		require.NoError(t, os.WriteFile(path, []byte("max_connections = 100\n"), 0644))
		assert.Equal(t, "127.0.0.1:5432", UpdateInstance("127.0.0.1:5432", path))
	})

	t.Run("keeps default when no config path", func(t *testing.T) {
		assert.Equal(t, "127.0.0.1:5432", UpdateInstance("127.0.0.1:5432", ""))
	})
}
