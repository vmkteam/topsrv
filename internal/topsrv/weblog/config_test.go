package weblog

import (
	"path/filepath"
	"testing"

	"github.com/vmkteam/topsrv/internal/topsrv"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func validConfig() *Config {
	return &Config{
		Enabled:  true,
		Token:    "wl_token",
		LogPaths: []string{"/var/log/nginx/site.log"},
	}
}

func TestConfigValidate(t *testing.T) {
	push := topsrv.PushConfig{Endpoint: "https://push.example.com/v1/write", SpoolDir: "/var/lib/topsrv/spool"}

	t.Run("derives endpoint and spool subdir from push", func(t *testing.T) {
		c := validConfig()
		require.NoError(t, c.Validate(push, "bl_token"))

		assert.Equal(t, "https://push.example.com/v1/web-logs", c.Endpoint)
		assert.Equal(t, filepath.Join("/var/lib/topsrv/spool", "weblog"), c.SpoolDir,
			"own subdir: the two streams have separate disk budgets")
		assert.Equal(t, DefaultBatchSize, c.BatchSize)
		assert.Equal(t, DefaultBatchInterval, c.ShipperOptions().BatchInterval)
	})

	// A shared token would make the two streams inseparable: revoking access to
	// the site's entire traffic would also switch off the customer's alerting.
	t.Run("token must differ from the bot-log one", func(t *testing.T) {
		c := validConfig()
		c.Token = "same_token"
		err := c.Validate(push, "same_token")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "must differ")
	})

	t.Run("token is required", func(t *testing.T) {
		c := validConfig()
		c.Token = ""
		require.Error(t, c.Validate(push, ""))
	})

	// Empty means "nothing configured", never "ship every log on the host":
	// that would include media, cdn and infrastructure vhosts, and any log
	// whose format carries request bodies.
	t.Run("empty LogPaths is an error, not a wildcard", func(t *testing.T) {
		c := validConfig()
		c.LogPaths = nil
		err := c.Validate(push, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "LogPaths")
	})

	// A glob resolves once at startup: it would miss a vhost added later but
	// happily pick up a log added with an unsafe format.
	t.Run("globs and relative paths are refused", func(t *testing.T) {
		for _, path := range []string{"/var/log/nginx/*.log", "/var/log/nginx/site?.log", "relative/site.log"} {
			c := validConfig()
			c.LogPaths = []string{path}
			assert.Errorf(t, c.Validate(push, ""), "path %q should be refused", path)
		}
	})

	t.Run("without push endpoint the ingest URL must be explicit", func(t *testing.T) {
		c := validConfig()
		require.Error(t, c.Validate(topsrv.PushConfig{}, ""))

		c = validConfig()
		c.Endpoint = "https://ingest.example.com/v1/web-logs"
		require.NoError(t, c.Validate(topsrv.PushConfig{}, ""))
	})

	t.Run("shipper options carry the web-log metric prefix", func(t *testing.T) {
		c := validConfig()
		require.NoError(t, c.Validate(push, ""))

		opts := c.ShipperOptions()
		assert.Equal(t, "topsrv_weblog", opts.MetricPrefix,
			"prefix is what lets both streams register metrics in one process")
		assert.Equal(t, c.SpoolDir, opts.SpoolDir)
		assert.Equal(t, c.Token, opts.Token)
	})
}
