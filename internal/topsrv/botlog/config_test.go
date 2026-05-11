package botlog

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/vmkteam/topsrv/internal/topsrv"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigValidate_RequiresToken(t *testing.T) {
	c := Config{}
	err := c.Validate(topsrv.PushConfig{Endpoint: "https://gate.example.com/v1/write"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Token must be set")
}

func TestConfigValidate_DerivesEndpointFromPush(t *testing.T) {
	c := Config{Token: "bl_x"}
	err := c.Validate(topsrv.PushConfig{Endpoint: "https://gate.example.com/v1/write?account=42"})
	require.NoError(t, err)
	assert.Equal(t, "https://gate.example.com/v1/bot-logs", c.Endpoint)
}

func TestConfigValidate_KeepsExplicitEndpoint(t *testing.T) {
	c := Config{Token: "bl_x", Endpoint: "https://other.example.com/ingest"}
	err := c.Validate(topsrv.PushConfig{Endpoint: "https://gate.example.com/v1/write"})
	require.NoError(t, err)
	assert.Equal(t, "https://other.example.com/ingest", c.Endpoint)
}

func TestConfigValidate_FailsWithoutAnyEndpoint(t *testing.T) {
	c := Config{Token: "bl_x"}
	err := c.Validate(topsrv.PushConfig{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Endpoint")
}

func TestConfigValidate_SpoolDirFromPush(t *testing.T) {
	c := Config{Token: "bl_x", Endpoint: "https://gate/v1/bot-logs"}
	err := c.Validate(topsrv.PushConfig{SpoolDir: "/var/lib/topsrv/spool"})
	require.NoError(t, err)
	assert.Equal(t, filepath.Join("/var/lib/topsrv/spool", "botlog"), c.SpoolDir)
}

func TestConfigValidate_SpoolDirExplicit(t *testing.T) {
	c := Config{Token: "bl_x", Endpoint: "https://gate/v1/bot-logs", SpoolDir: "/srv/botlog-spool"}
	err := c.Validate(topsrv.PushConfig{SpoolDir: "/var/lib/topsrv/spool"})
	require.NoError(t, err)
	assert.Equal(t, filepath.Join("/srv/botlog-spool", "botlog"), c.SpoolDir)
}

func TestConfigValidate_SpoolDirEmptyWhenBothMissing(t *testing.T) {
	c := Config{Token: "bl_x", Endpoint: "https://gate/v1/bot-logs"}
	require.NoError(t, c.Validate(topsrv.PushConfig{}))
	assert.Empty(t, c.SpoolDir, "no spool when neither side configures it")
}

func TestConfigValidate_AppliesDefaults(t *testing.T) {
	c := Config{Token: "bl_x", Endpoint: "https://gate/v1/bot-logs"}
	require.NoError(t, c.Validate(topsrv.PushConfig{}))
	assert.Equal(t, DefaultBatchSize, c.BatchSize)
	assert.Equal(t, DefaultBatchInterval.String(), c.BatchInterval)
	assert.Equal(t, DefaultMaxSpoolMB, c.MaxSpoolMB)
	assert.Equal(t, DefaultUATruncate, c.UATruncate)
	assert.Equal(t, DefaultBatchInterval, c.ParsedBatchInterval())
}

func TestConfigValidate_BadInterval(t *testing.T) {
	c := Config{Token: "bl_x", Endpoint: "https://gate/v1/bot-logs", BatchInterval: "12 parsecs"}
	err := c.Validate(topsrv.PushConfig{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "BatchInterval")
}

func TestConfigValidate_RespectsOverrides(t *testing.T) {
	c := Config{
		Token:         "bl_x",
		Endpoint:      "https://gate/v1/bot-logs",
		BatchSize:     1000,
		BatchInterval: "30s",
		MaxSpoolMB:    50,
		UATruncate:    256,
	}
	require.NoError(t, c.Validate(topsrv.PushConfig{}))
	assert.Equal(t, 1000, c.BatchSize)
	assert.Equal(t, 30*time.Second, c.ParsedBatchInterval())
	assert.Equal(t, 50, c.MaxSpoolMB)
	assert.Equal(t, 256, c.UATruncate)
}
