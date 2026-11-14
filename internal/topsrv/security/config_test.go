package security

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigValidate(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		var c Config
		require.NoError(t, c.Validate())
		assert.Equal(t, 6*time.Hour, c.ParsedInterval())
		assert.True(t, c.SectionEnabled(SectionKernel))
	})

	t.Run("nil config means defaults", func(t *testing.T) {
		var c *Config
		require.NoError(t, c.Validate())
		assert.Equal(t, 6*time.Hour, c.ParsedInterval())
		assert.True(t, c.SectionEnabled(SectionKernel))
	})

	t.Run("interval", func(t *testing.T) {
		c := Config{Interval: "30m"}
		require.NoError(t, c.Validate())
		assert.Equal(t, 30*time.Minute, c.ParsedInterval())
	})

	t.Run("disabled sections", func(t *testing.T) {
		c := Config{DisabledSections: []string{"sysctl", "procScan"}}
		require.NoError(t, c.Validate())
		assert.False(t, c.SectionEnabled(SectionSysctl))
		assert.False(t, c.SectionEnabled("procScan"), "a section of a later release can be disabled ahead of time")
		assert.True(t, c.SectionEnabled(SectionKernel))
	})

	errCases := []struct {
		name string
		cfg  Config
		want string
	}{
		{"malformed interval", Config{Interval: "six hours"}, "invalid Interval"},
		{"interval below 15m", Config{Interval: "10m"}, "minimum 15m"},
		{"unknown section", Config{DisabledSections: []string{"sshdd"}}, `unknown section "sshdd"`},
		{"environment cannot be disabled", Config{DisabledSections: []string{"environment"}}, `unknown section "environment"`},
	}
	for _, tc := range errCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}
