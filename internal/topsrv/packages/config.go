package packages

import (
	"fmt"
	"time"
)

const (
	defaultInterval    = 6 * time.Hour
	defaultMaxPackages = 10000
)

// Config configures the package inventory collector. Loaded from the
// [Packages] TOML section. Disable-style flags (Disabled, DisablePush) use
// zero=false so absence of the TOML section means "enabled with defaults" —
// same pattern as [Postgres].Disabled / [Smart].Disabled.
type Config struct {
	Disabled      bool     // skip the collector entirely
	Interval      string   // snapshot scan period; default "6h"
	Managers      []string // empty = auto-detect (dpkg|rpm|apk by marker files)
	CheckUpgrades bool     // populate topsrv_packages_upgradable from local apt/dnf cache (Phase 4)
	DisablePush   bool     // when true, skip POSTing snapshots to /v1/inventory
	MaxPackages   int      // safety cap; logs warning and truncates if exceeded

	parsedInterval time.Duration
}

// ParsedInterval returns the configured Interval as a time.Duration, falling
// back to the default when unset or malformed.
func (c *Config) ParsedInterval() time.Duration {
	if c == nil || c.parsedInterval == 0 {
		return defaultInterval
	}
	return c.parsedInterval
}

// MaxPackagesOrDefault returns the configured cap or the default.
func (c *Config) MaxPackagesOrDefault() int {
	if c == nil || c.MaxPackages <= 0 {
		return defaultMaxPackages
	}
	return c.MaxPackages
}

// Validate parses Interval and applies defaults. Returns an error only for
// malformed values that the operator likely meant to set.
func (c *Config) Validate() error {
	if c == nil {
		return nil
	}
	if c.Interval == "" {
		c.parsedInterval = defaultInterval
		return nil
	}
	d, err := time.ParseDuration(c.Interval)
	if err != nil {
		return fmt.Errorf("packages: invalid Interval %q: %w", c.Interval, err)
	}
	if d < time.Minute {
		return fmt.Errorf("packages: Interval %q too small (minimum 1m)", c.Interval)
	}
	c.parsedInterval = d
	return nil
}
