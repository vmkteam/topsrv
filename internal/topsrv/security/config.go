package security

import (
	"fmt"
	"slices"
	"time"
)

const (
	defaultInterval = 6 * time.Hour
	minInterval     = 15 * time.Minute
)

// Section names as they appear in Data.Sections and in DisabledSections.
const (
	SectionSSHD           = "sshd"
	SectionAccounts       = "accounts"
	SectionSudoers        = "sudoers"
	SectionAuthorizedKeys = "authorizedKeys"
	SectionFirewall       = "firewall"
	SectionDocker         = "docker"
	SectionUpdates        = "updates"
	SectionProcScan       = "procScan"
	SectionKernel         = "kernel"
	SectionSysctl         = "sysctl"
	SectionFIM            = "fim"
	SectionRoleSignals    = "roleSignals"
)

// knownSections lists every section of schema v1, including those a later
// release implements, so a config written for a newer agent stays valid.
var knownSections = []string{
	SectionSSHD, SectionAccounts, SectionSudoers, SectionAuthorizedKeys,
	SectionFirewall, SectionDocker, SectionUpdates, SectionProcScan,
	SectionKernel, SectionSysctl, SectionFIM, SectionRoleSignals,
}

// Config configures the security collector, loaded from the [Security] TOML
// section. Disable-style flags use zero=false, so a missing section means
// "enabled with defaults", as with [Packages].
type Config struct {
	Disabled         bool     // skip the collector entirely
	Interval         string   // full snapshot period; default "6h", minimum "15m"
	DisablePush      bool     // collect for metrics and dry-run only, send nothing
	DisabledSections []string // sections to skip, e.g. "procScan"

	parsedInterval time.Duration
}

// Validate parses Interval and checks DisabledSections against the known
// section names.
func (c *Config) Validate() error {
	if c == nil {
		return nil
	}
	c.parsedInterval = defaultInterval
	if c.Interval != "" {
		d, err := time.ParseDuration(c.Interval)
		if err != nil {
			return fmt.Errorf("security: invalid Interval %q: %w", c.Interval, err)
		}
		if d < minInterval {
			return fmt.Errorf("security: Interval %q too small (minimum 15m)", c.Interval)
		}
		c.parsedInterval = d
	}
	for _, s := range c.DisabledSections {
		if !slices.Contains(knownSections, s) {
			return fmt.Errorf("security: unknown section %q in DisabledSections", s)
		}
	}
	return nil
}

// ParsedInterval returns the validated Interval, or the default.
func (c *Config) ParsedInterval() time.Duration {
	if c == nil || c.parsedInterval == 0 {
		return defaultInterval
	}
	return c.parsedInterval
}

// SectionEnabled reports whether the section is not listed in DisabledSections.
func (c *Config) SectionEnabled(name string) bool {
	return c == nil || !slices.Contains(c.DisabledSections, name)
}
