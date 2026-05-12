// Package botlog ships parsed nginx access-log entries to the topsrv.io
// control plane for bot analytics. It plugs into the existing LogCollector
// through nginx.LogObserver and batches enriched JSON events with a disk-backed
// WAL spool.
package botlog

import (
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"time"

	"github.com/vmkteam/topsrv/internal/topsrv"
)

const (
	DefaultBatchSize = 5000
	// 30s gives the receiver larger batches on light bot traffic; a 5s
	// interval was flushing ~50-event payloads every tick on quiet hosts.
	DefaultBatchInterval = 30 * time.Second
	DefaultMaxSpoolMB    = 200
	DefaultUATruncate    = 1024

	// ingestPath is the control-plane handler that accepts ndjson bot-log batches.
	ingestPath = "/v1/bot-logs"
	// spoolSubdir keeps botlog WAL files out of push.go's glob; see plan.
	spoolSubdir = "botlog"
)

// Config is the [BotLogs] TOML section.
type Config struct {
	Enabled         bool
	Endpoint        string   // ingest URL; default: [Push].Endpoint with path replaced by /v1/bot-logs
	Token           string   // Bearer token; required when Enabled
	BatchSize       int      // events per batch; default 5000
	BatchInterval   string   // flush interval as Go duration; default "30s"
	SpoolDir        string   // parent directory; subdir "botlog" is created inside; default = [Push].SpoolDir
	MaxSpoolMB      int      // disk budget for spool subdir; default 200
	UATruncate      int      // max UA length stored per event; default 1024
	ExtraUAPatterns []string // local additions to knownBots (substring, case-sensitive)

	parsedBatchInterval time.Duration // populated by Validate
}

// Validate fills defaults, derives Endpoint/SpoolDir from push when blank, and
// reports the first failure. Mutates the receiver in place.
func (c *Config) Validate(push topsrv.PushConfig) error {
	if c.Token == "" {
		return errors.New("botlog: Token must be set")
	}

	if c.Endpoint == "" {
		if push.Endpoint == "" {
			return errors.New("botlog: Endpoint must be set or [Push].Endpoint configured")
		}
		u, err := url.Parse(push.Endpoint)
		if err != nil {
			return fmt.Errorf("botlog: parse [Push].Endpoint: %w", err)
		}
		u.Path = ingestPath
		u.RawQuery = ""
		c.Endpoint = u.String()
	} else if _, err := url.Parse(c.Endpoint); err != nil {
		return fmt.Errorf("botlog: parse Endpoint: %w", err)
	}

	if c.SpoolDir == "" && push.SpoolDir != "" {
		c.SpoolDir = push.SpoolDir
	}
	if c.SpoolDir != "" {
		c.SpoolDir = filepath.Join(c.SpoolDir, spoolSubdir)
	}

	if c.BatchSize <= 0 {
		c.BatchSize = DefaultBatchSize
	}
	if c.BatchInterval == "" {
		c.BatchInterval = DefaultBatchInterval.String()
		c.parsedBatchInterval = DefaultBatchInterval
	} else {
		d, err := time.ParseDuration(c.BatchInterval)
		if err != nil {
			return fmt.Errorf("botlog: parse BatchInterval: %w", err)
		}
		c.parsedBatchInterval = d
	}
	if c.MaxSpoolMB <= 0 {
		c.MaxSpoolMB = DefaultMaxSpoolMB
	}
	if c.UATruncate <= 0 {
		c.UATruncate = DefaultUATruncate
	}
	return nil
}

// ParsedBatchInterval returns BatchInterval as time.Duration. Validate must have
// been called first; otherwise returns 0.
func (c *Config) ParsedBatchInterval() time.Duration {
	return c.parsedBatchInterval
}
