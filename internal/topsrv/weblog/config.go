// Package weblog ships the full HTTP stream from explicitly chosen access logs.
//
// Where botlog sends only lines whose UA matched the built-in list, this stream
// sends everything from the files an operator named — which is the point: a
// scraper running a plain browser UA never appears in the bot stream at all.
// On a busy API host that gap can be the entire backend: a few dozen bot events
// a day against millions of requests.
//
// The UA classifier still runs, but as a signal (uaMatched) rather than a gate.
package weblog

import (
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/vmkteam/topsrv/internal/topsrv"
	"github.com/vmkteam/topsrv/internal/topsrv/shipper"
)

const (
	// ingestPath is the control-plane handler that accepts ndjson web-log batches.
	ingestPath = "/v1/web-logs"
	// spoolSubdir keeps web-log WAL files out of both push.go's glob and the
	// bot-log spool: the two streams have separate disk budgets, and a burst on
	// one must not evict the other's pending batches.
	spoolSubdir = "weblog"

	DefaultUATruncate  = 1024
	DefaultURITruncate = 2048
)

// Delivery defaults are the shipper's — one declaration, in the package that
// applies them. Sizing suits this stream anyway: a front node produces well
// over a thousand lines per second, so a batch fills in seconds and the
// interval mostly matters for quiet hosts.
const (
	DefaultBatchSize     = shipper.DefaultBatchSize
	DefaultBatchInterval = shipper.DefaultBatchInterval
	DefaultMaxSpoolMB    = shipper.DefaultMaxSpoolMB
)

// Config is the [WebLogs] TOML section.
type Config struct {
	Enabled bool
	// Token must differ from [BotLogs].Token: separate tokens are what make the
	// two streams separately revocable, and revoking access to a site's entire
	// traffic should not require revoking the customer's alerting.
	Token string
	// Endpoint defaults to [Push].Endpoint with the path replaced by /v1/web-logs.
	Endpoint string

	// LogPaths is an explicit allowlist over what discovery found. Not "where to
	// look": naming files is the cheapest filter there is, and it is the only
	// one that cannot accidentally include a log added later with a format that
	// carries request bodies.
	//
	// A host commonly writes a dozen or more vhost logs; only a few of them are
	// worth shipping.
	LogPaths []string

	// Local filters; empty means "off". See observer.go for the order they run in.
	RequireUpstream     bool     // keep only requests that reached a backend
	Upstreams           []string // allowlist of $proxy_host values; needs it in log_format
	ExcludePathPrefixes []string // e.g. ["/_nuxt/", "/static/"]

	BatchSize     int
	BatchInterval string
	SpoolDir      string
	MaxSpoolMB    int

	UATruncate  int
	URITruncate int

	parsedBatchInterval time.Duration
}

// ShipperOptions renders the delivery half of the config.
func (c *Config) ShipperOptions() shipper.Options {
	return shipper.Options{
		MetricPrefix:  "topsrv_weblog",
		MetricSubject: "Web-log",
		Endpoint:      c.Endpoint,
		Token:         c.Token,
		BatchSize:     c.BatchSize,
		BatchInterval: c.parsedBatchInterval,
		SpoolDir:      c.SpoolDir,
		MaxSpoolMB:    c.MaxSpoolMB,
	}
}

// Validate fills defaults, derives Endpoint/SpoolDir from push when blank, and
// reports the first failure. Mutates the receiver in place. botToken is
// [BotLogs].Token, checked for accidental reuse.
func (c *Config) Validate(push topsrv.PushConfig, botToken string) error {
	if c.Token == "" {
		return errors.New("weblog: Token must be set")
	}
	if botToken != "" && c.Token == botToken {
		return errors.New("weblog: Token must differ from [BotLogs].Token — a shared token cannot be revoked separately")
	}

	if err := c.validateLogPaths(); err != nil {
		return err
	}

	if c.Endpoint == "" {
		if push.Endpoint == "" {
			return errors.New("weblog: Endpoint must be set or [Push].Endpoint configured")
		}
		u, err := url.Parse(push.Endpoint)
		if err != nil {
			return fmt.Errorf("weblog: parse [Push].Endpoint: %w", err)
		}
		u.Path = ingestPath
		u.RawQuery = ""
		c.Endpoint = u.String()
	} else if _, err := url.Parse(c.Endpoint); err != nil {
		return fmt.Errorf("weblog: parse Endpoint: %w", err)
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
			return fmt.Errorf("weblog: parse BatchInterval: %w", err)
		}
		c.parsedBatchInterval = d
	}
	if c.MaxSpoolMB <= 0 {
		c.MaxSpoolMB = DefaultMaxSpoolMB
	}
	if c.UATruncate <= 0 {
		c.UATruncate = DefaultUATruncate
	}
	if c.URITruncate <= 0 {
		c.URITruncate = DefaultURITruncate
	}
	return nil
}

// validateLogPaths rejects an empty list and glob patterns.
//
// Empty is an error rather than "ship everything": on a host with many vhost
// logs that would quietly include media, cdn and infrastructure endpoints — and
// any log whose format carries request bodies.
//
// Globs are refused because they resolve once at startup: a new vhost would not
// be picked up until restart, but a newly added log would be — including one
// added with an unsafe format. The list is meant to be reviewable.
func (c *Config) validateLogPaths() error {
	if len(c.LogPaths) == 0 {
		return errors.New("weblog: LogPaths must list at least one access log")
	}
	for _, p := range c.LogPaths {
		if !filepath.IsAbs(p) {
			return fmt.Errorf("weblog: LogPaths entry must be an absolute path: %s", p)
		}
		if strings.ContainsAny(p, "*?[") {
			return fmt.Errorf("weblog: LogPaths entry must not be a glob: %s", p)
		}
	}
	return nil
}
