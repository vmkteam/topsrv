package weblog

import (
	"slices"
	"strings"
	"time"

	"github.com/vmkteam/topsrv/internal/topsrv/botlog"
	"github.com/vmkteam/topsrv/internal/topsrv/nginx"
	"github.com/vmkteam/topsrv/internal/topsrv/shipper"
)

// proxyHostField is the one nginx variable this stream reads that the bot
// stream does not: it answers "which backend served this".
const proxyHostField = "proxy_host"

// RequiredFields is the set of nginx variables this stream needs read into
// ParsedLine.Extras, mirroring botlog's. Declaring it here rather than having
// app.go append a literal is what keeps the name in one place — the observer,
// the format check and the collector wiring all have to agree on it.
func RequiredFields(aliases botlog.FieldAliases) []string {
	// Concat, not append: FieldAliases.Names() returns a slice whose capacity
	// still covers the aliases it dropped, so appending would write into the
	// caller's backing array whenever one alias is empty.
	return slices.Concat(botlog.RequiredFields(aliases), []string{proxyHostField})
}

// EventSink is where accepted events go. Narrow on purpose, same reason as in
// botlog: the observer has no business knowing about batching or spool.
type EventSink interface {
	Enqueue(ev shipper.Event)
}

// Observer implements nginx.LogObserver for the web-log stream. It runs on the
// tail goroutine for every line of every tailed file — including the files this
// stream does not want — so the cheap rejections come first.
//
// The order matters more than it looks. Parsing already happened (the collector
// needs it for metrics regardless), so filters do not save parsing; what they
// save is the work below them, and MatchUA is microseconds against a 1 KB UA
// while a path comparison is tens of nanoseconds.
type Observer struct {
	sink     EventSink
	metrics  *Metrics
	hostname string

	paths    map[string]struct{}
	upstream map[string]struct{}

	// Copied out of Config rather than held by pointer: these three are read
	// per line, and the config also carries the token, endpoint and spool path,
	// which have no business staying reachable from the tail goroutine.
	excludePrefixes []string
	uaTruncate      int
	uriTruncate     int

	// Which filters this host can actually apply — see Filters.
	filters Filters

	// Resolved from the collector's ExtractFields; -1 when the format lacks it.
	idxUA, idxHost, idxServerName, idxRemoteAddr, idxReferer, idxProxyHost int
}

// NewObserver wires an Observer. tailPaths are the paths that survived
// CheckFormats; extractFields mirrors the collector's, and its indices decide
// where each variable lands in ParsedLine.Extras.
func NewObserver(sink EventSink, m *Metrics, cfg *Config, hostname string, tailPaths, extractFields []string,
	aliases botlog.FieldAliases, filters Filters,
) *Observer {
	paths := make(map[string]struct{}, len(tailPaths))
	for _, p := range tailPaths {
		paths[p] = struct{}{}
	}
	upstream := make(map[string]struct{}, len(cfg.Upstreams))
	for _, u := range cfg.Upstreams {
		upstream[u] = struct{}{}
	}

	return &Observer{
		sink:            sink,
		metrics:         m,
		hostname:        hostname,
		paths:           paths,
		upstream:        upstream,
		excludePrefixes: cfg.ExcludePathPrefixes,
		uaTruncate:      cfg.UATruncate,
		uriTruncate:     cfg.URITruncate,
		filters:         filters,
		idxUA:           indexOrSkip(extractFields, aliases.UserAgent),
		idxHost:         indexOrSkip(extractFields, aliases.Host),
		idxServerName:   indexOrSkip(extractFields, aliases.ServerName),
		idxRemoteAddr:   indexOrSkip(extractFields, aliases.RemoteAddr),
		idxReferer:      indexOrSkip(extractFields, aliases.Referer),
		idxProxyHost:    indexOrSkip(extractFields, proxyHostField),
	}
}

func indexOrSkip(extractFields []string, name string) int {
	if name == "" {
		return -1
	}
	return slices.Index(extractFields, name)
}

// OnLogLine satisfies nginx.LogObserver.
func (o *Observer) OnLogLine(p *nginx.ParsedLine, path string) {
	// 1. Wrong file. A host usually tails far more logs than this stream wants,
	// so this rejects most calls — and it costs one map probe.
	if _, ok := o.paths[path]; !ok {
		o.metrics.FilteredPath.Inc()
		return
	}

	// 2. Never reached a backend. On a front node serving bundles, images and
	// static files from disk this rejects most lines — the single most
	// effective filter available, and it takes the assets out of the volume.
	reached := reachedUpstream(p.UpstreamResponseTime)
	if o.filters.RequireUpstream && !reached {
		o.metrics.FilteredUpstream.Inc()
		return
	}

	// 3. Wrong backend.
	proxyHost := o.field(p, o.idxProxyHost)
	if o.filters.Upstreams {
		if _, ok := o.upstream[proxyHost]; !ok {
			o.metrics.FilteredProxyHost.Inc()
			return
		}
	}

	// 4. Excluded prefix. Compared against the raw path, not the normalized
	// URI: the normalized form collapses to /:id and /:rest, which would make
	// an operator's rule depend on the normalizer's current shape.
	rawPath := nginx.StripQuery(p.RawURI)
	for _, prefix := range o.excludePrefixes {
		if strings.HasPrefix(rawPath, prefix) {
			o.metrics.FilteredPrefix.Inc()
			return
		}
	}

	// 5. UA is a signal here, not a gate: the scraper this stream exists for
	// sends a plain browser UA, and dropping non-matches would reproduce the
	// blind spot the stream was built to remove.
	ua := o.field(p, o.idxUA)
	family, name := botlog.MatchUA(ua, nil)

	uri := p.RawURI
	if uri == "" {
		uri = p.URI
	}
	ts, ok := p.Timestamp()
	if !ok {
		ts = time.Now()
	}

	ev := botlog.BuildEvent(ts, o.hostname, botlog.Fields{
		Status:               p.Status,
		URI:                  botlog.Truncate(uri, o.uriTruncate),
		BodyBytesSent:        p.BodyBytesSent,
		RequestTime:          p.RequestTime,
		UpstreamResponseTime: p.UpstreamResponseTime,
		UpstreamCacheStatus:  p.UpstreamCacheStatus,
		UserAgent:            ua,
		Method:               p.Method,
		Host:                 o.field(p, o.idxHost),
		ServerName:           o.field(p, o.idxServerName),
		RemoteAddr:           o.field(p, o.idxRemoteAddr),
		Referer:              botlog.Truncate(o.field(p, o.idxReferer), o.uriTruncate),
		RequestID:            p.RequestID,
		UpstreamStatus:       p.UpstreamStatus,
	}, family, name, o.uaTruncate)

	// What the bot stream has no field for.
	ev.UAMatched = family != ""
	ev.UAListVersion = botlog.UAListVersion
	ev.ReachedUpstream = reached
	ev.ProxyHost = botlog.DashToEmpty(proxyHost)
	ev.Platform = p.Platform
	ev.AppVersion = p.AppVersion
	ev.VisitorID = p.VisitorID
	if family != "" {
		o.metrics.Matched(family)
	}
	o.sink.Enqueue(ev)
}

func (o *Observer) field(p *nginx.ParsedLine, idx int) string {
	if idx < 0 || idx >= p.NExtras {
		return ""
	}
	return p.Extras[idx]
}

// reachedUpstream reads the boolean out of $upstream_response_time. On a retry
// nginx logs a chain ("0.012, 0.034"); for the boolean "not empty and not a
// dash" is enough, and the numeric field takes the first entry separately.
func reachedUpstream(v string) bool { return v != "" && v != "-" }
