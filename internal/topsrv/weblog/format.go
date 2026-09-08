package weblog

import (
	"regexp"

	"github.com/vmkteam/topsrv/internal/topsrv/botlog"
	"github.com/vmkteam/topsrv/internal/topsrv/nginx"
)

// Warning kinds, reported by CheckFormats and surfaced as
// topsrv_collector_config_warnings_total{kind=...}.
const (
	KindUnknownPath       = "weblog_unknown_path"
	KindUnsafeFormat      = "weblog_unsafe_format"
	KindNoClientIP        = "weblog_no_client_ip"
	KindIncompleteFormat  = "weblog_incomplete_format"
	KindNoTimestamp       = "weblog_no_timestamp"
	KindNoMethod          = "weblog_no_method"
	KindNoUpstream        = "weblog_no_upstream"
	KindNoRequestID       = "weblog_no_request_id"
	KindNoUpstreamStatus  = "weblog_no_upstream_status"
	KindUpstreamFilterOff = "weblog_upstream_filter_disabled"
)

// Warning is one problem found while checking a configured log path.
// Fatal means the path is not tailed at all.
type Warning struct {
	Kind   string
	Path   string
	Detail string
	Fatal  bool
}

// unsafeVars must never be shipped. A format carrying any of them is refused
// outright rather than filtered later: an nginx config can declare such a
// format (one with $http_cookie, another with $request_body) without attaching
// it anywhere, leaving it one config line away from a vhost we tail.
//
//nolint:gochecknoglobals // immutable check tables
var unsafeVars = []string{"request_body", "http_cookie", "http_authorization"}

// varRe matches an nginx variable reference with a word boundary, so "request"
// does not match $request_time or $request_uri.
var varRe = regexp.MustCompile(`\$([a-z_0-9]+)`) //nolint:gochecknoglobals // compiled once

// Filters says which of the two upstream filters this host can actually apply:
// the configured setting AND'd with whether every tailed format carries the
// field it reads.
//
// Every, not any: both are a single boolean on the observer, which sees lines
// from all paths. Enabling one on a format that lacks the field would silently
// drop that file's entire traffic — so a format short of it disables the filter
// for the host, and CheckFormats has already said which one and why.
type Filters struct {
	RequireUpstream bool
	Upstreams       bool
}

// CheckFormats decides which of the configured paths are safe to tail, which
// filters the result can feed, and reports everything an operator should know
// about the rest.
//
// The check is free: the collector config already holds the format string for
// every access_log, so this reads memory rather than files. It runs at startup
// because the alternative — noticing at query time that a stream has been
// shipping nothing for a week — is not a diagnosis anyone gets to make.
//
// aliases are the field names resolved from the discovered log_format, so a
// host that logs its client address under an operator-defined name is judged
// by what the parser will actually read rather than by the canonical spelling.
func CheckFormats(cfg *Config, log nginx.LogConfig, aliases botlog.FieldAliases) (tail []string, f Filters, warnings []Warning) {
	tailed := make(map[string]struct{}, len(log.LogPaths))
	for _, p := range log.LogPaths {
		tailed[p] = struct{}{}
	}

	// Start true and AND down: a host with no usable path ends up with both
	// filters off, which is what the zero value already says.
	haveUpstream, haveProxyHost := true, true

	for _, path := range cfg.LogPaths {
		if _, ok := tailed[path]; !ok {
			warnings = append(warnings, Warning{
				Kind: KindUnknownPath, Path: path, Fatal: true,
				Detail: "no access_log directive found for this path — check the exact path in nginx -T",
			})
			continue
		}

		vars := varsOf(formatOf(log, path))
		w, fatal := checkPath(cfg, path, vars, aliases)
		warnings = append(warnings, w...)
		if fatal {
			continue
		}
		haveUpstream = haveUpstream && vars["upstream_response_time"]
		haveProxyHost = haveProxyHost && vars[proxyHostField]
		tail = append(tail, path)
	}

	if len(tail) > 0 {
		f.RequireUpstream = cfg.RequireUpstream && haveUpstream
		f.Upstreams = len(cfg.Upstreams) > 0 && haveProxyHost
	}
	return tail, f, warnings
}

// formatOf returns the log_format for one path: the per-path one discovery
// found, else the collector's default.
func formatOf(log nginx.LogConfig, path string) string {
	if f := log.LogFormats[path]; f != "" {
		return f
	}
	return log.LogFormat
}

// checkPath returns the warnings for one path and whether they disqualify it.
func checkPath(cfg *Config, path string, vars map[string]bool, aliases botlog.FieldAliases) (warnings []Warning, fatal bool) {
	for _, v := range unsafeVars {
		if vars[v] {
			return []Warning{{
				Kind: KindUnsafeFormat, Path: path, Fatal: true,
				Detail: "format carries $" + v + " — request bodies, cookies and credentials are never shipped",
			}}, true
		}
	}

	if !vars[aliases.RemoteAddr] && !anyOf(vars, botlog.RemoteCandidates) {
		return []Warning{{
			Kind: KindNoClientIP, Path: path, Fatal: true,
			Detail: "format has no client address — an event without one cannot be attributed",
		}}, true
	}
	if !vars["status"] || !anyOf(vars, nginx.URICandidates) {
		return []Warning{{
			Kind: KindIncompleteFormat, Path: path, Fatal: true,
			Detail: "format lacks $status or a URI variable",
		}}, true
	}

	// Non-fatal from here: the stream still carries useful data, but the
	// operator should know what it will be missing.
	if !anyOf(vars, nginx.TimeCandidates) {
		warnings = append(warnings, Warning{
			Kind: KindNoTimestamp, Path: path,
			Detail: "format has no timestamp — the agent clock is used instead, so think time and request gaps are not trustworthy",
		})
	}
	if !anyOf(vars, nginx.MethodCandidates) {
		warnings = append(warnings, Warning{
			Kind: KindNoMethod, Path: path,
			Detail: "format has neither $request_method nor $request — events ship without a verb",
		})
	}
	if !vars["upstream_response_time"] {
		warnings = append(warnings, Warning{
			Kind: KindNoUpstream, Path: path,
			Detail: "format has no $upstream_response_time — RequireUpstream cannot be used on this host",
		})
	}
	// Advisory, unlike the checks above: these disable no filter, the stream
	// runs fine without them. They are here because the price is paid silently
	// — the receiver generates a requestId that is unique and joins to nothing,
	// and upstreamStatus stays 0 — so an operator otherwise learns about it
	// from an empty column weeks later.
	if !anyOf(vars, []string{"request_id", "http_x_request_id"}) {
		warnings = append(warnings, Warning{
			Kind: KindNoRequestID, Path: path,
			Detail: "format has no $request_id — events cannot be joined to the backend's own logs for the same request; the receiver will generate an id that matches nothing",
		})
	}
	if !vars["upstream_status"] {
		warnings = append(warnings, Warning{
			Kind: KindNoUpstreamStatus, Path: path,
			Detail: "format has no $upstream_status — what the backend answered cannot be told apart from what nginx returned on its own (its 502 page, a cached 200 over a dead backend)",
		})
	}
	if len(cfg.Upstreams) > 0 && !vars[proxyHostField] {
		// The filter is dropped rather than applied to an always-empty field:
		// a silent zero stream is indistinguishable from "the site has no
		// traffic", which is the worst outcome available here.
		warnings = append(warnings, Warning{
			Kind: KindUpstreamFilterOff, Path: path,
			Detail: "Upstreams is set but format has no $proxy_host — the filter is ignored rather than dropping every line",
		})
	}
	return warnings, false
}

func varsOf(format string) map[string]bool {
	out := map[string]bool{}
	for _, m := range varRe.FindAllStringSubmatch(format, -1) {
		out[m[1]] = true
	}
	return out
}

func anyOf(vars map[string]bool, names []string) bool {
	for _, n := range names {
		if vars[n] {
			return true
		}
	}
	return false
}
