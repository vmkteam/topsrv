package botlog

import (
	"regexp"
	"slices"
	"strings"
)

// FieldAliases resolves the per-format names of the five nginx variables
// botlog needs. For non-JSON formats the value is the nginx variable name
// (matches gonx's field naming, e.g. "http_referer" for "$http_referer").
// For JSON formats the value is the JSON key wrapping the variable in the
// log_format (e.g. "ref" for `"ref":"$http_referer"`). An empty string means
// the format doesn't carry the field and downstream code should ship empty.
type FieldAliases struct {
	UserAgent  string
	Host       string
	ServerName string
	RemoteAddr string
	Referer    string
}

// DefaultAliases returns the canonical nginx variable names — used as the
// last-resort fallback when discovery is unavailable and no explicit
// override is configured.
func DefaultAliases() FieldAliases {
	return FieldAliases{
		UserAgent:  fieldUserAgent,
		Host:       fieldHost,
		ServerName: fieldServerName,
		RemoteAddr: fieldRemoteAddr,
		Referer:    fieldReferer,
	}
}

// Merge returns a copy of a with each empty field replaced by the
// corresponding non-empty value from other. Used to layer defaults under
// auto-detected results, and explicit operator overrides on top.
func (a FieldAliases) Merge(other FieldAliases) FieldAliases {
	out := a
	if out.UserAgent == "" {
		out.UserAgent = other.UserAgent
	}
	if out.Host == "" {
		out.Host = other.Host
	}
	if out.ServerName == "" {
		out.ServerName = other.ServerName
	}
	if out.RemoteAddr == "" {
		out.RemoteAddr = other.RemoteAddr
	}
	if out.Referer == "" {
		out.Referer = other.Referer
	}
	return out
}

// Names returns the resolved field names in a stable order, dropping empty
// entries — suitable for merging into LogConfig.ExtractFields so the parser
// knows which nginx variables to copy into ParsedLine.Extras.
func (a FieldAliases) Names() []string {
	out := []string{a.UserAgent, a.Host, a.ServerName, a.RemoteAddr, a.Referer}
	return slices.DeleteFunc(out, func(s string) bool { return s == "" })
}

// Known nginx-variable variants per semantic field. First match wins.
// Ordering reflects operator preference (standard → common typo → fallback).
var (
	uaCandidates      = []string{"http_user_agent"}
	hostCandidates    = []string{"host", "http_host"}
	serverCandidates  = []string{"server_name"}
	remoteCandidates  = []string{"remote_addr", "http_x_real_ip", "http_x_forwarded_for"}
	refererCandidates = []string{"http_referer", "http_referrer", "referer"}
)

// DetectAliases inspects an nginx log_format string and returns the resolved
// field name for each semantic field. Empty values for fields the format
// doesn't carry — caller layers DefaultAliases under and explicit override on
// top via Merge.
//
// For non-JSON formats (combined / key=value / logfmt / hybrid), the result
// is the nginx variable name without the '$' prefix. For JSON formats, the
// result is the JSON key wrapping the variable in the format string.
func DetectAliases(format string, isJSON bool) FieldAliases {
	if isJSON {
		return FieldAliases{
			UserAgent:  detectJSONKey(format, uaCandidates),
			Host:       detectJSONKey(format, hostCandidates),
			ServerName: detectJSONKey(format, serverCandidates),
			RemoteAddr: detectJSONKey(format, remoteCandidates),
			Referer:    detectJSONKey(format, refererCandidates),
		}
	}
	return FieldAliases{
		UserAgent:  detectTextVar(format, uaCandidates),
		Host:       detectTextVar(format, hostCandidates),
		ServerName: detectTextVar(format, serverCandidates),
		RemoteAddr: detectTextVar(format, remoteCandidates),
		Referer:    detectTextVar(format, refererCandidates),
	}
}

// detectTextVar returns the first candidate that appears as $candidate in
// format (word-boundary delimited, so $http_referer does not match
// $http_referrer). gonx uses the variable name itself as the field name,
// so the returned string is the lookup key for entry.Field().
func detectTextVar(format string, candidates []string) string {
	for _, name := range candidates {
		if textVarRe(name).MatchString(format) {
			return name
		}
	}
	return ""
}

// detectJSONKey returns the JSON key that wraps the first matched candidate
// variable in a JSON log_format — patterns like `"<key>":"$<variable>"` or
// the variant with whitespace around the colon. Returns "" if no candidate
// is wrapped.
func detectJSONKey(format string, candidates []string) string {
	for _, name := range candidates {
		if m := jsonKeyRe(name).FindStringSubmatch(format); m != nil {
			return m[1]
		}
	}
	return ""
}

// textVarRe matches "$name" with a word boundary so http_referer does not
// accidentally match the longer http_referrer. Cached per name across calls.
func textVarRe(name string) *regexp.Regexp {
	return regexp.MustCompile(`\$` + regexp.QuoteMeta(name) + `\b`)
}

// jsonKeyRe matches `"<key>":"$<name>"` (with optional whitespace around the
// colon) and captures the JSON key. The variable side is word-boundaried so
// $http_referer does not consume $http_referrer's key.
func jsonKeyRe(name string) *regexp.Regexp {
	return regexp.MustCompile(`"([^"]+)"\s*:\s*"\$` + regexp.QuoteMeta(name) + `\b`)
}

// String renders aliases as a one-liner suitable for startup logging.
func (a FieldAliases) String() string {
	var sb strings.Builder
	sb.WriteString("ua=")
	sb.WriteString(orDash(a.UserAgent))
	sb.WriteString(" host=")
	sb.WriteString(orDash(a.Host))
	sb.WriteString(" server=")
	sb.WriteString(orDash(a.ServerName))
	sb.WriteString(" remote=")
	sb.WriteString(orDash(a.RemoteAddr))
	sb.WriteString(" referer=")
	sb.WriteString(orDash(a.Referer))
	return sb.String()
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
