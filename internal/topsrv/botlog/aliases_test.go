package botlog

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDefaultAliases(t *testing.T) {
	a := DefaultAliases()
	assert.Equal(t, "http_user_agent", a.UserAgent)
	assert.Equal(t, "host", a.Host)
	assert.Equal(t, "server_name", a.ServerName)
	assert.Equal(t, "remote_addr", a.RemoteAddr)
	assert.Equal(t, "http_referer", a.Referer)
}

func TestFieldAliases_Names(t *testing.T) {
	a := FieldAliases{UserAgent: "ua", Host: "", ServerName: "sn", RemoteAddr: "ip", Referer: "ref"}
	assert.Equal(t, []string{"ua", "sn", "ip", "ref"}, a.Names())
}

func TestFieldAliases_Merge(t *testing.T) {
	base := DefaultAliases()
	override := FieldAliases{Referer: "ref"}
	got := override.Merge(base)
	assert.Equal(t, "ref", got.Referer, "override wins")
	assert.Equal(t, "http_user_agent", got.UserAgent, "empty falls back to base")
	assert.Equal(t, "host", got.Host)
}

func TestDetectAliases_TextCombined(t *testing.T) {
	// Standard combined format — every field uses the canonical variable.
	format := `$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"`
	got := DetectAliases(format, false)
	assert.Equal(t, "http_user_agent", got.UserAgent)
	assert.Equal(t, "remote_addr", got.RemoteAddr)
	assert.Equal(t, "http_referer", got.Referer)
	assert.Empty(t, got.Host, "combined format has no $host")
	assert.Empty(t, got.ServerName)
}

func TestDetectAliases_TextKeyValue(t *testing.T) {
	// Key=value style: $variables wrapped in literal label="..." pairs.
	// gonx still names fields after the variable, not the wrapper.
	format := `time="$time_iso8601" h="$host" sn="$server_name" ip="$remote_addr" ua="$http_user_agent" ref="$http_referer"`
	got := DetectAliases(format, false)
	assert.Equal(t, "host", got.Host)
	assert.Equal(t, "server_name", got.ServerName)
	assert.Equal(t, "remote_addr", got.RemoteAddr)
	assert.Equal(t, "http_user_agent", got.UserAgent)
	assert.Equal(t, "http_referer", got.Referer)
}

func TestDetectAliases_TextLogfmt(t *testing.T) {
	// Bare key=$var (no quotes around values).
	format := `time=$time_local host=$host ua=$http_user_agent referer=$http_referer`
	got := DetectAliases(format, false)
	assert.Equal(t, "host", got.Host)
	assert.Equal(t, "http_user_agent", got.UserAgent)
	assert.Equal(t, "http_referer", got.Referer)
}

func TestDetectAliases_TextHybridWithFallbacks(t *testing.T) {
	// Hybrid format: no $remote_addr (uses XFF), no $http_referer (uses
	// http_referrer typo variant). Both should be picked up via fallback.
	format := `$http_x_forwarded_for [$time_local] "$request" $status "$http_referrer" "$http_user_agent" h="$host"`
	got := DetectAliases(format, false)
	assert.Equal(t, "http_x_forwarded_for", got.RemoteAddr, "falls back to XFF when remote_addr absent")
	assert.Equal(t, "http_referrer", got.Referer, "picks up typo variant")
	assert.Equal(t, "http_user_agent", got.UserAgent)
	assert.Equal(t, "host", got.Host)
}

func TestDetectAliases_TextWordBoundary(t *testing.T) {
	// $http_referrer must NOT be matched by the $http_referer candidate.
	// Without word boundary, regex would match the prefix and report wrong.
	format := `... "$http_referrer" ...`
	got := DetectAliases(format, false)
	assert.Equal(t, "http_referrer", got.Referer)
}

func TestDetectAliases_JSONStandardKeys(t *testing.T) {
	// dl.old-games.su-style: JSON keys match the nginx variable name 1:1.
	format := `{"time_local":"$time_local","remote_addr":"$remote_addr","host":"$host","request_uri":"$request_uri","http_referer":"$http_referer","http_user_agent":"$http_user_agent"}`
	got := DetectAliases(format, true)
	assert.Equal(t, "remote_addr", got.RemoteAddr)
	assert.Equal(t, "host", got.Host)
	assert.Equal(t, "http_referer", got.Referer)
	assert.Equal(t, "http_user_agent", got.UserAgent)
	assert.Empty(t, got.ServerName, "format omits server_name")
}

func TestDetectAliases_JSONCustomKeys(t *testing.T) {
	// Operator chose short keys: "ua", "ref", "ip". Our code must follow.
	format := `{"ua":"$http_user_agent","ip":"$remote_addr","ref":"$http_referer","h":"$host"}`
	got := DetectAliases(format, true)
	assert.Equal(t, "ua", got.UserAgent)
	assert.Equal(t, "ip", got.RemoteAddr)
	assert.Equal(t, "ref", got.Referer)
	assert.Equal(t, "h", got.Host)
}

func TestDetectAliases_JSONWhitespace(t *testing.T) {
	// Some operators pretty-print log_format with spaces around the colon.
	format := `{"http_user_agent" : "$http_user_agent", "host":"$host"}`
	got := DetectAliases(format, true)
	assert.Equal(t, "http_user_agent", got.UserAgent)
	assert.Equal(t, "host", got.Host)
}

func TestDetectAliases_JSONReferrerTypo(t *testing.T) {
	// Operator's JSON key has the typo, nginx variable too.
	format := `{"http_referrer":"$http_referrer","http_user_agent":"$http_user_agent"}`
	got := DetectAliases(format, true)
	assert.Equal(t, "http_referrer", got.Referer)
}

func TestDetectAliases_JSONFallbackToXFF(t *testing.T) {
	// JSON format without $remote_addr — pick XFF as the next best identity.
	format := `{"client_ip":"$http_x_forwarded_for","ua":"$http_user_agent"}`
	got := DetectAliases(format, true)
	assert.Equal(t, "client_ip", got.RemoteAddr)
}

func TestDetectAliases_EmptyFormatGivesEmpty(t *testing.T) {
	// Format with none of the candidates — every alias empty. Caller layers
	// DefaultAliases or surfaces a startup warning.
	got := DetectAliases(`$status $body_bytes_sent`, false)
	assert.Equal(t, FieldAliases{}, got)
}
