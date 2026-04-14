package nginx

import (
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// DiscoverResult holds the result of parsing nginx configuration.
type DiscoverResult struct {
	LogFormats      map[string]string // name → format string
	JSONFormats     map[string]bool   // name → true if format is JSON (escape=json)
	AccessLogs      []AccessLogEntry
	SSLCertificates []string // deduplicated ssl_certificate paths
	StubStatusPath  string   // e.g. "/stub_status", empty if not found
	StubStatusPort  int      // listen port of the server with stub_status
	APIStatusPath   string   // e.g. "/status/", empty if not found (Angie api directive)
	APIStatusPort   int      // listen port of the server with api directive
}

// AccessLogEntry represents a single access_log directive from nginx config.
type AccessLogEntry struct {
	Path       string
	FormatName string
}

var (
	logFormatStart = regexp.MustCompile(`log_format\s+(\S+)\s+`)
	accessLogRe    = regexp.MustCompile(`access_log\s+(\S+)\s+(\w+)`)
	includeRe      = regexp.MustCompile(`include\s+(\S+)\s*;`)
	stubStatusRe   = regexp.MustCompile(`stub_status\s*;`)
	apiStatusRe    = regexp.MustCompile(`api\s+/\S+\s*;`)
	locationRe     = regexp.MustCompile(`location\s+(?:=\s+)?(\S+)\s*\{`)
	listenRe       = regexp.MustCompile(`listen\s+(?:\S+:)?(\d+)`)
	sslCertRe      = regexp.MustCompile(`ssl_certificate\s+(?:"([^"]+)"|(\S+))\s*;`)
)

// DiscoverConfig parses nginx.conf and all includes, extracting log_format and access_log directives.
func DiscoverConfig(configPath string) (*DiscoverResult, error) {
	result := &DiscoverResult{
		LogFormats:  make(map[string]string),
		JSONFormats: make(map[string]bool),
	}

	dir := filepath.Dir(configPath)
	if err := parseFile(configPath, dir, result); err != nil {
		return nil, err
	}

	return result, nil
}

func parseFile(path, baseDir string, result *DiscoverResult) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	content := string(data)

	extractLogFormats(content, result)
	extractStubStatus(content, result)
	extractAPIStatus(content, result)
	extractSSLCertificates(content, result)

	// Extract access_log directives.
	for _, m := range accessLogRe.FindAllStringSubmatch(content, -1) {
		logPath := strings.TrimRight(m[1], ";")
		formatName := m[2]
		if logPath == "off" {
			continue
		}
		result.AccessLogs = append(result.AccessLogs, AccessLogEntry{Path: logPath, FormatName: formatName})
	}

	// Follow includes. Relative paths are resolved against baseDir
	// (the nginx prefix/conf directory), matching nginx behavior.
	for _, m := range includeRe.FindAllStringSubmatch(content, -1) {
		pattern := m[1]
		if !filepath.IsAbs(pattern) {
			pattern = filepath.Join(baseDir, pattern)
		}
		matches, err := filepath.Glob(pattern)
		if err != nil {
			continue
		}
		for _, inc := range matches {
			if err := parseFile(inc, baseDir, result); err != nil {
				slog.Debug("nginx: failed to parse include", "path", inc, "error", err) //nolint:sloglint
			}
		}
	}

	return nil
}

// directiveMatch holds the result of findDirective.
type directiveMatch struct {
	path string
	port int
}

// findDirective scans content for a directive matching re, tracking the current
// location and listen port. pathFn extracts the path from the matched line and
// the current location context.
func findDirective(content string, re *regexp.Regexp, pathFn func(line, currentLocation string) string) *directiveMatch {
	if !re.MatchString(content) {
		return nil
	}

	lines := strings.Split(content, "\n")
	var currentLocation string
	var currentPort int

	for _, line := range lines {
		l := strings.TrimSpace(line)
		if strings.HasPrefix(l, "#") {
			continue
		}

		if m := listenRe.FindStringSubmatch(l); m != nil {
			if p, err := strconv.Atoi(m[1]); err == nil {
				currentPort = p
			}
		}
		if m := locationRe.FindStringSubmatch(l); m != nil {
			currentLocation = m[1]
		}
		if re.MatchString(l) {
			return &directiveMatch{
				path: pathFn(l, currentLocation),
				port: currentPort,
			}
		}
	}
	return nil
}

func extractStubStatus(content string, result *DiscoverResult) {
	if result.StubStatusPath != "" {
		return
	}
	if m := findDirective(content, stubStatusRe, func(_, loc string) string { return loc }); m != nil {
		result.StubStatusPath = m.path
		result.StubStatusPort = m.port
	}
}

func extractAPIStatus(content string, result *DiscoverResult) {
	if result.APIStatusPath != "" {
		return
	}
	if m := findDirective(content, apiStatusRe, func(line, loc string) string {
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			if p := strings.TrimSuffix(parts[1], ";"); p != "" {
				return p
			}
		}
		return loc
	}); m != nil {
		result.APIStatusPath = m.path
		result.APIStatusPort = m.port
	}
}

// extractLogFormats parses multi-line log_format directives.
// nginx format: log_format name 'part1'\n                       'part2'\n ... ;
func extractLogFormats(content string, result *DiscoverResult) {
	lines := strings.Split(content, "\n")
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		m := logFormatStart.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		name := m[1]

		// Collect all quoted parts until semicolon.
		var parts []string
		for j := i; j < len(lines); j++ {
			l := strings.TrimSpace(lines[j])
			parts = append(parts, extractQuotedParts(l)...)
			if strings.HasSuffix(l, ";") {
				i = j
				break
			}
		}

		if len(parts) > 0 {
			joined := strings.Join(parts, "")
			result.LogFormats[name] = joined
			if strings.HasPrefix(joined, "{") {
				result.JSONFormats[name] = true
			}
		}
	}
}

// extractSSLCertificates extracts ssl_certificate paths, deduplicating across server blocks.
func extractSSLCertificates(content string, result *DiscoverResult) {
	seen := make(map[string]bool, len(result.SSLCertificates))
	for _, p := range result.SSLCertificates {
		seen[p] = true
	}

	for _, line := range strings.Split(content, "\n") {
		l := strings.TrimSpace(line)
		if strings.HasPrefix(l, "#") {
			continue
		}
		if strings.Contains(l, "ssl_certificate_key") {
			continue
		}
		m := sslCertRe.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		path := m[1] // quoted
		if path == "" {
			path = m[2] // unquoted
		}
		if path == "" || seen[path] {
			continue
		}
		seen[path] = true
		result.SSLCertificates = append(result.SSLCertificates, path)
	}
}

// extractQuotedParts extracts content from single-quoted strings in a line.
func extractQuotedParts(line string) []string {
	var parts []string
	for {
		start := strings.IndexByte(line, '\'')
		if start < 0 {
			break
		}
		end := strings.IndexByte(line[start+1:], '\'')
		if end < 0 {
			break
		}
		parts = append(parts, line[start+1:start+1+end])
		line = line[start+1+end+1:]
	}
	return parts
}
