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
	LogFormats     map[string]string // name → format string
	AccessLogs     []AccessLogEntry
	StubStatusPath string // e.g. "/stub_status", empty if not found
	StubStatusPort int    // listen port of the server with stub_status
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
	locationRe     = regexp.MustCompile(`location\s+(?:=\s+)?(\S+)\s*\{`)
	listenRe       = regexp.MustCompile(`listen\s+(?:\S+:)?(\d+)`)
)

// DiscoverConfig parses nginx.conf and all includes, extracting log_format and access_log directives.
func DiscoverConfig(configPath string) (*DiscoverResult, error) {
	result := &DiscoverResult{
		LogFormats: make(map[string]string),
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

	// Extract access_log directives.
	for _, m := range accessLogRe.FindAllStringSubmatch(content, -1) {
		logPath := strings.TrimRight(m[1], ";")
		formatName := m[2]
		if logPath == "off" {
			continue
		}
		result.AccessLogs = append(result.AccessLogs, AccessLogEntry{Path: logPath, FormatName: formatName})
	}

	// Follow includes.
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
			if err := parseFile(inc, filepath.Dir(inc), result); err != nil {
				slog.Debug("nginx: failed to parse include", "path", inc, "error", err) //nolint:sloglint
			}
		}
	}

	return nil
}

// extractStubStatus finds stub_status directive and its location path + listen port.
func extractStubStatus(content string, result *DiscoverResult) {
	if result.StubStatusPath != "" {
		return // already found in another file
	}
	if !stubStatusRe.MatchString(content) {
		return
	}

	lines := strings.Split(content, "\n")
	var currentLocation string
	var currentPort int

	for _, line := range lines {
		l := strings.TrimSpace(line)

		if m := listenRe.FindStringSubmatch(l); m != nil {
			if p, err := strconv.Atoi(m[1]); err == nil {
				currentPort = p
			}
		}
		if m := locationRe.FindStringSubmatch(l); m != nil {
			currentLocation = m[1]
		}
		if stubStatusRe.MatchString(l) {
			result.StubStatusPath = currentLocation
			result.StubStatusPort = currentPort
			return
		}
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
			result.LogFormats[name] = strings.Join(parts, "")
		}
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
