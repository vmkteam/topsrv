package sshdconf

import (
	"fmt"
	"io/fs"
	"path"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// memFiles serves a configuration from a map of path → content.
func memFiles(files map[string]string) Files {
	return Files{
		ReadFile: func(p string) ([]byte, error) {
			b, ok := files[p]
			if !ok {
				return nil, fs.ErrNotExist
			}
			return []byte(b), nil
		},
		ReadDir: func(dir string) ([]string, error) {
			var names []string
			for p := range files {
				if path.Dir(p) == dir {
					names = append(names, path.Base(p))
				}
			}
			if names == nil {
				return nil, fs.ErrNotExist
			}
			return names, nil
		},
	}
}

func parse(t *testing.T, files map[string]string, opts Options) *Config {
	t.Helper()
	return Parse(DefaultConfig, opts, memFiles(files))
}

func TestSplitLine(t *testing.T) {
	cases := []struct {
		line string
		kw   string
		args []string
		code string
	}{
		{"Port 22", "Port", []string{"22"}, ""},
		{"Port=22", "Port", []string{"22"}, ""},
		{"Port = 22", "Port", []string{"22"}, ""},
		{"  Port\t22  # trailing comment", "Port", []string{"22"}, ""},
		{"PasswordAuthentication yes\r", "PasswordAuthentication", []string{"yes"}, ""},
		{`Banner "/etc/my banner"`, "Banner", []string{"/etc/my banner"}, ""},
		{`AuthorizedKeysFile .ssh/a\ b 'c d'`, "AuthorizedKeysFile", []string{".ssh/a b", "c d"}, ""},
		{`ForceCommand echo "a\"b" x#y`, "ForceCommand", []string{"echo", `a"b`, "x#y"}, ""},
		{`Banner "unterminated`, "Banner", nil, CodeUnterminatedQuote},
		{"# comment", "", nil, ""},
		{"   ", "", nil, ""},
		{"UsePAM", "UsePAM", nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.line, func(t *testing.T) {
			kw, args, code := splitLine(tc.line)
			assert.Equal(t, tc.kw, kw)
			assert.Equal(t, tc.args, args)
			assert.Equal(t, tc.code, code)
		})
	}
}

func TestMatch(t *testing.T) {
	cases := []struct {
		pattern, name string
		want          bool
	}{
		{"*.conf", "50-cloud-init.conf", true},
		{"*.conf", ".hidden.conf", false},
		{".*.conf", ".hidden.conf", true},
		{"*", "a.conf", true},
		{"*", ".a", false},
		{"?0-*", "50-x", true},
		{"[0-9]*", "5x", true},
		{"[!0-9]*", "5x", false},
		{"[!0-9]*", "x5", true},
		{"[]a]", "]", true},
		{"[a", "[a", true},
		{`\*`, "*", true},
		{`\*`, "a", false},
		{"a*b*c", "aXbYc", true},
		{"a*b*c", "aXbY", false},
		{"*.conf", "a.conf.bak", false},
		{strings.Repeat("*a", 20) + "b", strings.Repeat("a", 200), false},
	}
	for _, tc := range cases {
		t.Run(tc.pattern+" "+tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, Match(tc.pattern, tc.name))
		})
	}
}

func TestParseOrderAndClasses(t *testing.T) {
	cfg := parse(t, map[string]string{
		DefaultConfig: "Include /etc/ssh/sshd_config.d/*.conf\n" +
			"PermitRootLogin without-password\n" +
			"PasswordAuthentication no\n" +
			"Port 22\n" +
			"AllowUsers alice\n" +
			"AuthorizedKeysFile .ssh/authorized_keys .ssh/authorized_keys2\n" +
			"AuthorizedKeysFile /etc/ssh/keys/%u\n" +
			"KbdInteractiveAuthentication yes\n" +
			"DebianBanner no\n",
		"/etc/ssh/sshd_config.d/50-cloud-init.conf": "PasswordAuthentication yes\r\nPort=2222\r\n",
		"/etc/ssh/sshd_config.d/10-redhat.conf":     "ChallengeResponseAuthentication no\nAllowUsers bob carol\n",
		"/etc/ssh/sshd_config.d/.hidden.conf":       "PermitRootLogin yes\n",
		"/etc/ssh/sshd_config.d/notes.txt":          "PermitRootLogin yes\n",
	}, Options{})

	assert.True(t, cfg.Valid(), "errors: %v %v", cfg.Errors, cfg.ReadErrors)
	assert.Equal(t, []string{DefaultConfig, "/etc/ssh/sshd_config.d/10-redhat.conf", "/etc/ssh/sshd_config.d/50-cloud-init.conf"}, cfg.Files,
		"glob order, no hidden files, no other suffixes")
	assert.Equal(t, Value{Values: []string{"yes"}, Source: "/etc/ssh/sshd_config.d/50-cloud-init.conf:1"}, cfg.Global["PasswordAuthentication"],
		"cloud-init's drop-in comes first and wins")
	assert.Equal(t, Value{Values: []string{"no"}, Source: "/etc/ssh/sshd_config.d/10-redhat.conf:1"}, cfg.Global["KbdInteractiveAuthentication"],
		"ChallengeResponseAuthentication shares the slot and came first")
	assert.Equal(t, []string{"prohibit-password"}, cfg.Global["PermitRootLogin"].Values)
	assert.Equal(t, []string{"2222", "22"}, cfg.Global["Port"].Values, "ports accumulate")
	assert.Equal(t, []string{"bob", "carol", "alice"}, cfg.Global["AllowUsers"].Values)
	assert.Equal(t, Value{Values: []string{".ssh/authorized_keys", ".ssh/authorized_keys2"}, Source: DefaultConfig + ":6"}, cfg.Global["AuthorizedKeysFile"],
		"the first line, whole")
	assert.Equal(t, []Ref{{File: DefaultConfig, Line: 9, Code: "DebianBanner"}}, cfg.Unknown)
}

func TestParseCmdline(t *testing.T) {
	files := map[string]string{DefaultConfig: "Port 22\nPermitRootLogin no\nPasswordAuthentication no\n"}

	cfg := parse(t, files, Options{Options: []string{"PermitRootLogin=yes", "PasswordAuthentication yes"}, Ports: []string{"2200"}})

	assert.Equal(t, Value{Values: []string{"yes"}, Source: "cmdline"}, cfg.Global["PermitRootLogin"], "-o comes first and wins")
	assert.Equal(t, Value{Values: []string{"yes"}, Source: "cmdline"}, cfg.Global["PasswordAuthentication"])
	assert.Equal(t, Value{Values: []string{"2200"}, Source: "cmdline"}, cfg.Global["Port"], "-p drops the Port lines")
}

func TestParseMatch(t *testing.T) {
	cfg := parse(t, map[string]string{
		DefaultConfig: "PasswordAuthentication no\n" +
			"Include /etc/ssh/inc.conf\n" +
			"X11Forwarding no\n" +
			"Match User alice\n" +
			"  PasswordAuthentication yes\n" +
			"  Include /etc/ssh/inmatch.conf\n" +
			"  Port 2222\n" +
			"Match All\n" +
			"PermitRootLogin no\n",
		"/etc/ssh/inc.conf":     "Match Address 10.0.0.0/8\nAllowTcpForwarding yes\n",
		"/etc/ssh/inmatch.conf": "MaxAuthTries 2\n",
	}, Options{})

	assert.Equal(t, []string{"no"}, cfg.Global["X11Forwarding"].Values, "a Match in an include ends with the file")
	assert.Equal(t, []string{"no"}, cfg.Global["PermitRootLogin"].Values, "Match All returns to the global context")
	assert.Equal(t, []string{"no"}, cfg.Global["PasswordAuthentication"].Values, "a Match block does not change the global value")
	assert.NotContains(t, cfg.Global, "AllowTcpForwarding")
	require.Len(t, cfg.MatchBlocks, 2)
	assert.Equal(t, []string{"Address", "10.0.0.0/8"}, cfg.MatchBlocks[0].Criteria)
	assert.Equal(t, "/etc/ssh/inc.conf:1", cfg.MatchBlocks[0].Source)
	assert.Contains(t, cfg.MatchBlocks[0].Keys, "AllowTcpForwarding")
	alice := cfg.MatchBlocks[1]
	assert.Equal(t, []string{"yes"}, alice.Keys["PasswordAuthentication"].Values)
	assert.Equal(t, []string{"2"}, alice.Keys["MaxAuthTries"].Values, "an include inside a Match belongs to it")
	assert.Equal(t, []Ref{{File: DefaultConfig, Line: 7, Code: CodeNotInMatch}}, cfg.Errors, "Port is global only")
}

func TestParseInclude(t *testing.T) {
	t.Run("relative to /etc/ssh, a pattern without matches is fine", func(t *testing.T) {
		cfg := parse(t, map[string]string{
			DefaultConfig:            "Include extra.conf missing.conf nothere/*.conf\nPermitRootLogin no\n",
			"/etc/ssh/extra.conf":    "PermitRootLogin yes\n",
			"/etc/ssh/unrelated.cfg": "",
		}, Options{})

		assert.True(t, cfg.Valid(), "%v %v", cfg.Errors, cfg.ReadErrors)
		assert.Equal(t, []string{"yes"}, cfg.Global["PermitRootLogin"].Values)
	})

	t.Run("a loop stops at depth 16 and makes the config invalid", func(t *testing.T) {
		cfg := parse(t, map[string]string{DefaultConfig: "Include /etc/ssh/sshd_config\n"}, Options{})

		assert.False(t, cfg.Valid())
		assert.Len(t, cfg.Files, maxIncludeDepth+1)
		require.Len(t, cfg.Errors, 1)
		assert.Equal(t, CodeIncludeDepth, cfg.Errors[0].Code)
	})

	t.Run("depth 16 is allowed, 17 is not", func(t *testing.T) {
		chain := func(n int) map[string]string {
			files := map[string]string{DefaultConfig: "Include /etc/ssh/1.conf\n"}
			for i := 1; i < n; i++ {
				files[fmt.Sprintf("/etc/ssh/%d.conf", i)] = fmt.Sprintf("Include /etc/ssh/%d.conf\n", i+1)
			}
			files[fmt.Sprintf("/etc/ssh/%d.conf", n)] = "PermitRootLogin no\n"
			return files
		}
		assert.True(t, parse(t, chain(16), Options{}).Valid())
		assert.False(t, parse(t, chain(17), Options{}).Valid())
	})

	t.Run("an unreadable include is a read error", func(t *testing.T) {
		files := memFiles(map[string]string{DefaultConfig: "Include /etc/ssh/sshd_config.d/*.conf\n", "/etc/ssh/sshd_config.d/50-x.conf": ""})
		read := files.ReadFile
		files.ReadFile = func(p string) ([]byte, error) {
			if strings.HasSuffix(p, "50-x.conf") {
				return nil, fs.ErrPermission
			}
			return read(p)
		}

		cfg := Parse(DefaultConfig, Options{}, files)

		assert.False(t, cfg.Valid())
		require.Len(t, cfg.ReadErrors, 1)
		assert.ErrorIs(t, cfg.ReadErrors[0].Err, fs.ErrPermission)
	})

	t.Run("at most 256 files", func(t *testing.T) {
		files := map[string]string{DefaultConfig: "Include /etc/ssh/d/*.conf\n"}
		for i := range maxFiles + 10 {
			files[fmt.Sprintf("/etc/ssh/d/%03d.conf", i)] = ""
		}

		cfg := parse(t, files, Options{})

		assert.Len(t, cfg.Files, maxFiles)
		assert.False(t, cfg.Valid())
	})
}

func TestParseErrors(t *testing.T) {
	cfg := parse(t, map[string]string{
		DefaultConfig: "Banner \"SENTINELLINE\nPort\nPermitRootLogin yes no\nMatch\nBogus SENTINELLINE\n#!# x\nweird-key! x\n",
	}, Options{})

	assert.Equal(t, []Ref{
		{File: DefaultConfig, Line: 1, Code: CodeUnterminatedQuote},
		{File: DefaultConfig, Line: 2, Code: CodeMissingArgument},
		{File: DefaultConfig, Line: 3, Code: CodeExtraArguments},
		{File: DefaultConfig, Line: 4, Code: CodeBadMatch},
	}, cfg.Errors)
	assert.Equal(t, []Ref{
		{File: DefaultConfig, Line: 5, Code: "Bogus"},
		{File: DefaultConfig, Line: 7, Code: "invalid"},
	}, cfg.Unknown)
	assert.NotContains(t, fmt.Sprint(cfg), "SENTINELLINE", "no line text anywhere")
}

func TestParseFlags(t *testing.T) {
	cases := []struct {
		args []string
		want Flags
	}{
		{nil, Flags{ConfigFile: DefaultConfig}},
		{[]string{"-D"}, Flags{ConfigFile: DefaultConfig}},
		{[]string{"-D", "-f", "/etc/ssh/alt", "-p2222", "-o", "PermitRootLogin=no"},
			Flags{ConfigFile: "/etc/ssh/alt", Ports: []string{"2222"}, Options: []string{"PermitRootLogin=no"}}},
		{[]string{"-Def/etc/ssh/x"}, Flags{ConfigFile: "/etc/ssh/x"}},
		{[]string{"-o", "PasswordAuthentication", "no", "-D"}, Flags{ConfigFile: DefaultConfig, Options: []string{"PasswordAuthentication no"}}},
	}
	for _, tc := range cases {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			assert.Equal(t, tc.want, ParseFlags(tc.args))
		})
	}
}

func TestListenerArgs(t *testing.T) {
	cases := []struct {
		name    string
		cmdline string
		args    []string
		ok      bool
	}{
		{"title of 8.2+", "sshd: /usr/sbin/sshd -D -p 2222 [listener] 0 of 10-100 startups\x00\x00\x00", []string{"-D", "-p", "2222"}, true},
		{"old argv", "/usr/sbin/sshd\x00-D\x00-f\x00/etc/ssh/alt\x00", []string{"-D", "-f", "/etc/ssh/alt"}, true},
		{"bare", "/usr/sbin/sshd\x00", []string{}, true},
		{"a session", "sshd: alice@pts/0\x00", nil, false},
		{"pre-auth", "sshd: alice [priv]\x00", nil, false},
		{"sshd-session", "/usr/lib/openssh/sshd-session\x00-R\x00", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args, ok := ListenerArgs([]byte(tc.cmdline))
			assert.Equal(t, tc.ok, ok)
			if tc.ok {
				assert.Equal(t, tc.args, args)
			}
		})
	}
}

func TestKeywordTable(t *testing.T) {
	for name, k := range keywords {
		if _, alias := aliases[name]; !alias {
			assert.Equal(t, name, strings.ToLower(k.name), "the key is the lower-case name")
		}
	}
	for alias, target := range aliases {
		assert.Contains(t, keywords, target, alias)
	}
	assert.True(t, slices.ContainsFunc([]string{"permitrootlogin", "usepam", "authorizedkeysfile"}, func(n string) bool { _, ok := keywords[n]; return ok }))
}

func FuzzSplitLine(f *testing.F) {
	for _, seed := range []string{"Port 22", `Banner "a b"`, `X a\ b 'c d' # e`, "Key=value", `"unterminated`, "=\t=", `\\\"`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, line string) {
		kw, args, code := splitLine(line)
		if code != "" && args != nil {
			t.Fatalf("args with an error: %q", args)
		}
		if strings.ContainsAny(kw, " \t\r\n") {
			t.Fatalf("whitespace in keyword %q", kw)
		}
	})
}
