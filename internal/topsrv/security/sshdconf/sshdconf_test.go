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

func parse(t *testing.T, files map[string]string, flags Flags) *Config {
	t.Helper()
	if flags.ConfigFile == "" {
		flags.ConfigFile = DefaultConfig
	}
	return Parse(flags, memFiles(files))
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
	}, Flags{})

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

	cfg := parse(t, files, Flags{Options: []string{"PermitRootLogin=yes", "PasswordAuthentication yes"}, Ports: []string{"2200"}})

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
	}, Flags{})

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
		}, Flags{})

		assert.True(t, cfg.Valid(), "%v %v", cfg.Errors, cfg.ReadErrors)
		assert.Equal(t, []string{"yes"}, cfg.Global["PermitRootLogin"].Values)
	})

	t.Run("a loop stops at depth 16 and makes the config invalid", func(t *testing.T) {
		cfg := parse(t, map[string]string{DefaultConfig: "Include /etc/ssh/sshd_config\n"}, Flags{})

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
		assert.True(t, parse(t, chain(16), Flags{}).Valid())
		assert.False(t, parse(t, chain(17), Flags{}).Valid())
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

		cfg := Parse(Flags{ConfigFile: DefaultConfig}, files)

		assert.False(t, cfg.Valid())
		require.Len(t, cfg.ReadErrors, 1)
		assert.ErrorIs(t, cfg.ReadErrors[0].Err, fs.ErrPermission)
	})

	t.Run("at most 256 files", func(t *testing.T) {
		files := map[string]string{DefaultConfig: "Include /etc/ssh/d/*.conf\n"}
		for i := range maxFiles + 10 {
			files[fmt.Sprintf("/etc/ssh/d/%03d.conf", i)] = ""
		}

		cfg := parse(t, files, Flags{})

		assert.Len(t, cfg.Files, maxFiles)
		assert.False(t, cfg.Valid())
	})
}

func TestParseErrors(t *testing.T) {
	cfg := parse(t, map[string]string{
		DefaultConfig: "Banner \"SENTINELLINE\nPort\nPermitRootLogin yes no\nMatch\nBogus SENTINELLINE\n#!# x\nweird-key! x\n",
	}, Flags{})

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
	for _, k := range keywords {
		if k.enum {
			assert.Contains(t, valueChecks, k.name, "an enum keyword without the values sshd takes")
		}
	}
	for name := range valueChecks {
		k, ok := keywords[strings.ToLower(name)]
		assert.True(t, ok && k.name == name, "a check for an unknown keyword %s", name)
	}
}

func TestParseValues(t *testing.T) {
	cases := []struct {
		line  string
		valid bool
	}{
		{"PermitRootLogin without-password", true},
		{"PermitRootLogin FORCED-COMMANDS-ONLY", true},
		{"PermitRootLogin SENTINELSECRET", false},
		{"PasswordAuthentication Yes", true},
		{"PasswordAuthentication true", false},
		{"IgnoreRhosts shosts-only", true},
		{"AllowTcpForwarding local", true},
		{"PermitTunnel point-to-point", true},
		{"GatewayPorts clientspecified", true},
		{"AddressFamily inet6", true},
		{"LogLevel DEBUG3", true},
		{"LogLevel loud", false},
		{"SyslogFacility AUTHPRIV", true},
		{"FingerprintHash sha1", false},
		{"Port 2222", true},
		{"Port 0", false},
		{"Port 65536", false},
		{"Port ssh", true},
		{"Port secure-shell", true}, // an alias
		{"Port https", false},       // udp only
		{"Port SENTINELSECRET", false},
		{"MaxAuthTries 3", true},
		{"MaxAuthTries -1", false},
		{"MaxAuthTries 3x", false},
		{"ClientAliveCountMax 0", true},
		{"LoginGraceTime 1h30m", true},
		{"LoginGraceTime 90", true},
		{"LoginGraceTime m", false},
		{"ClientAliveInterval 5x", false},
		{"MaxStartups 10:30:100", true},
		{"MaxStartups 10", true},
		{"MaxStartups 10:30", false},
		{"Ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com", true},
		{"Ciphers -*-cbc", true},
		{"KexAlgorithms +sntrup761x25519-sha512", true},
		{"MACs ,hmac-sha2-256", false},
		{"HostKeyAlgorithms SENTINELSECRET", false},
		{"AuthenticationMethods publickey,password publickey,keyboard-interactive:pam", true},
		{"AuthenticationMethods any", true},
		{"AuthenticationMethods publickey,SENTINEL", false},
		{"AuthenticationMethods password:pam", true}, // sshd cuts the device off any method
		{"AuthenticationMethods none", true},
		{"AuthenticationMethods keyboard-interactive:PAM", false},
		{"AllowUsers anything@192.0.2.1", true},
		{"ListenAddress host.test.local:2222", true},
		{"ListenAddress [2001:db8::1]:22", true},
		{"ListenAddress [2001:db8::1]", true},
		{"ListenAddress 2001:db8::1", true},
		{"ListenAddress 192.0.2.1 rdomain vrf1", true},
		{"ListenAddress 192.0.2.1:SENTINEL", false},
		{"ListenAddress [2001:db8::1]:", false},
		{"ListenAddress [2001:db8::1]x", false},
	}
	files := map[string]string{"/etc/services": "ssh\t\t22/tcp\tsecure-shell\t# SSH Remote Login Protocol\nhttps 443/udp\n"}
	for _, tc := range cases {
		t.Run(tc.line, func(t *testing.T) {
			files[DefaultConfig] = tc.line + "\n"
			cfg := parse(t, files, Flags{})

			assert.Equal(t, tc.valid, cfg.Valid(), "errors: %v", cfg.Errors)
			if !tc.valid {
				assert.Equal(t, []Ref{{File: DefaultConfig, Line: 1, Code: CodeBadValue}}, cfg.Errors)
				assert.Empty(t, cfg.Global, "a refused value is never stored")
			}
		})
	}
}

func TestParseMatchCriteria(t *testing.T) {
	cases := []struct {
		line  string
		valid bool
	}{
		{"Match User alice Address 192.0.2.0/24", true},
		{"Match group admins host *.test.local", true},
		{"Match Invalid-User", true},
		{"Match Invalid-User LocalAddress 192.0.2.1", true},
		{"Match User invalid-user", true}, // a pattern, not the token
		{"Match LocalPort 2222", true},
		{"Match RDomain vrf1 Version OpenSSH_10*", true},
		{"Match LocalPort SENTINEL", false},
		{"Match SENTINELSECRET x", false},
		{"Match User", false},
		{"Match All User alice", false},
	}
	for _, tc := range cases {
		t.Run(tc.line, func(t *testing.T) {
			cfg := parse(t, map[string]string{DefaultConfig: tc.line + "\n  X11Forwarding no\n"}, Flags{})

			assert.Equal(t, tc.valid, cfg.Valid(), "errors: %v", cfg.Errors)
			if tc.valid {
				require.Len(t, cfg.MatchBlocks, 1)
				assert.Equal(t, strings.Fields(tc.line)[1:], cfg.MatchBlocks[0].Criteria)
			} else {
				assert.Equal(t, []Ref{{File: DefaultConfig, Line: 1, Code: CodeBadMatch}}, cfg.Errors)
				assert.Empty(t, cfg.MatchBlocks, "refused criteria are never stored")
			}
		})
	}
}

func TestParseBadValueSources(t *testing.T) {
	t.Run("a refused line does not hide the next one", func(t *testing.T) {
		cfg := parse(t, map[string]string{DefaultConfig: "PermitRootLogin SENTINEL\nPermitRootLogin no\n"}, Flags{})
		assert.Equal(t, "no", cfg.Global["PermitRootLogin"].Values[0])
		assert.False(t, cfg.Valid())
	})
	t.Run("in a Match block", func(t *testing.T) {
		cfg := parse(t, map[string]string{DefaultConfig: "Match User deploy\n  X11Forwarding SENTINEL\n"}, Flags{})
		assert.Empty(t, cfg.MatchBlocks[0].Keys)
		assert.Equal(t, []Ref{{File: DefaultConfig, Line: 2, Code: CodeBadValue}}, cfg.Errors)
	})
	t.Run("-o and -p", func(t *testing.T) {
		cfg := parse(t, map[string]string{DefaultConfig: "Port SENTINEL\n"},
			Flags{Ports: []string{"SENTINEL"}, Options: []string{"MaxAuthTries=SENTINEL"}})
		assert.Equal(t, []Ref{{File: SourceCmdline, Code: CodeBadValue}, {File: SourceCmdline, Code: CodeBadValue}}, cfg.Errors,
			"the Port line of the file is skipped unchecked under -p, as sshd does")
		assert.Empty(t, cfg.Global)
	})
	t.Run("a service name without /etc/services", func(t *testing.T) {
		cfg := parse(t, map[string]string{DefaultConfig: "Port ssh\n"}, Flags{})
		assert.False(t, cfg.Valid(), "getservbyname finds nothing")
	})
	t.Run("a scalar checks the value it keeps", func(t *testing.T) {
		cfg := parse(t, map[string]string{DefaultConfig: "MaxAuthTries 3 SENTINEL\n"}, Flags{})
		assert.Equal(t, []Ref{{File: DefaultConfig, Line: 1, Code: CodeExtraArguments}}, cfg.Errors)
		assert.Equal(t, []string{"3"}, cfg.Global["MaxAuthTries"].Values)
	})
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

func TestParseReviewCases(t *testing.T) {
	t.Run("an unlistable Include directory is a read error, not an empty one", func(t *testing.T) {
		files := memFiles(map[string]string{DefaultConfig: "Include /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication no\n"})
		files.ReadDir = func(string) ([]string, error) { return nil, fs.ErrPermission } // RHEL: 0700 without root

		cfg := Parse(Flags{ConfigFile: DefaultConfig}, files)

		assert.False(t, cfg.Valid())
		require.Len(t, cfg.ReadErrors, 1)
		assert.Equal(t, "/etc/ssh/sshd_config.d", cfg.ReadErrors[0].Path)
	})

	t.Run("a missing Include directory is fine", func(t *testing.T) {
		cfg := parse(t, map[string]string{DefaultConfig: "Include /etc/ssh/nothere/*.conf\n"}, Flags{})
		assert.True(t, cfg.Valid())
	})

	t.Run("PubkeyAuthOptions takes several flags", func(t *testing.T) {
		cfg := parse(t, map[string]string{DefaultConfig: "PubkeyAuthOptions touch-required verify-required\n"}, Flags{})
		assert.Empty(t, cfg.Errors)
		assert.Equal(t, []string{"touch-required", "verify-required"}, cfg.Global["PubkeyAuthOptions"].Values)
	})

	t.Run("Match needs criterion-value pairs, All stands alone", func(t *testing.T) {
		cfg := parse(t, map[string]string{DefaultConfig: "Match User alice Address\nMatch All User bob\n"}, Flags{})
		assert.Equal(t, []Ref{{File: DefaultConfig, Line: 1, Code: CodeBadMatch}, {File: DefaultConfig, Line: 2, Code: CodeBadMatch}}, cfg.Errors)
	})

	t.Run("only CamelCase words are sent as unknown keywords", func(t *testing.T) {
		for kw, want := range map[string]string{
			"DebianBanner": "DebianBanner", "GSSAPIKeyExchange": "GSSAPIKeyExchange",
			"AKIAIOSFODNN7EXAMPLE": "invalid", "HUNTER": "invalid", "hunter2": "invalid", "secret": "invalid",
		} {
			assert.Equal(t, want, keywordCode(kw), kw)
		}
	})
}

func TestGlobErrors(t *testing.T) {
	readDir := func(dir string) ([]string, error) {
		switch dir {
		case "/a":
			return []string{"x", "y"}, nil
		case "/a/x":
			return nil, fs.ErrPermission
		}
		return nil, fs.ErrNotExist
	}

	matches, errs := Glob("/a/*/k*", readDir)

	assert.Empty(t, matches)
	assert.Equal(t, []ReadError{{Path: "/a/x", Err: fs.ErrPermission}}, errs, "/a/y is missing: no error")
}
