package sudoers

import (
	"fmt"
	"io/fs"
	"path"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

func parse(files map[string]string) *Policy {
	return Parse("/etc/sudoers", "web1", memFiles(files))
}

func TestParseDebianDefault(t *testing.T) {
	p := parse(map[string]string{
		"/etc/sudoers": `# /etc/sudoers
Defaults	env_reset
Defaults	mail_badpass
Defaults	secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Defaults	use_pty

root	ALL=(ALL:ALL) ALL
%sudo	ALL=(ALL:ALL) ALL

@includedir /etc/sudoers.d
`,
		"/etc/sudoers.d/README":     "# files in this directory are read\n",
		"/etc/sudoers.d/90-cloud":   "ubuntu ALL=(ALL) NOPASSWD:ALL\n",
		"/etc/sudoers.d/admin.conf": "eve ALL=(ALL) NOPASSWD: ALL\n",
		"/etc/sudoers.d/old~":       "mallory ALL=(ALL) ALL\n",
	})

	assert.Empty(t, p.Errors)
	require.Len(t, p.Rules, 3, "admin.conf and old~ are never read by sudo")
	assert.Equal(t, Rule{Source: "/etc/sudoers:7", Principals: []string{"root"}, HostsAll: true,
		Runas: &Runas{Users: []string{"ALL"}, Groups: []string{"ALL"}}, CommandsAll: true, Setenv: true}, p.Rules[0])
	assert.Equal(t, []string{"%sudo"}, p.Rules[1].Principals)
	assert.Equal(t, Rule{Source: "/etc/sudoers.d/90-cloud:1", Principals: []string{"ubuntu"}, HostsAll: true,
		Runas: &Runas{Users: []string{"ALL"}, Groups: []string{}}, CommandsAll: true, NopasswdAll: true, NopasswdAny: true, Setenv: true}, p.Rules[2])
	assert.Equal(t, []string{"/etc/sudoers.d/admin.conf", "/etc/sudoers.d/old~"}, p.Ignored)
	assert.Equal(t, []string{"/etc/sudoers", "/etc/sudoers.d/90-cloud", "/etc/sudoers.d/README"}, p.Files)
	require.NotNil(t, p.Defaults.UsePTY)
	assert.True(t, *p.Defaults.UsePTY)
	assert.Nil(t, p.Defaults.Authenticate)
}

func TestParseRules(t *testing.T) {
	p := parse(map[string]string{"/etc/sudoers": `User_Alias ADMINS = alice, bob, !carol : OPS = %ops
Runas_Alias DB = postgres, mysql
Host_Alias WEB = web1, web2
Cmnd_Alias SHELLS = /bin/sh, /bin/bash
Cmnd_Alias EVERYTHING = ALL

ADMINS WEB = (ALL, !root) NOPASSWD: /usr/bin/systemctl restart SENTINELCMD, PASSWD: /bin/ls
OPS ALL = (DB) NOPASSWD: SETENV: CWD=/srv sha256:abcd /usr/bin/pg_dump, !SHELLS
#1000 ALL = EVERYTHING
deploy web1 = (root) /usr/bin/a : ALL = NOPASSWD: /usr/bin/b
%#200, +netgroup ALL = /usr/bin/c, \
    /usr/bin/d # trailing comment
`})

	require.Empty(t, p.Errors)
	require.Len(t, p.Rules, 6)

	admins := p.Rules[0]
	assert.Equal(t, []string{"alice", "bob", "!carol"}, admins.Principals, "aliases expanded, negation kept")
	assert.False(t, admins.HostsAll)
	assert.True(t, admins.Runas.HasNegation, "(ALL, !root) is reported, not trusted")
	assert.True(t, admins.NopasswdAny)
	assert.False(t, admins.NopasswdAll, "PASSWD: after NOPASSWD: takes the password back")
	assert.False(t, admins.CommandsAll)

	ops := p.Rules[1]
	assert.Equal(t, []string{"%ops"}, ops.Principals)
	assert.Equal(t, []string{"postgres", "mysql"}, ops.Runas.Users)
	assert.True(t, ops.NopasswdAll, "the negated shells grant nothing and do not count")
	assert.True(t, ops.Setenv)

	assert.Equal(t, []string{"#1000"}, p.Rules[2].Principals, "#1000 is a uid, not a comment")
	assert.True(t, p.Rules[2].CommandsAll, "a Cmnd_Alias of ALL")
	assert.Nil(t, p.Rules[2].Runas, "no runas spec: runas_default")

	assert.Equal(t, "/etc/sudoers:10", p.Rules[3].Source)
	assert.False(t, p.Rules[3].HostsAll)
	assert.True(t, p.Rules[4].HostsAll, "the second host list of the same line")
	assert.True(t, p.Rules[4].NopasswdAll)
	assert.Equal(t, p.Rules[3].Principals, p.Rules[4].Principals)

	assert.Equal(t, []string{"%#200", "+netgroup"}, p.Rules[5].Principals)
	assert.Equal(t, "/etc/sudoers:11", p.Rules[5].Source, "a continued line keeps its first line number")

	assert.NotContains(t, fmt.Sprint(p), "SENTINELCMD", "no command text kept")
}

func TestParseDefaults(t *testing.T) {
	p := parse(map[string]string{"/etc/sudoers": `Defaults !authenticate
Defaults rootpw
Defaults env_keep += "LD_PRELOAD HOME"
Defaults:alice !authenticate
Defaults>root rootpw
Defaults@web1 env_keep += LD_LIBRARY_PATH
Defaults!/bin/ls !lecture
Defaults authenticate
`})

	require.Empty(t, p.Errors)
	require.NotNil(t, p.Defaults.Authenticate)
	assert.True(t, *p.Defaults.Authenticate, "the last global setting wins")
	assert.True(t, *p.Defaults.RootPW)
	assert.True(t, p.Defaults.EnvKeepLD)
	assert.Equal(t, []ScopedDefault{
		{Source: "/etc/sudoers:4", Binding: "user", List: []string{"alice"}, NoAuthenticate: true},
		{Source: "/etc/sudoers:5", Binding: "runas", List: []string{"root"}, RootPW: true},
		{Source: "/etc/sudoers:6", Binding: "host", List: []string{"web1"}, EnvKeepLD: true},
	}, p.Scoped, "only bound Defaults that set a tracked flag")
}

func TestParseIncludes(t *testing.T) {
	t.Run("relative to the including file, %h, quoted paths", func(t *testing.T) {
		p := parse(map[string]string{
			"/etc/sudoers":               "@include sudoers.local\n#include /etc/sudoers.%h\n@include \"/etc/sudo rs/extra\"\n",
			"/etc/sudoers.local":         "a ALL = ALL\n",
			"/etc/sudoers.web1":          "b ALL = ALL\n",
			"/etc/sudo rs/extra":         "c ALL = ALL\n",
			"/etc/sudoers.d/should-skip": "x ALL = ALL\n",
		})
		require.Empty(t, p.Errors)
		require.Len(t, p.Rules, 3)
		assert.Equal(t, []string{"c"}, p.Rules[2].Principals)
	})

	t.Run("a loop is an error, not a hang", func(t *testing.T) {
		p := parse(map[string]string{"/etc/sudoers": "@include /etc/sudoers.d/a\n", "/etc/sudoers.d/a": "@include /etc/sudoers\n"})
		require.Len(t, p.Errors, 1)
		assert.Equal(t, CodeIncludeLoop, p.Errors[0].Code)
	})

	t.Run("130 levels: past 128 is an error", func(t *testing.T) {
		files := map[string]string{"/etc/sudoers": "@include /etc/s/1\n"}
		for i := 1; i <= 130; i++ {
			files[fmt.Sprintf("/etc/s/%d", i)] = fmt.Sprintf("@include /etc/s/%d\n", i+1)
		}
		p := parse(files)
		require.NotEmpty(t, p.Errors)
		assert.Equal(t, CodeIncludeDepth, p.Errors[0].Code)
		assert.Len(t, p.Files, maxDepth+1)
	})

	t.Run("a missing include is a read error, a missing includedir is not", func(t *testing.T) {
		p := parse(map[string]string{"/etc/sudoers": "@include /etc/nope\n@includedir /etc/nodir\n"})
		require.Len(t, p.ReadErrors, 1)
		assert.Equal(t, "/etc/nope", p.ReadErrors[0].Path)
	})
}

func TestParseErrors(t *testing.T) {
	p := parse(map[string]string{"/etc/sudoers": "garbage SENTINELLINE\nUser_Alias lower = x\nDefaults%x y\n"})

	assert.Equal(t, []Ref{
		{File: "/etc/sudoers", Line: 1, Code: CodeSyntax},
		{File: "/etc/sudoers", Line: 2, Code: CodeSyntax},
		{File: "/etc/sudoers", Line: 3, Code: CodeSyntax},
	}, p.Errors)
	assert.NotContains(t, fmt.Sprint(p), "SENTINELLINE")
}

func TestParseDoas(t *testing.T) {
	rules, errs := ParseDoas("/etc/doas.conf", []byte(`# Alpine default
permit persist :wheel
permit nopass setenv { PATH LANG } deploy as root cmd /usr/bin/SENTINELCMD
permit nopass alice as postgres
deny bob
bogus line
`))

	assert.Equal(t, []DoasRule{
		{Source: "/etc/doas.conf:2", Permit: true, Principal: ":wheel", Persist: true, AsRoot: true},
		{Source: "/etc/doas.conf:3", Permit: true, Principal: "deploy", Nopass: true, AsRoot: true, Cmd: true},
		{Source: "/etc/doas.conf:4", Permit: true, Principal: "alice", Nopass: true},
		{Source: "/etc/doas.conf:5", Principal: "bob", AsRoot: true},
	}, rules)
	assert.Equal(t, []Ref{{File: "/etc/doas.conf", Line: 6, Code: CodeSyntax}}, errs)
	assert.NotContains(t, fmt.Sprint(rules), "SENTINELCMD")
}

func FuzzParse(f *testing.F) {
	for _, seed := range []string{"root ALL=(ALL:ALL) ALL", `Defaults env_keep+="LD_X"`, "User_Alias A = b : C = d", "x y = (a:b) NOPASSWD: /c : z = d", "\\", `"`, "a b = (c"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		p := parse(map[string]string{"/etc/sudoers": s})
		for _, r := range p.Rules {
			if r.NopasswdAll && !r.NopasswdAny {
				t.Fatalf("nopasswdAll without nopasswdAny: %+v", r)
			}
		}
		if strings.Contains(s, "@include") && len(p.Files) > maxFiles {
			t.Fatal("file budget exceeded")
		}
	})
}

func TestAliasFanOut(t *testing.T) {
	// Each level uses the next ten times: 10^16 members without reuse.
	var b strings.Builder
	for i := range 16 {
		fmt.Fprintf(&b, "User_Alias A%d = %s\n", i, strings.TrimSuffix(strings.Repeat(fmt.Sprintf("A%d, ", i+1), 10), ", "))
	}
	b.WriteString("User_Alias A16 = alice\nA0 ALL = ALL\n")

	p := parse(map[string]string{"/etc/sudoers": b.String()})

	require.Len(t, p.Rules, 1)
	assert.Len(t, p.Rules[0].Principals, maxExpanded, "capped, and fast")
}
