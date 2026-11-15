package security

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// accountsFixture is a Debian host with every kind of password field.
func accountsFixture() map[string]string {
	return map[string]string{
		"etc/passwd": strings.Join([]string{
			"root:x:0:0:root:/root:/bin/bash",
			"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
			"sync:x:4:65534:sync:/bin:/bin/sync",
			"alice:x:1000:1000:Alice Example,,,:/home/alice:/bin/zsh",
			"bob:x:1001:1001::/home/bob:/bin/bash",
			"locked:x:1002:1002::/home/locked:/bin/bash",
			"nopw:x:1003:1003::/home/nopw:/bin/bash",
			"legacy:$1$abcd$hashinpasswd:1004:1004::/home/legacy:/bin/sh",
			"gone:x:1005:1005::/home/gone:/bin/false",
			"toor:x:0:0::/root:/bin/sh",
			"svc:x:61200:61200::/:/usr/sbin/nologin",
			"",
			"# a comment",
		}, "\n"),
		"etc/shadow": strings.Join([]string{
			"root:$y$j9T$saltsalt$hashhashhash:19700:0:99999:7:::",
			"daemon:*:19700:0:99999:7:::",
			"sync:!*:19700:0:99999:7:::",
			"alice:$6$salt$alicehash:19800:0:99999:7:::",
			"bob:!!:19800::::::",
			"locked:!$6$salt$lockedhash:19800:0:99999:7::20000:",
			"nopw::19800:0:99999:7:::",
			"legacy:x:19800:0:99999:7:::",
			"toor:abcdefghijklm:19800:0:30:7:10::",
			"svc:!plaintext-oops:19800::::::",
			"orphan:*:19800::::::",
		}, "\n"),
		"etc/group": strings.Join([]string{
			"root:x:0:",
			"sudo:x:27:alice",
			"docker:x:999:bob,alice",
			"adm:x:4:syslog",
			"alice:x:1000:",
			"bob:x:1001:",
		}, "\n"),
		"etc/gshadow":       "root:*::\n",
		"etc/nsswitch.conf": "passwd: files systemd\ngroup: files systemd\nshadow: files\nsudoers: files sss\nnetgroup: nis\n",
	}
}

// testToday is 2026-11-14 in days since 1970-01-01.
var testToday = time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)

func accountsOf(t *testing.T, files map[string]string) (Section, accountsData, *accountsResult) {
	t.Helper()
	sc := fixture(t, files)
	sc.now = testToday
	sec, res := collectAccounts(t.Context(), sc)
	d, _ := sec.Data.(accountsData)
	r, _ := res.(*accountsResult)
	return sec, d, r
}

func userByName(t *testing.T, users []account, name string) account {
	t.Helper()
	for _, u := range users {
		if u.Name == name {
			return u
		}
	}
	require.Failf(t, "no user", "%s", name)
	return account{}
}

func TestAccounts(t *testing.T) {
	sec, d, res := accountsOf(t, accountsFixture())
	require.Equal(t, StatusOK, sec.Status, "gaps: %v", sec.Gaps)

	str := func(s string) *string { return &s }
	cases := []struct {
		name                string
		pw                  *string
		marker, algo, shell string
		token               bool
	}{
		{name: "root", pw: str(pwHash), algo: "yescrypt", shell: shellLogin, token: true},
		{name: "daemon", pw: str(pwNone), marker: "*", shell: shellNologin},
		{name: "sync", pw: str(pwNone), marker: "!*", shell: shellOther},
		{name: "alice", pw: str(pwHash), algo: "sha512", shell: shellLogin, token: true},
		{name: "bob", pw: str(pwNone), marker: "!!", shell: shellLogin},
		{name: "locked", pw: str(pwLockedHash), algo: "sha512", shell: shellLogin, token: true},
		{name: "nopw", pw: str(pwEmpty), shell: shellLogin},
		{name: "legacy", pw: str(pwHashInPasswd), algo: "md5", shell: shellLogin, token: true},
		{name: "gone", pw: nil, shell: shellFalse},
		{name: "toor", pw: str(pwHash), algo: "des", shell: shellLogin, token: true},
		{name: "svc", pw: str(pwNone), marker: "other", shell: shellNologin},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u := userByName(t, d.Users, tc.name)
			assert.Equal(t, tc.pw, u.PW)
			assert.Equal(t, tc.marker, u.Marker)
			assert.Equal(t, tc.algo, u.Algo)
			assert.Equal(t, tc.shell, u.ShellClass)
			if tc.token {
				assert.Regexp(t, `^[0-9a-f]{16}$`, u.PWToken)
			} else {
				assert.Empty(t, u.PWToken)
			}
		})
	}

	t.Run("expiry", func(t *testing.T) {
		assert.False(t, *userByName(t, d.Users, "alice").Expired)
		assert.True(t, *userByName(t, d.Users, "locked").Expired, "expiry date 20000 passed")
		assert.True(t, *userByName(t, d.Users, "toor").Expired, "max 30 + inactive 10 days since 19800")
		assert.Nil(t, userByName(t, d.Users, "legacy").Expired, "the hash is in passwd, shadow is not used")
		assert.Nil(t, userByName(t, d.Users, "gone").Expired, "no shadow entry")
		assert.EqualValues(t, 19800, *userByName(t, d.Users, "alice").LastChangeDays)
	})

	t.Run("dynamic user", func(t *testing.T) {
		assert.True(t, userByName(t, d.Users, "svc").DynamicUser)
		assert.False(t, userByName(t, d.Users, "alice").DynamicUser)
	})

	t.Run("anomalies", func(t *testing.T) {
		assert.Equal(t, []string{"root", "toor"}, d.Anomalies.UID0Users)
		assert.Equal(t, []int64{0}, d.Anomalies.DuplicateUIDs)
		assert.Empty(t, d.Anomalies.DuplicateNames)
		assert.Equal(t, []string{"gone", "orphan"}, d.Anomalies.PasswdShadowMismatch)
	})

	t.Run("privileged groups: listed members and primary group", func(t *testing.T) {
		assert.Equal(t, map[string][]string{
			"root":   {"root", "toor"},
			"sudo":   {"alice"},
			"docker": {"alice", "bob"},
			"adm":    {"syslog"},
		}, d.PrivilegedGroups)
	})

	t.Run("nsswitch", func(t *testing.T) {
		require.NotNil(t, d.NSS)
		assert.Equal(t, []string{"files", "systemd"}, d.NSS.Passwd)
		assert.Equal(t, []string{"files", "sss"}, d.NSS.Sudoers)
		assert.False(t, d.NSS.ExternalIdentities, "systemd is not a directory")
	})

	t.Run("files", func(t *testing.T) {
		paths := make([]string, 0, len(d.Files))
		for _, f := range d.Files {
			paths = append(paths, f.Path)
		}
		assert.Equal(t, []string{"/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow"}, paths)
		assert.Equal(t, "0644", d.Files[0].Mode)
	})

	t.Run("the result keeps home directories for authorizedKeys", func(t *testing.T) {
		require.NotNil(t, res)
		assert.Len(t, res.users, 11)
		assert.Equal(t, "/home/alice", userByName(t, res.users, "alice").home)
	})

	t.Run("no GECOS and no hash on the wire", func(t *testing.T) {
		js := toJSON(t, sec)
		for _, secret := range []string{"Alice Example", "alicehash", "lockedhash", "hashinpasswd", "abcdefghijklm", "plaintext-oops", "saltsalt"} {
			assert.NotContains(t, js, secret)
		}
		assert.NotContains(t, js, "/home/alice", "home is not sent")
	})
}

func TestAccountsToken(t *testing.T) {
	files := accountsFixture()
	_, before, _ := accountsOf(t, files)

	t.Run("locking keeps the token, a new password changes it", func(t *testing.T) {
		locked := strings.Replace(files["etc/shadow"], "alice:$6$salt$alicehash", "alice:!$6$salt$alicehash", 1)
		_, d, _ := accountsOf(t, merge(files, map[string]string{"etc/shadow": locked}))
		assert.Equal(t, pwLockedHash, *userByName(t, d.Users, "alice").PW)
		assert.Equal(t, userByName(t, before.Users, "alice").PWToken, userByName(t, d.Users, "alice").PWToken)

		changed := strings.Replace(files["etc/shadow"], "alicehash", "newhash", 1)
		_, d, _ = accountsOf(t, merge(files, map[string]string{"etc/shadow": changed}))
		assert.NotEqual(t, userByName(t, before.Users, "alice").PWToken, userByName(t, d.Users, "alice").PWToken)
	})

	t.Run("the same hash of another user gives another token", func(t *testing.T) {
		assert.NotEqual(t, userByName(t, before.Users, "alice").PWToken, userByName(t, before.Users, "locked").PWToken)
	})
}

func TestAccountsGaps(t *testing.T) {
	t.Run("no passwd: unknown", func(t *testing.T) {
		sec, _, res := accountsOf(t, nil)
		assert.Equal(t, StatusUnknown, sec.Status)
		assert.Equal(t, ReasonNotFound, sec.Reason)
		assert.Nil(t, res)
	})

	t.Run("unreadable shadow: partial, passwords not read", func(t *testing.T) {
		sc := fixture(t, accountsFixture())
		unreadable(t, sc, "etc/shadow")
		sec, _ := collectAccounts(t.Context(), sc)

		assert.Equal(t, StatusPartial, sec.Status)
		assert.Equal(t, []Gap{{Path: "/etc/shadow", Reason: ReasonPermissionDenied}}, sec.Gaps)
		d := sec.Data.(accountsData)
		assert.Nil(t, userByName(t, d.Users, "alice").PW, "unread, not empty")
		assert.Equal(t, pwHashInPasswd, *userByName(t, d.Users, "legacy").PW, "passwd still tells")
		assert.Nil(t, d.Anomalies.PasswdShadowMismatch)
	})

	t.Run("no group: partial, no privileged groups", func(t *testing.T) {
		files := accountsFixture()
		delete(files, "etc/group")
		sec, d, _ := accountsOf(t, files)

		assert.Equal(t, StatusPartial, sec.Status)
		assert.Nil(t, d.PrivilegedGroups)
	})

	t.Run("no nsswitch (musl): not a gap", func(t *testing.T) {
		files := accountsFixture()
		delete(files, "etc/nsswitch.conf")
		sec, d, _ := accountsOf(t, files)

		assert.Equal(t, StatusOK, sec.Status)
		assert.Nil(t, d.NSS)
	})

	t.Run("malformed lines and NIS compat", func(t *testing.T) {
		files := merge(accountsFixture(), map[string]string{
			"etc/passwd": "root:x:0:0:root:/root:/bin/bash\nbroken:x:1\nbad:x:abc:1::/:/bin/sh\n+@netgroup::::::\n",
			"etc/group":  "root:x:0:\n-nisgroup\nodd:x:z:\n",
		})
		sec, d, _ := accountsOf(t, files)

		assert.Equal(t, StatusOK, sec.Status)
		assert.True(t, d.NISCompat)
		assert.Equal(t, []lineRef{
			{File: "/etc/passwd", Line: 2, Code: "fields"},
			{File: "/etc/passwd", Line: 3, Code: "id"},
			{File: "/etc/group", Line: 3, Code: "id"},
		}, d.Malformed)
		assert.Len(t, d.Users, 1)
	})
}

func TestAccountsHomed(t *testing.T) {
	t.Run("no homed: false", func(t *testing.T) {
		_, d, _ := accountsOf(t, accountsFixture())
		require.NotNil(t, d.HomedUsers)
		assert.False(t, *d.HomedUsers)
	})

	t.Run("no home registered: false", func(t *testing.T) {
		_, d, _ := accountsOf(t, merge(accountsFixture(), map[string]string{
			"var/lib/systemd/home/local.public":  "-----BEGIN PUBLIC KEY-----\n", // homed's signing keys
			"var/lib/systemd/home/local.private": "-----BEGIN PRIVATE KEY-----\n",
		}))
		require.NotNil(t, d.HomedUsers)
		assert.False(t, *d.HomedUsers)
	})

	t.Run("a home registered: true, no name or record sent", func(t *testing.T) {
		sec, d, _ := accountsOf(t, merge(accountsFixture(), map[string]string{
			"var/lib/systemd/home/SENTINELUSER.identity": `{"userName":"SENTINELUSER","privileged":{"hashedPassword":["SENTINELHASH"]}}`,
		}))
		require.NotNil(t, d.HomedUsers)
		assert.True(t, *d.HomedUsers)
		assert.NotContains(t, toJSON(t, sec), "SENTINEL")
	})

	t.Run("unreadable: null and a gap", func(t *testing.T) {
		sc := fixture(t, merge(accountsFixture(), map[string]string{"var/lib/systemd/home/": ""}))
		unreadable(t, sc, "var/lib/systemd/home")
		sec, _ := collectAccounts(t.Context(), sc)

		assert.Equal(t, StatusPartial, sec.Status)
		assert.Equal(t, []Gap{{Path: "/var/lib/systemd/home", Reason: ReasonPermissionDenied}}, sec.Gaps)
		assert.Nil(t, sec.Data.(accountsData).HomedUsers)
	})
}

func TestAccountsTruncated(t *testing.T) {
	var passwd strings.Builder
	for i := range maxUsers + 5 {
		fmt.Fprintf(&passwd, "u%d:x:%d:%d::/home/u%d:/bin/sh\n", i, 10000+i, 10000+i, i)
	}
	passwd.WriteString("dup:x:0:0::/:/bin/sh\n") // past the cut, still an anomaly

	_, d, res := accountsOf(t, map[string]string{"etc/passwd": passwd.String(), "etc/shadow": "", "etc/group": ""})

	assert.Len(t, d.Users, maxUsers)
	assert.True(t, d.Truncated)
	assert.Equal(t, []string{"dup"}, d.Anomalies.UID0Users)
	assert.Len(t, res.users, maxUsers+6, "authorizedKeys sees every user")
}

func TestClassifyPW(t *testing.T) {
	cases := []struct {
		field    string
		inPasswd bool
		want     pwClass
	}{
		{"", false, pwClass{pw: pwEmpty}},
		{"!", false, pwClass{pw: pwNone, marker: "!"}},
		{"*LK*", false, pwClass{pw: pwNone, marker: "*LK*"}},
		{"x", false, pwClass{pw: pwNone, marker: "x"}},
		{"$gy$j9T$s$h", false, pwClass{pw: pwHash, algo: "gost-yescrypt", hash: "$gy$j9T$s$h"}},
		{"$7$CU..../....$h", false, pwClass{pw: pwHash, algo: "scrypt", hash: "$7$CU..../....$h"}},
		{"$5$s$h", false, pwClass{pw: pwHash, algo: "sha256", hash: "$5$s$h"}},
		{"$2b$12$h", false, pwClass{pw: pwHash, algo: "bcrypt", hash: "$2b$12$h"}},
		{"$sha1$19703$s$h", false, pwClass{pw: pwHash, algo: "other", hash: "$sha1$19703$s$h"}},
		{"!!$6$s$h", false, pwClass{pw: pwLockedHash, algo: "sha512", hash: "$6$s$h"}},
		{"$6$s$h", true, pwClass{pw: pwHashInPasswd, algo: "sha512", hash: "$6$s$h"}},
		{"*", true, pwClass{pw: pwNone, marker: "*"}},
		{"hunter2", false, pwClass{pw: pwNone, marker: "other"}},
		{"$notahash", false, pwClass{pw: pwNone, marker: "other"}},
	}
	for _, tc := range cases {
		t.Run(tc.field, func(t *testing.T) {
			assert.Equal(t, tc.want, classifyPW(tc.field, tc.inPasswd))
		})
	}
}

func TestParseNSSwitch(t *testing.T) {
	c := parseNSSwitch([]byte("# comment\npasswd:  files [NOTFOUND=return] sss\ngroup: files [ SUCCESS=merge ] winbind\nshadow: files\nshadow: ldap\nsudoers: files Bad.Name\nhosts: files dns\n"))

	assert.Equal(t, []string{"files", "sss"}, c.Passwd)
	assert.Equal(t, []string{"files", "winbind"}, c.Group)
	assert.Equal(t, []string{"files"}, c.Shadow, "the first line wins")
	assert.Equal(t, []string{"files", valueInvalid}, c.Sudoers)
	assert.Nil(t, c.Netgroup, "not listed")
	assert.True(t, c.ExternalIdentities)
}

func TestAccountsAgingAndGroups(t *testing.T) {
	_, d, _ := accountsOf(t, merge(accountsFixture(), map[string]string{
		"etc/group": strings.Join([]string{
			"root:x:0:", "sudo:x:27:alice", "docker:x:999:bob,alice", "adm:x:4:syslog",
			"alice:x:1000:", "bob:x:1001:",
			"wheel:x:0:",        // GID 0, not root
			"backup:x:1001:",    // bob's GID again
			"sudo:x:28:mallory", // a second sudo: the first counts
		}, "\n"),
	}))
	a := d.Anomalies
	assert.Equal(t, []string{"sudo"}, a.DuplicateGroupNames)
	assert.Equal(t, []int64{0, 1001}, a.DuplicateGIDs)
	assert.Equal(t, []string{"wheel"}, a.GID0Groups)
	assert.Equal(t, []string{"daemon", "gone", "legacy", "locked", "nopw", "svc", "sync"}, a.PrimaryGroupMissing,
		"passwd GIDs without a group line; sync's 65534 too")

	byName := map[string]account{}
	for _, u := range d.Users {
		byName[u.Name] = u
	}
	toor := byName["toor"]
	assert.Equal(t, int64(0), *toor.MinDays)
	assert.Equal(t, int64(30), *toor.MaxDays)
	assert.Equal(t, int64(7), *toor.WarnDays)
	assert.Equal(t, int64(10), *toor.InactiveDays)
	assert.Nil(t, toor.ExpireDays, "empty field")
	assert.Equal(t, int64(20000), *byName["locked"].ExpireDays)
	assert.Nil(t, byName["bob"].MaxDays)
}

func TestAccountsGroupUnread(t *testing.T) {
	files := accountsFixture()
	delete(files, "etc/group")
	_, d, _ := accountsOf(t, files)
	assert.Nil(t, d.Anomalies.DuplicateGIDs, "null: not read")
	assert.Nil(t, d.Anomalies.PrimaryGroupMissing)
}

func TestAccountsGroupsByUser(t *testing.T) {
	_, _, res := accountsOf(t, accountsFixture())
	require.NotNil(t, res)
	assert.Equal(t, []string{"alice", "docker", "sudo"}, res.groups["alice"], "primary by GID, supplementary by member list")
	assert.Equal(t, []string{"root"}, res.groups["root"])
	assert.Empty(t, res.groups["daemon"], "GID 1 has no group line")
	assert.Equal(t, []string{"adm"}, res.groups["syslog"], "a member without a passwd entry still gets its groups")
}

// TestAccountsGroupOf: the group of a gid as the kernel checks it — the
// first name getgrgid returns, members of every line with the gid and the
// users whose primary group it is.
func TestAccountsGroupOf(t *testing.T) {
	_, d, res := accountsOf(t, merge(accountsFixture(), map[string]string{
		"etc/passwd": accountsFixture()["etc/passwd"] + "\nci:x:1010:987::/home/ci:/bin/sh",
		"etc/group": strings.Join([]string{
			"root:x:0:", "sudo:x:27:alice", "docker:x:999:bob,alice",
			"dockerroot:x:987:bob", // dockerd --group dockerroot
			"ops:x:987:carol,bob",  // the same gid under a later name
			"alice:x:1000:", "bob:x:1001:",
			"builders:x:999:eve", // docker's gid under another name
			"docker:x:999:dave",  // a second docker line: initgroups reads it too
			"docker:x:996:frank", // and one with a gid of its own
		}, "\n"),
	}))
	require.NotNil(t, res)

	t.Run("socket group other than docker: its gid shared, a primary member", func(t *testing.T) {
		assert.Equal(t, &gidGroup{Name: new("dockerroot"), Members: []string{"bob", "carol", "ci"}}, res.groupOf(987))
	})
	t.Run("docker, and privilegedGroups agree: both by gid", func(t *testing.T) {
		assert.Equal(t, &gidGroup{Name: new("docker"), Members: []string{"alice", "bob", "dave", "eve"}}, res.groupOf(999))
		assert.Equal(t, []string{"alice", "bob", "dave", "eve"}, d.PrivilegedGroups["docker"])
	})
	t.Run("a gid first seen on a repeated name's line", func(t *testing.T) {
		assert.Equal(t, &gidGroup{Name: new("docker"), Members: []string{"frank"}}, res.groupOf(996))
	})
	t.Run("root: the users with gid 0", func(t *testing.T) {
		assert.Equal(t, &gidGroup{Name: new("root"), Members: []string{"root", "toor"}}, res.groupOf(0))
	})
	t.Run("no line with the gid: no name, primary members still", func(t *testing.T) {
		assert.Equal(t, &gidGroup{Members: []string{"locked"}}, res.groupOf(1002))
		assert.Equal(t, &gidGroup{Members: []string{}}, res.groupOf(4242))
	})
	t.Run("more than maxUsers members: cut, flagged", func(t *testing.T) {
		users := make([]string, maxUsers+1)
		for i := range users {
			users[i] = fmt.Sprintf("u%05d", i)
		}
		big := &accountsResult{groupsByName: map[string]groupEntry{"users": {gid: 100, members: users}}}
		g := big.groupOf(100)
		assert.Len(t, g.Members, maxUsers)
		assert.True(t, g.Truncated)
	})
	t.Run("group unread: unknown", func(t *testing.T) {
		files := accountsFixture()
		delete(files, "etc/group")
		_, _, res := accountsOf(t, files)
		require.NotNil(t, res)
		assert.Nil(t, res.groupOf(999))
	})
}
