package security

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func wireString(b []byte) []byte {
	out := binary.BigEndian.AppendUint32(nil, uint32(len(b)))
	return append(out, b...)
}

// ed25519Blob is an Ed25519 public key blob with a distinct body.
func ed25519Blob(seed byte) []byte {
	body := make([]byte, 32)
	body[0] = seed
	return append(wireString([]byte("ssh-ed25519")), wireString(body)...)
}

// rsaBlob is an RSA public key blob with a modulus of bits bits.
func rsaBlob(bits int) []byte {
	n := new(big.Int).Lsh(big.NewInt(1), uint(bits-1))
	blob := wireString([]byte("ssh-rsa"))
	blob = append(blob, wireString(big.NewInt(65537).Bytes())...)
	return append(blob, wireString(append([]byte{0}, n.Bytes()...))...) // mpint with a leading zero
}

func b64(blob []byte) string { return base64.StdEncoding.EncodeToString(blob) }

func fingerprint(blob []byte) string {
	sum := sha256.Sum256(blob)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

const authMountinfo = "22 1 8:1 / / rw - ext4 /dev/sda1 rw\n" +
	"40 22 0:50 / /net rw - autofs auto.net rw\n" +
	"41 22 0:51 / /home/remote rw - nfs4 192.0.2.10:/home rw\n"

// authKeysFixture: alice's keys with every kind of line, bob's file sshd
// ignores, carol on NFS.
func authKeysFixture() map[string]string {
	alice := strings.Join([]string{
		"# a comment line",
		"ssh-ed25519 " + b64(ed25519Blob(1)) + " sentinel@example.com",
		`from="10.0.0.0/8",command="echo \"ssh-rsa AAAA\"",no-pty ssh-rsa ` + b64(rsaBlob(2048)) + " laptop-comment",
		"restrict,unknown-opt ssh-ed25519 " + b64(ed25519Blob(2)),
		"ssh-rsa " + b64(ed25519Blob(3)) + " mislabeled",
		"ssh-ed25519 not-base64!",
		"",
	}, "\n")
	return map[string]string{
		"proc/self/mountinfo":                    authMountinfo,
		"home/alice/.ssh/authorized_keys":        alice,
		"home/alice/.ssh/authorized_keys2":       "-> authorized_keys",
		"home/bob/.ssh/authorized_keys":          "ssh-ed25519 " + b64(ed25519Blob(4)) + "\n",
		"home/dave/.ssh/authorized_keys":         "-> /net/server/keys",
		"etc/ssh/keys/deploy":                    "ssh-ed25519 " + b64(ed25519Blob(5)) + "\n",
		"home/remote/carol/.ssh/authorized_keys": "",
		"net/server/keys":                        "ssh-ed25519 " + b64(ed25519Blob(6)) + "\n",
	}
}

// authUsers are owned by the test user, so StrictModes can pass.
func authUsers() *accountsResult {
	uid := int64(os.Getuid())
	return &accountsResult{users: []account{
		{Name: "alice", UID: uid, home: "/home/alice"},
		{Name: "bob", UID: uid, home: "/home/bob"},
		{Name: "carol", UID: uid, home: "/home/remote/carol"},
		{Name: "dave", UID: uid, home: "/home/dave"},
		{Name: "erin", UID: uid, home: "/home/erin"},
		{Name: "deploy", UID: uid, home: "/home/deploy"},
		{Name: "nobody", UID: 65534, home: "/nonexistent"},
	}}
}

func authKeysOf(t *testing.T, sc *scanCtx, sshd *sshdResult) (Section, authKeysData) {
	t.Helper()
	sc.setResult(SectionAccounts, authUsers())
	if sshd != nil {
		sc.setResult(SectionSSHD, sshd)
	}
	sec := collectAuthorizedKeys(t.Context(), sc)
	d, _ := sec.Data.(authKeysData)
	return sec, d
}

func filesOf(t *testing.T, d authKeysData, user string) map[string]authKeysFile {
	t.Helper()
	out := map[string]authKeysFile{}
	for _, u := range d.Users {
		if u.Name == user {
			for _, f := range u.Files {
				out[f.Path] = f
			}
		}
	}
	return out
}

func testSSHDResult() *sshdResult {
	return &sshdResult{
		authorizedKeysFiles: defaultAuthorizedKeysFiles,
		userKeysFiles:       map[string][]string{"deploy": {"/etc/ssh/keys/%u"}},
		strictModes:         true,
	}
}

func TestAuthorizedKeys(t *testing.T) {
	sc := fixture(t, authKeysFixture())
	require.NoError(t, os.Chmod(filepath.Join(sc.root, "home/bob"), 0o775)) // group-writable home
	sec, d := authKeysOf(t, sc, testSSHDResult())
	require.Equal(t, StatusOK, sec.Status)
	assert.True(t, d.ConfigKnown)

	alice := filesOf(t, d, "alice")
	t.Run("every kind of line", func(t *testing.T) {
		f := alice["/home/alice/.ssh/authorized_keys"]
		require.Equal(t, keysOK, f.Status)
		require.Len(t, f.Keys, 4, "the comment line and the broken base64 are skipped")
		assert.Equal(t, authKey{FP: fingerprint(ed25519Blob(1)), Type: "ssh-ed25519", Bits: 256}, f.Keys[0])
		assert.Equal(t, authKey{FP: fingerprint(rsaBlob(2048)), Type: "ssh-rsa", Bits: 2048,
			Options: authKeyOptions{From: true, Command: true, NoPty: true}}, f.Keys[1],
			`a quoted \" and a key type inside command= do not confuse the parser`)
		assert.True(t, f.Keys[2].Rejected, "an unknown option makes sshd drop the line")
		assert.True(t, f.Keys[2].Options.Restrict)
		assert.True(t, f.Keys[3].TypeMismatch)
		assert.Equal(t, 256, f.Keys[3].Bits, "the size comes from the blob")
	})

	t.Run("a symlink sshd follows", func(t *testing.T) {
		f := alice["/home/alice/.ssh/authorized_keys2"]
		assert.Equal(t, keysOK, f.Status)
		assert.Len(t, f.Keys, 4)
	})

	t.Run("StrictModes: a group-writable home makes sshd ignore the file", func(t *testing.T) {
		f := filesOf(t, d, "bob")["/home/bob/.ssh/authorized_keys"]
		assert.Equal(t, keysIgnoredBySSHD, f.Status)
		assert.Len(t, f.Keys, 1, "the keys are still listed")
	})

	t.Run("NFS home: not touched", func(t *testing.T) {
		assert.Equal(t, keysSkippedRemoteFS, filesOf(t, d, "carol")["/home/remote/carol/.ssh/authorized_keys"].Status)
	})

	t.Run("a symlink into autofs is not followed", func(t *testing.T) {
		assert.Equal(t, keysSkippedRemoteFS, filesOf(t, d, "dave")["/home/dave/.ssh/authorized_keys"].Status)
	})

	t.Run("AuthorizedKeysFile of Match User with %u", func(t *testing.T) {
		f := filesOf(t, d, "deploy")["/etc/ssh/keys/deploy"]
		assert.Equal(t, keysOK, f.Status)
		require.Len(t, f.Keys, 1)
		assert.Equal(t, fingerprint(ed25519Blob(5)), f.Keys[0].FP)
	})

	t.Run("users without files are not listed", func(t *testing.T) {
		assert.Empty(t, filesOf(t, d, "nobody"))
	})

	t.Run("no comment on the wire", func(t *testing.T) {
		js := toJSON(t, sec)
		for _, s := range []string{"sentinel@example.com", "laptop-comment", "mislabeled", "10.0.0.0/8", "echo"} {
			assert.NotContains(t, js, s)
		}
	})
}

func TestAuthorizedKeysSpecialFiles(t *testing.T) {
	// A FIFO in place of the file, and a symlink to a non-regular file
	// (/dev/zero in life, a FIFO here): refused, never opened for reading.
	sc := fixture(t, map[string]string{
		"proc/self/mountinfo":            authMountinfo,
		"home/alice/.ssh/":               "",
		"home/erin/.ssh/authorized_keys": "-> /dev/zero",
		"dev/":                           "",
	})
	require.NoError(t, syscall.Mkfifo(filepath.Join(sc.root, "home/alice/.ssh/authorized_keys"), 0o600))
	require.NoError(t, syscall.Mkfifo(filepath.Join(sc.root, "dev/zero"), 0o600))

	_, d := authKeysOf(t, sc, testSSHDResult())

	assert.Equal(t, keysIgnoredBySSHD, filesOf(t, d, "alice")["/home/alice/.ssh/authorized_keys"].Status)
	assert.Equal(t, keysIgnoredBySSHD, filesOf(t, d, "erin")["/home/erin/.ssh/authorized_keys"].Status)
}

func TestAuthorizedKeysStatus(t *testing.T) {
	t.Run("no accounts: unknown", func(t *testing.T) {
		sec := collectAuthorizedKeys(t.Context(), fixture(t, authKeysFixture()))
		assert.Equal(t, StatusUnknown, sec.Status)
	})

	t.Run("sshd not installed: na", func(t *testing.T) {
		sec, _ := authKeysOf(t, fixture(t, authKeysFixture()), &sshdResult{notInstalled: true})
		assert.Equal(t, StatusNA, sec.Status)
	})

	t.Run("sshd config unknown: default paths, flagged", func(t *testing.T) {
		sec, d := authKeysOf(t, fixture(t, authKeysFixture()), nil)
		assert.Equal(t, StatusOK, sec.Status)
		assert.False(t, d.ConfigKnown)
		assert.Contains(t, filesOf(t, d, "alice"), "/home/alice/.ssh/authorized_keys")
		assert.Empty(t, filesOf(t, d, "deploy"), "no Match User override without the config")
	})

	t.Run("no mount table: nothing is touched", func(t *testing.T) {
		files := authKeysFixture()
		delete(files, "proc/self/mountinfo")
		sec, _ := authKeysOf(t, fixture(t, files), testSSHDResult())
		assert.Equal(t, StatusUnknown, sec.Status)
	})

	t.Run("an unreadable file: unreadable, not missing", func(t *testing.T) {
		sc := fixture(t, authKeysFixture())
		unreadable(t, sc, "home/alice/.ssh/authorized_keys")
		_, d := authKeysOf(t, sc, testSSHDResult())
		assert.Equal(t, keysUnreadable, filesOf(t, d, "alice")["/home/alice/.ssh/authorized_keys"].Status)
	})

	t.Run("too large", func(t *testing.T) {
		files := merge(authKeysFixture(), map[string]string{"home/alice/.ssh/authorized_keys": strings.Repeat("#", authKeysFileLimit+1)})
		_, d := authKeysOf(t, fixture(t, files), testSSHDResult())
		assert.Equal(t, keysTooLarge, filesOf(t, d, "alice")["/home/alice/.ssh/authorized_keys"].Status)
	})

	t.Run("at most 2000 keys", func(t *testing.T) {
		line := "ssh-ed25519 " + b64(ed25519Blob(9)) + "\n"
		files := merge(authKeysFixture(), map[string]string{"home/alice/.ssh/authorized_keys": strings.Repeat(line, maxKeysPerFile+1)})
		_, d := authKeysOf(t, fixture(t, files), testSSHDResult())
		f := filesOf(t, d, "alice")["/home/alice/.ssh/authorized_keys"]
		assert.Len(t, f.Keys, maxKeysPerFile)
		assert.True(t, f.Truncated)
	})

	t.Run("AuthorizedKeysFile none and a glob", func(t *testing.T) {
		files := merge(authKeysFixture(), map[string]string{"home/alice/.ssh/keys.d/a.pub": "ssh-ed25519 " + b64(ed25519Blob(7)) + "\n", "home/alice/.ssh/keys.d/.hidden": "x"})
		sshd := &sshdResult{authorizedKeysFiles: []string{"none", ".ssh/keys.d/*"}, strictModes: false}
		_, d := authKeysOf(t, fixture(t, files), sshd)
		alice := filesOf(t, d, "alice")
		assert.Len(t, alice, 1)
		assert.Equal(t, keysOK, alice["/home/alice/.ssh/keys.d/a.pub"].Status)
	})
}

func TestParseAuthKeyLine(t *testing.T) {
	cases := []struct {
		name string
		line string
		ok   bool
	}{
		{"plain", "ssh-ed25519 " + b64(ed25519Blob(1)), true},
		{"with a comment", "ssh-ed25519 " + b64(ed25519Blob(1)) + " a b c", true},
		{"options", `no-pty,permitopen="host:22" ssh-ed25519 ` + b64(ed25519Blob(1)), true},
		{"blank", "   ", false},
		{"comment", "# ssh-ed25519 " + b64(ed25519Blob(1)), false},
		{"unknown type", "ssh-foo " + b64(ed25519Blob(1)), false},
		{"unterminated quote", `command="x ssh-ed25519 ` + b64(ed25519Blob(1)), false},
		{"truncated blob", "ssh-ed25519 " + b64([]byte{0, 0, 0, 9, 's'}), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, ok := parseAuthKeyLine(tc.line)
			assert.Equal(t, tc.ok, ok)
		})
	}
}

func FuzzAuthKeyLine(f *testing.F) {
	f.Add("ssh-ed25519 " + b64(ed25519Blob(1)) + " c")
	f.Add(`from="a,b",command="x \" y" ssh-rsa ` + b64(rsaBlob(1024)))
	f.Add(`"`)
	f.Fuzz(func(t *testing.T, line string) {
		k, ok := parseAuthKeyLine(line)
		if ok && !strings.HasPrefix(k.FP, "SHA256:") {
			t.Fatalf("fingerprint %q", k.FP)
		}
	})
}
