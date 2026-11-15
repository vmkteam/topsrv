//go:build unix

package security

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Cases from the review of the A2 sections: user-controlled paths that
// must not lead the root agent anywhere.

const reviewMountinfo = "22 1 8:1 / / rw - ext4 /dev/sda1 rw\n" +
	"23 22 0:21 / /proc rw - proc proc rw\n" +
	"40 22 0:50 / /net rw - autofs auto.net rw\n"

func TestResolveUser(t *testing.T) {
	sc := fixture(t, map[string]string{
		"proc/self/mountinfo":  reviewMountinfo,
		"srv/keys/alice":       "k",
		"home/alice/up":        "-> ../../srv/keys", // relative, with ..
		"home/alice/abs":       "-> /srv/keys",
		"home/alice/away":      "-> /net/server/alice", // into autofs
		"home/alice/loop":      "-> loop",
		"home/alice/kmsg":      "-> /proc/kmsg",
		"home/alice/.ssh/keys": "k",
		"proc/kmsg":            "",
	})

	got, err := sc.resolveUser("/home/alice/up/alice")
	require.NoError(t, err)
	assert.Equal(t, "/srv/keys/alice", got)

	got, err = sc.resolveUser("/home/alice/abs/alice")
	require.NoError(t, err)
	assert.Equal(t, "/srv/keys/alice", got)

	_, err = sc.resolveUser("/home/alice/away/.ssh/authorized_keys")
	assert.Equal(t, ReasonRemoteFSSkipped, reasonOf(err), "the autofs target is refused before an lstat mounts it")

	_, err = sc.resolveUser("/home/alice/loop")
	assert.Equal(t, ReasonNotRegular, reasonOf(err), "ELOOP")

	got, err = sc.resolveUser("/home/alice/kmsg")
	require.NoError(t, err, "an lstat in procfs is harmless")
	_, _, err = sc.readUser(got, 64)
	assert.Equal(t, ReasonNotRegular, reasonOf(err), "a read there is refused")

	_, err = sc.resolveUser("/proc/nothere/.ssh/authorized_keys")
	assert.Equal(t, ReasonNotFound, reasonOf(err), "missing, not refused: the home of sys is /dev")
}

func TestAuthorizedKeysProcKmsg(t *testing.T) {
	// /proc/kmsg is a regular file that blocks and consumes kernel messages;
	// a FIFO stands in for it: opening it by mistake would hang the test.
	sc := fixture(t, map[string]string{
		"proc/self/mountinfo":             reviewMountinfo,
		"home/alice/.ssh/authorized_keys": "-> /proc/kmsg",
	})
	require.NoError(t, syscall.Mkfifo(filepath.Join(sc.root, "proc/kmsg"), 0o600))

	done := make(chan authKeysData, 1)
	go func() {
		_, d := authKeysOf(t, sc, testSSHDResult())
		done <- d
	}()
	select {
	case d := <-done:
		assert.Equal(t, keysIgnoredBySSHD, filesOf(t, d, "alice")["/home/alice/.ssh/authorized_keys"].Status)
	case <-time.After(2 * time.Second):
		t.Fatal("followed a link into procfs")
	}
}

func TestReadUserSwappedDirectory(t *testing.T) {
	sc := fixture(t, map[string]string{
		"proc/self/mountinfo":             reviewMountinfo,
		"home/alice/.ssh/authorized_keys": "mine",
		"root/.ssh/authorized_keys":       "root's",
	})
	resolved, err := sc.resolveUser("/home/alice/.ssh/authorized_keys")
	require.NoError(t, err)
	// After the check, .ssh is swapped for a link to root's directory.
	require.NoError(t, os.RemoveAll(filepath.Join(sc.root, "home/alice/.ssh")))
	require.NoError(t, os.Symlink(filepath.Join(sc.root, "root/.ssh"), filepath.Join(sc.root, "home/alice/.ssh")))

	_, _, err = sc.readUser(resolved, 64)

	require.Error(t, err, "the swapped directory is never followed")
	assert.Equal(t, ReasonNotRegular, reasonOf(err))
}

func TestAuthorizedKeysGlobThroughLinks(t *testing.T) {
	files := map[string]string{
		"proc/self/mountinfo":         reviewMountinfo,
		"home/alice/.ssh":             "-> /net/server/alice", // the glob directory is behind autofs
		"home/bob/.ssh/keys.d":        "-> /srv/bobkeys",      // a linked directory sshd's glob follows
		"srv/bobkeys/laptop.pub":      "ssh-ed25519 " + b64(ed25519Blob(8)) + "\n",
		"net/server/alice/keys.d/x":   "never read",
		"home/bob/.ssh/.placeholder/": "",
	}
	sc := fixture(t, files)
	noGroupWrite(t, sc.root)
	sshd := sshdOK(&sshdResult{authorizedKeysFiles: []string{".ssh/keys.d/*"}, strictModes: false})

	sec, d := authKeysOf(t, sc, sshd)

	assert.Contains(t, sec.Gaps, Gap{Path: "/home/alice/.ssh/keys.d", Reason: ReasonRemoteFSSkipped}, "unknown, not empty")
	bob := filesOf(t, d, "bob")["/home/bob/.ssh/keys.d/laptop.pub"]
	assert.Equal(t, keysOK, bob.Status)
	assert.Len(t, bob.Keys, 1)
}

func TestReadableBy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys")
	require.NoError(t, os.WriteFile(path, nil, 0o600))
	me, myGroup := int64(os.Getuid()), int64(os.Getgid())
	stat := func(mode os.FileMode) os.FileInfo {
		require.NoError(t, os.Chmod(path, mode))
		fi, err := os.Stat(path)
		require.NoError(t, err)
		return fi
	}

	assert.True(t, readableBy(stat(0o600), account{UID: me}))
	assert.False(t, readableBy(stat(0o600), account{UID: me + 1, GID: myGroup}), "root's 0600 file is not the user's")
	assert.True(t, readableBy(stat(0o640), account{UID: me + 1, GID: myGroup}))
	assert.True(t, readableBy(stat(0o604), account{UID: me + 1, GID: myGroup + 1}))
	assert.True(t, readableBy(stat(0), account{UID: 0, GID: myGroup + 1}), "root reads any file")
}

func TestSSHDUntrustedListener(t *testing.T) {
	// A user's ~/bin/sshd at a pid that sorts first must not choose the config.
	files := merge(hostProc(), sshdFixture(), map[string]string{
		"proc/1000/exe":     "-> /home/m/bin/sshd",
		"proc/1000/ns/mnt":  "-> mnt:[4026531841]",
		"proc/1000/cmdline": "sshd: /home/m/bin/sshd -f /home/m/evil [listener] 0 of 10-100 startups\x00",
		"home/m/bin/sshd":   "",
		"home/m/evil":       "PasswordAuthentication no\nInclude /root/secret\n",
		"root/secret":       "AKIAIOSFODNN7EXAMPLE\n",
	})
	sc := fixture(t, files)
	require.NoError(t, os.Chmod(filepath.Join(sc.root, "home/m/bin/sshd"), 0o777)) // anyone could have written it

	sec, _ := collectSSHD(t.Context(), sc)

	d := sec.Data.(sshdData)
	assert.Equal(t, "/etc/ssh/sshd_config", d.ConfigFile, "the system listener, not the user's")
	assert.NotContains(t, toJSON(t, sec), "AKIA")
}

func TestSSHDPAMUnreadable(t *testing.T) {
	sc := fixture(t, merge(hostProc(), sshdFixture()))
	unreadable(t, sc, "usr/lib/openssh/sshd-session")

	sec, _ := collectSSHD(t.Context(), sc)

	assert.Nil(t, sec.Data.(sshdData).PAMCompiled, "PAM may be in the binary it could not read: unknown, not no")
}

func TestSSHDResultOf(t *testing.T) {
	sc := fixture(t, merge(hostProc(), sshdFixture(), map[string]string{
		"etc/ssh/sshd_config.d/50-cloud-init.conf": "StrictModes no\nAuthorizedKeysFile .ssh/keys %h/.ssh/more\n",
	}))

	_, res := collectSSHD(t.Context(), sc)

	r := res.(*sshdResult)
	assert.False(t, r.strictModes)
	assert.Equal(t, []string{".ssh/keys", "%h/.ssh/more"}, r.authorizedKeysFiles)
}

func TestSudoersSubdirectorySkipped(t *testing.T) {
	sec := collectSudoers(t.Context(), fixture(t, merge(sudoFixture(), map[string]string{"etc/sudoers.d/subdir/x": "x ALL = ALL\n"})))

	assert.Equal(t, StatusOK, sec.Status, "sudo skips a directory in an includedir: no gap")
}
