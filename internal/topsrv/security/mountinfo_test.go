package security

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testMountinfo = `22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw
23 22 0:21 / /proc rw,nosuid shared:12 - proc proc rw
30 22 0:40 / /home rw,relatime shared:20 - nfs4 192.0.2.10:/export/home rw,vers=4.2
31 30 8:2 / /home/local rw,relatime shared:21 - ext4 /dev/sda2 rw
32 22 0:41 / /mnt/my\040share rw,relatime shared:22 - cifs //192.0.2.11/share rw
33 22 0:42 / /media rw,relatime shared:23 - autofs systemd-1 rw,fd=50
34 22 0:43 / /srv/sshfs rw,relatime shared:24 - fuse.sshfs user@192.0.2.12:/ rw
35 22 0:44 / /srv/data rw,relatime - nfs 192.0.2.13:/data rw
36 22 8:3 / /srv/data rw,relatime - xfs /dev/sdb1 rw
`

func TestParseMountinfo(t *testing.T) {
	m, err := parseMountinfo([]byte(testMountinfo))
	require.NoError(t, err)
	require.Len(t, m, 9)
	assert.Equal(t, mount{point: "/mnt/my share", fsType: "cifs"}, m[4], `\040 is a space`)

	cases := []struct {
		path   string
		remote bool
	}{
		{"/etc/ssh/sshd_config", false},
		{"/home/alice/.ssh/authorized_keys", true},
		{"/home", true},
		{"/home/local/bob/.ssh/authorized_keys", false},
		{"/homer/.ssh/authorized_keys", false},
		{"/mnt/my share/x", true},
		{"/media/usb", true},
		{"/srv/sshfs/key", true},
		{"/srv/data/key", false},
		{"/home/alice/../local/bob", false},
	}
	remote := m.remoteOnly()
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			assert.Equal(t, tc.remote, m.isRemote(tc.path))
			assert.Equal(t, tc.remote, remote.isRemote(tc.path), "the remote-only table answers the same")
		})
	}
}

func TestRemoteOnly(t *testing.T) {
	t.Run("keeps remote mounts and the mounts under them", func(t *testing.T) {
		m, err := parseMountinfo([]byte(testMountinfo))
		require.NoError(t, err)

		remote := m.remoteOnly()
		points := make([]string, 0, len(remote))
		for _, mt := range remote {
			points = append(points, mt.point)
		}

		assert.Equal(t, []string{"/home", "/home/local", "/mnt/my share", "/media", "/srv/sshfs", "/srv/data", "/srv/data"}, points)
	})

	t.Run("empty without remote mounts", func(t *testing.T) {
		m, err := parseMountinfo([]byte("22 1 8:1 / / rw - ext4 /dev/sda1 rw\n23 22 0:21 / /proc rw - proc proc rw\n"))
		require.NoError(t, err)

		assert.Empty(t, m.remoteOnly())
	})
}

func TestParseMountinfoErrors(t *testing.T) {
	for name, in := range map[string]string{
		"too few fields":   "22 1 8:1 / / rw\n",
		"no separator":     "22 1 8:1 / / rw,relatime shared:1 ext4 /dev/sda1 rw\n",
		"nothing after -":  "22 1 8:1 / / rw,relatime -\n",
		"bad octal escape": "22 1 8:1 / /a\\09x rw - ext4 /dev/sda1 rw\n",
		"cut octal escape": "22 1 8:1 / /a\\04 rw - ext4 /dev/sda1 rw\n",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := parseMountinfo([]byte(in))
			require.ErrorIs(t, err, errParse)
			assert.Contains(t, err.Error(), "line 1")
		})
	}
}

func TestIsRemoteFS(t *testing.T) {
	for _, fs := range []string{"nfs", "nfs4", "cifs", "smb3", "fuse", "fuse.sshfs", "autofs", "ceph", "glusterfs", "9p", "afs", "lustre", "gpfs"} {
		assert.True(t, isRemoteFS(fs), fs)
	}
	for _, fs := range []string{"ext4", "xfs", "btrfs", "tmpfs", "overlay", "zfs", "proc", "fusectl", "nfsd"} {
		assert.False(t, isRemoteFS(fs), fs)
	}
}

func TestLoadMounts(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{"proc/self/mountinfo": testMountinfo})

	m, err := loadMounts(root)
	require.NoError(t, err)
	assert.True(t, m.isRemote("/home/alice"))

	_, err = loadMounts(t.TempDir())
	assert.Equal(t, ReasonNotFound, reasonOf(err))
}
