package inventory

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeTree creates files under root; keys are absolute-style paths
// ("/etc/os-release"), values are file contents.
func writeTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for name, body := range files {
		path := filepath.Join(root, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o750))
		require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
	}
}

func TestDetectHost(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		want  HostMeta
	}{
		{
			name: "ubuntu 24.04",
			files: map[string]string{
				"/etc/os-release": "PRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\nNAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\n" +
					"VERSION_CODENAME=noble\nID=ubuntu\nID_LIKE=debian\n",
				"/proc/sys/kernel/osrelease": "6.8.0-90-generic\n",
			},
			want: HostMeta{
				OsID:              "ubuntu",
				OsVersionID:       "24.04",
				OsVersionCodename: "noble",
				OsIDLike:          []string{"debian"},
				OsPrettyName:      "Ubuntu 24.04.1 LTS",
				KernelRelease:     "6.8.0-90-generic",
			},
		},
		{
			name: "rocky 9 with several ID_LIKE values",
			files: map[string]string{
				"/etc/os-release": "NAME=\"Rocky Linux\"\nID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"\n" +
					"VERSION_ID=\"9.5\"\nPRETTY_NAME=\"Rocky Linux 9.5 (Blue Onyx)\"\n",
				"/proc/sys/kernel/osrelease": "5.14.0-503.14.1.el9_5.x86_64\n",
			},
			want: HostMeta{
				OsID:          "rocky",
				OsVersionID:   "9.5",
				OsIDLike:      []string{"rhel", "centos", "fedora"},
				OsPrettyName:  "Rocky Linux 9.5 (Blue Onyx)",
				KernelRelease: "5.14.0-503.14.1.el9_5.x86_64",
			},
		},
		{
			name: "alpine without codename, comments and blank lines skipped",
			files: map[string]string{
				"/etc/os-release": "# generated\n\nNAME=\"Alpine Linux\"\nID=alpine\nVERSION_ID=3.22.0\n" +
					"PRETTY_NAME=\"Alpine Linux v3.22\"\n",
				"/proc/sys/kernel/osrelease": "6.12.13-0-lts",
			},
			want: HostMeta{
				OsID:          "alpine",
				OsVersionID:   "3.22.0",
				OsPrettyName:  "Alpine Linux v3.22",
				KernelRelease: "6.12.13-0-lts",
			},
		},
		{
			name:  "nothing readable leaves only the arch",
			files: nil,
			want:  HostMeta{},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeTree(t, root, tc.files)

			got := DetectHost(root)

			tc.want.KernelArch = runtime.GOARCH
			assert.Equal(t, tc.want, got)
			assert.Empty(t, got.PackageManager, "PackageManager is filled per snapshot by the caller")
		})
	}
}

func TestManagers(t *testing.T) {
	cases := []struct {
		name    string
		markers []string
		want    []string
	}{
		{"debian", []string{DpkgStatusPath}, []string{ManagerDpkg}},
		{"rhel 9 sqlite rpmdb", []string{"/var/lib/rpm/rpmdb.sqlite"}, []string{ManagerRpm}},
		{"rhel 8 bdb rpmdb", []string{"/var/lib/rpm/Packages"}, []string{ManagerRpm}},
		{"suse ndb rpmdb", []string{"/var/lib/rpm/Packages.db"}, []string{ManagerRpm}},
		{"ostree sysimage rpmdb", []string{"/usr/lib/sysimage/rpm/rpmdb.sqlite"}, []string{ManagerRpm}},
		{"alpine", []string{ApkInstalledPath}, []string{ManagerApk}},
		{
			"mixed container keeps dpkg, rpm, apk order",
			[]string{ApkInstalledPath, "/var/lib/rpm/rpmdb.sqlite", DpkgStatusPath},
			[]string{ManagerDpkg, ManagerRpm, ManagerApk},
		},
		{"no package database", nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			files := make(map[string]string, len(tc.markers))
			for _, m := range tc.markers {
				files[m] = ""
			}
			writeTree(t, root, files)

			assert.Equal(t, tc.want, Managers(root))

			wantPrimary := ""
			if len(tc.want) > 0 {
				wantPrimary = tc.want[0]
			}
			assert.Equal(t, wantPrimary, PrimaryManager(root))
		})
	}
}

func TestRpmDB(t *testing.T) {
	t.Run("sqlite wins over bdb and sysimage", func(t *testing.T) {
		root := t.TempDir()
		writeTree(t, root, map[string]string{
			"/var/lib/rpm/Packages":              "",
			"/var/lib/rpm/rpmdb.sqlite":          "",
			"/usr/lib/sysimage/rpm/rpmdb.sqlite": "",
		})
		assert.Equal(t, root+"/var/lib/rpm/rpmdb.sqlite", RpmDB(root))
	})

	t.Run("none found", func(t *testing.T) {
		assert.Empty(t, RpmDB(t.TempDir()))
	})
}
