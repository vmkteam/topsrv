package topsrv

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vmkteam/embedlog"
)

func TestDiskCollector(t *testing.T) {
	c := NewDiskCollector(embedlog.Logger{})
	assert.Equal(t, "disk", c.Name())

	n := collectAndLint(t, c)
	require.NotZero(t, n, "disk collector returned no metrics")
}

func TestDiskCollectorKeyMetrics(t *testing.T) {
	reg := prometheus.NewRegistry()
	reg.MustRegister(NewDiskCollector(embedlog.Logger{}))

	// Filesystem metrics (always present).
	requireMetric(t, reg, "topsrv_filesystem_bytes")
	requireMetric(t, reg, "topsrv_filesystem_inodes")
}

func TestDiskCollectorIOMetrics(t *testing.T) {
	reg := prometheus.NewRegistry()
	reg.MustRegister(NewDiskCollector(embedlog.Logger{}))

	mfs, err := reg.Gather()
	require.NoError(t, err)

	// IO metrics may be absent on some systems (e.g., macOS without physical disks).
	ioNames := map[string]bool{}
	for _, mf := range mfs {
		ioNames[mf.GetName()] = true
	}

	if ioNames["topsrv_disk_read_bytes_total"] {
		requireMetric(t, reg, "topsrv_disk_read_bytes_total")
		requireMetric(t, reg, "topsrv_disk_write_bytes_total")
		requireMetric(t, reg, "topsrv_disk_read_ops_total")
		requireMetric(t, reg, "topsrv_disk_write_ops_total")
		requireMetric(t, reg, "topsrv_disk_read_time_seconds_total")
		requireMetric(t, reg, "topsrv_disk_write_time_seconds_total")
		requireMetric(t, reg, "topsrv_disk_io_time_seconds_total")
		requireMetric(t, reg, "topsrv_disk_io_time_weighted_seconds_total")
	} else {
		t.Log("disk IO metrics not available on this system, skipping IO checks")
	}
}

func TestDiskCollectorFilesystemLabels(t *testing.T) {
	reg := prometheus.NewRegistry()
	reg.MustRegister(NewDiskCollector(embedlog.Logger{}))

	mfs, err := reg.Gather()
	require.NoError(t, err)

	for _, mf := range mfs {
		if mf.GetName() != "topsrv_filesystem_bytes" {
			continue
		}
		require.NotEmpty(t, mf.GetMetric())

		// Check labels: mountpoint, device, fstype, type.
		labels := mf.GetMetric()[0].GetLabel()
		labelNames := make([]string, len(labels))
		for i, l := range labels {
			labelNames[i] = l.GetName()
		}
		assert.Contains(t, labelNames, "mountpoint")
		assert.Contains(t, labelNames, "device")
		assert.Contains(t, labelNames, "fstype")
		assert.Contains(t, labelNames, "type")

		// Check type values: total, used, free.
		types := map[string]bool{}
		for _, m := range mf.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "type" {
					types[l.GetValue()] = true
				}
			}
		}
		for _, typ := range []string{"total", "used", "free"} {
			assert.True(t, types[typ], "missing filesystem type: %s", typ)
		}
		return
	}
	t.Fatal("topsrv_filesystem_bytes not found")
}

func TestMsToSec(t *testing.T) {
	tests := []struct {
		ms   uint64
		want float64
	}{
		{0, 0},
		{1000, 1.0},
		{500, 0.5},
		{1, 0.001},
	}
	for _, tt := range tests {
		assert.InDelta(t, tt.want, float64(tt.ms)*msToSec, 1e-15)
	}
}

func TestIsEphemeralMount(t *testing.T) {
	tests := []struct {
		name string
		p    disk.PartitionStat
		want bool
	}{
		{"zfs dataset", disk.PartitionStat{Device: "tank/data", Mountpoint: "/mnt/tank/data", Fstype: "zfs"}, false},
		{"zfs snapshot", disk.PartitionStat{Device: "tank/data@daily", Mountpoint: "/mnt/tank/data/.zfs/snapshot/daily", Fstype: "zfs"}, true},
		{"docker zfs layer", disk.PartitionStat{Device: "rpool/docker/3f1a", Mountpoint: "/var/lib/docker/zfs/graph/3f1a", Fstype: "zfs"}, true},
		{"ext4 under graph path", disk.PartitionStat{Device: "/dev/sdb1", Mountpoint: "/srv/zfs/graph/x", Fstype: "ext4"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isEphemeralMount(tt.p))
		})
	}
}

// TestDiskCollectorPartitions pins which mounts become filesystem series, so a
// gopsutil bump can't change it unnoticed. Before v4.26.10 ZFS-only hosts
// (TrueNAS, Proxmox) reported none, as ZFS sources are dataset names, not
// paths, and a btrfs root subvolume was taken for a bind; since then network
// filesystems such as CIFS are left out, being nodev.
func TestDiskCollectorPartitions(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("mountinfo parsing is Linux-only")
	}

	// every mountpoint exists, so only the filters keep a mount out
	base := t.TempDir()
	dir := func(name string) string {
		p := filepath.Join(base, name)
		require.NoError(t, os.MkdirAll(p, 0o755))
		return p
	}
	zroot, zdata, zsnap, zlayer := dir("zroot"), dir("zdata"), dir("zdata/.zfs/snapshot/daily"), dir("docker/zfs/graph/3f1a")
	broot, bhome, share := dir("broot"), dir("bhome"), dir("share")

	mountinfo := strings.Join([]string{
		"25 1 0:22 / " + zroot + " rw,relatime shared:1 - zfs boot-pool/ROOT/24.10 rw,xattr,posixacl",
		"26 25 0:23 / " + zdata + " rw,relatime shared:2 - zfs tank/data rw,xattr,posixacl",
		"27 26 0:24 / " + zsnap + " ro,relatime - zfs tank/data@daily ro",
		"28 25 0:25 / " + zlayer + " rw,relatime - zfs tank/docker/3f1a rw",
		"29 25 0:26 /@ " + broot + " rw,relatime shared:3 - btrfs /dev/sdb2 rw,subvolid=256,subvol=/@",
		"30 29 0:26 /@home " + bhome + " rw,relatime shared:4 - btrfs /dev/sdb2 rw,subvolid=257,subvol=/@home",
		"31 25 0:27 / " + share + " rw,relatime shared:5 - cifs //nas.example.com/share rw,vers=3.1.1",
	}, "\n") + "\n"
	proc := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(proc, "1"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(proc, "1", "mountinfo"), []byte(mountinfo), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(proc, "filesystems"), []byte("\tbtrfs\nnodev\tcifs\nnodev\tzfs\n"), 0o644))
	t.Setenv("HOST_PROC", proc)

	ch := make(chan prometheus.Metric, 64)
	NewDiskCollector(embedlog.Logger{}).collectFilesystems(ch)
	close(ch)

	got := map[string]string{} // mountpoint -> device
	for m := range ch {
		var pb dto.Metric
		require.NoError(t, m.Write(&pb))
		labels := map[string]string{}
		for _, l := range pb.GetLabel() {
			labels[l.GetName()] = l.GetValue()
		}
		if labels["device"] != "" {
			got[labels["mountpoint"]] = labels["device"]
		}
	}
	assert.Equal(t, map[string]string{
		zroot: "boot-pool/ROOT/24.10",
		zdata: "tank/data",
		broot: "/dev/sdb2", // bhome is the same filesystem
	}, got)
}
