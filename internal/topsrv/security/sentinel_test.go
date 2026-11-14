package security

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vmkteam/embedlog"
)

// sentinelFiles plants the §13 markers where the collector reads, and where
// later sections will: none may reach the snapshot or the logs. Each PR adds
// markers for its sections.
func sentinelFiles() map[string]string {
	return map[string]string{
		"proc/cmdline":              "BOOT_IMAGE=/vmlinuz ro mitigations=auto iscsi_password=SENTINELSECRET quiet\n",
		"proc/102/cmdline":          "/usr/local/bin/k3s\x00server\x00--token\x00SENTINELSECRET\x00",
		"proc/1/environ":            "LD_PRELOAD=/SENTINEL.so\x00container=docker\x00",
		"proc/sys/kernel/tainted":   "SENTINELLINE\n", // a broken source: a gap, never its content
		"etc/shadow":                "root:$6$SENTINELHASH$abc:19700:0:99999:7:::\n",
		"etc/passwd":                "root:x:0:0:Sentinel Person:/root:/bin/bash\n",
		"root/.ssh/authorized_keys": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGq0 sentinel@example.com\n",
	}
}

// captureLogs builds a verbose logger whose output goes to a temp file, and
// returns it with a func reading everything logged. embedlog binds the
// standard streams when the logger is built, so they are swapped only for
// that call; tests of this package do not run in parallel.
func captureLogs(t *testing.T) (embedlog.Logger, func() string) {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "log")
	require.NoError(t, err)
	t.Cleanup(func() { f.Close() })
	stdout, stderr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = f, f
	logger := embedlog.NewLogger(true, false)
	os.Stdout, os.Stderr = stdout, stderr
	return logger, func() string {
		b, err := os.ReadFile(f.Name())
		require.NoError(t, err)
		return string(b)
	}
}

func TestNoSecretsLeak(t *testing.T) {
	variants := map[string]map[string]string{
		"host": merge(hostFixture(), sentinelFiles()),
		// in a container the environment of PID 1 is read for container=
		"container": merge(hostFixture(), sentinelFiles(), map[string]string{"proc/self/ns/pid": "-> pid:[4026532501]"}),
	}
	for name, files := range variants {
		t.Run(name, func(t *testing.T) {
			c, _ := newTestCollector(t, files)
			logger, logged := captureLogs(t)
			c.Logger = logger
			// a panicking parser logs its error
			bad := &fakeSection{next: func(context.Context) Section { panic(errors.New("parse SENTINELLINE: invalid syntax")) }}
			c.sections = append(c.sections, bad.def("bad", time.Second))

			p := c.pass(t.Context(), Trigger{Cause: triggerStart})
			c.finish(t.Context(), p)

			snapshot, logs := toJSON(t, p), logged()
			require.Contains(t, logs, "sentinel_test.go:", "the panic is logged with its type and site")
			for _, marker := range []string{"SENTINEL", "sentinel@example.com", "Sentinel Person"} {
				assert.NotContains(t, snapshot, marker, "snapshot")
				assert.NotContains(t, logs, marker, "logs")
			}
		})
	}
}
