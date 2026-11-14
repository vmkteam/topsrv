package security

import (
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// writeTree creates files under root from path → content. Content "-> x"
// makes a symlink to x; a path ending in "/" makes a directory.
func writeTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for path, content := range files {
		full := filepath.Join(root, path)
		if strings.HasSuffix(path, "/") {
			require.NoError(t, os.MkdirAll(full, 0o755))
			continue
		}
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o755))
		if target, ok := strings.CutPrefix(content, "-> "); ok {
			require.NoError(t, os.Symlink(target, full))
			continue
		}
		require.NoError(t, os.WriteFile(full, []byte(content), 0o644))
	}
}

// fixture builds a scan root from files.
func fixture(t *testing.T, files map[string]string) *scanCtx {
	t.Helper()
	root := t.TempDir()
	writeTree(t, root, files)
	return &scanCtx{root: root}
}

// unreadable makes a fixture file unreadable; root reads it anyway, so the
// test is skipped there.
func unreadable(t *testing.T, sc *scanCtx, path string) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("root reads a 0000 file")
	}
	require.NoError(t, os.Chmod(filepath.Join(sc.root, path), 0))
}

// hostProc is the /proc of an agent on the host: host pid and net
// namespaces, the same root as PID 1, systemd as init.
func hostProc() map[string]string {
	return map[string]string{
		"proc/self/ns/pid": "-> pid:[4026531836]",
		"proc/self/ns/net": "-> net:[4026531840]",
		"proc/1/ns/net":    "-> net:[4026531840]",
		"proc/1/root":      "-> ../..",
		"proc/1/comm":      "systemd\n",
		"proc/self/status": "Name:\ttopsrv\nUid:\t0\t0\t0\t0\nCapEff:\t000001ffffffffff\n",
	}
}

// merge returns the union of the maps; later maps win.
func merge(ms ...map[string]string) map[string]string {
	out := make(map[string]string)
	for _, m := range ms {
		maps.Copy(out, m)
	}
	return out
}

// toJSON marshals v for assertions on the wire form.
func toJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return string(b)
}
