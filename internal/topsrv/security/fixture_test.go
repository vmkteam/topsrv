package security

import (
	"bytes"
	"io/fs"
	"debug/elf"
	"encoding/binary"
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

// noGroupWrite clears the group and other write bits under root, whatever
// the umask: StrictModes tests must not depend on it (002 under su).
func noGroupWrite(t *testing.T, root string) {
	t.Helper()
	require.NoError(t, filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.Type()&fs.ModeSymlink != 0 {
			return err
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		return os.Chmod(p, fi.Mode().Perm()&^0o022)
	}))
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
		"proc/self/ns/pid":  "-> pid:[4026531836]",
		"proc/self/ns/net":  "-> net:[4026531840]",
		"proc/self/ns/user": "-> user:[4026531837]",
		"proc/1/ns/net":     "-> net:[4026531840]",
		"proc/1/root":       "-> ../..",
		"proc/1/comm":       "systemd\n",
		"proc/self/status":  "Name:\ttopsrv\nUid:\t0\t0\t0\t0\nCapEff:\t000001ffffffffff\n",
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

// elfNeeding is a minimal ELF64 file whose dynamic section lists libs as
// DT_NEEDED: what ImportedLibraries reads, no code.
func elfNeeding(libs ...string) string {
	must := func(err error) {
		if err != nil {
			panic(err) // binary.Write into a buffer fails only on a bad type
		}
	}
	dynstr := []byte{0}
	dyn := make([]elf.Dyn64, 0, len(libs)+1)
	for _, l := range libs {
		dyn = append(dyn, elf.Dyn64{Tag: int64(elf.DT_NEEDED), Val: uint64(len(dynstr))})
		dynstr = append(append(dynstr, l...), 0)
	}
	dyn = append(dyn, elf.Dyn64{Tag: int64(elf.DT_NULL)})
	shstr := []byte("\x00.dynstr\x00.dynamic\x00.shstrtab\x00")

	var dynBuf bytes.Buffer
	must(binary.Write(&dynBuf, binary.LittleEndian, dyn))
	const hdr = 64
	dynstrOff := uint64(hdr)
	dynOff := dynstrOff + uint64(len(dynstr))
	shstrOff := dynOff + uint64(dynBuf.Len())
	shOff := shstrOff + uint64(len(shstr))

	var b bytes.Buffer
	h := elf.Header64{Type: uint16(elf.ET_DYN), Machine: uint16(elf.EM_X86_64), Version: uint32(elf.EV_CURRENT),
		Shoff: shOff, Ehsize: hdr, Phentsize: 56, Shentsize: 64, Shnum: 4, Shstrndx: 3}
	copy(h.Ident[:], []byte{0x7f, 'E', 'L', 'F', byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), byte(elf.EV_CURRENT)})
	must(binary.Write(&b, binary.LittleEndian, h))
	b.Write(dynstr)
	b.Write(dynBuf.Bytes())
	b.Write(shstr)
	sections := []elf.Section64{
		{},
		{Name: 1, Type: uint32(elf.SHT_STRTAB), Off: dynstrOff, Size: uint64(len(dynstr)), Addralign: 1},
		{Name: 9, Type: uint32(elf.SHT_DYNAMIC), Off: dynOff, Size: uint64(dynBuf.Len()), Link: 1, Entsize: 16, Addralign: 8},
		{Name: 18, Type: uint32(elf.SHT_STRTAB), Off: shstrOff, Size: uint64(len(shstr)), Addralign: 1},
	}
	must(binary.Write(&b, binary.LittleEndian, sections))
	return b.String()
}
