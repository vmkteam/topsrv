package security

import (
	"bufio"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// memAPT serves an APT configuration from path → content.
func memAPT(files map[string]string) aptFiles {
	return aptFiles{
		readFile: func(p string) ([]byte, error) {
			b, ok := files[p]
			if !ok {
				return nil, fs.ErrNotExist
			}
			return []byte(b), nil
		},
		readDir: func(dir string) ([]string, error) {
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

// testdataTree reads testdata/<dir>/etc/... into path → content, keys as
// the host sees them.
func testdataTree(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	root := filepath.Join("testdata", dir)
	require.NoError(t, filepath.WalkDir(filepath.Join(root, "etc"), func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		rel, _ := filepath.Rel(root, p)
		out["/"+filepath.ToSlash(rel)] = string(b)
		return err
	}))
	return out
}

// TestAPTConfigOracle compares the parse of real apt.conf.d directories
// with what `apt-config dump` printed on the same machines.
func TestAPTConfigOracle(t *testing.T) {
	for _, distro := range []string{"debian-12", "ubuntu-24.04"} {
		t.Run(distro, func(t *testing.T) {
			cfg := readAPTConfig(memAPT(testdataTree(t, "apt/"+distro)))
			require.Nil(t, cfg.err)

			f, err := os.Open(filepath.Join("testdata", "apt", distro, "apt-config-dump.txt"))
			require.NoError(t, err)
			defer f.Close()
			lists := map[string][]string{}
			s := bufio.NewScanner(f)
			for s.Scan() {
				key, val, ok := strings.Cut(s.Text(), " ")
				require.True(t, ok)
				val = strings.TrimSuffix(strings.TrimPrefix(val, `"`), `";`)
				if list, isItem := strings.CutSuffix(key, "::"); isItem {
					lists[list] = append(lists[list], val)
					continue
				}
				if val != "" {
					require.NotNil(t, cfg.value(key), key)
					assert.Equal(t, val, *cfg.value(key), key)
				}
			}
			require.NotEmpty(t, lists)
			for key, want := range lists {
				assert.Equal(t, want, cfg.list(key), key)
			}
		})
	}
}

func TestAPTConfigSyntax(t *testing.T) {
	cases := []struct {
		name string
		text string
		key  string
		want string
	}{
		{"nested blocks", `APT { Periodic { Enable "1"; }; };`, "APT::Periodic::Enable", "1"},
		{"a block over lines", "APT::Periodic {\n  Update-Package-Lists\n \"7\";\n};", "APT::Periodic::Update-Package-Lists", "7"},
		{"tags are case-insensitive", `apt::periodic::enable "1";`, "APT::Periodic::Enable", "1"},
		{"unquoted value", `APT::Periodic::Enable 0;`, "APT::Periodic::Enable", "0"},
		{"later wins", "A::B \"1\";\nA::B \"2\";", "A::B", "2"},
		{"quoted strings join", `A::B "x" "y";`, "A::B", "x y"},
		{"%xx in an unquoted word", `A::B x%20y;`, "A::B", "x y"},
		{"%xx stays in quotes", `A::B "x%20y";`, "A::B", "x%20y"},
		{"// comment", "A::B \"1\"; // A::B \"2\";", "A::B", "1"},
		{"# comment", "# A::B \"2\";\nA::B \"1\";", "A::B", "1"},
		{"/* */ over lines", "A::B \"1\"; /* A::B \"2\";\nA::B \"3\"; */ A::C \"4\";", "A::B", "1"},
		{"after /* */", "A::B \"1\"; /* x\n*/ A::B \"5\";", "A::B", "5"},
		{"comment markers in quotes", `A::B "http://x/#y";`, "A::B", "http://x/#y"},
		{"#clear", "A::B \"1\";\n#clear A::B;", "A::B", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := readAPTConfig(memAPT(map[string]string{aptConfMain: tc.text}))
			require.Nil(t, cfg.err)
			got := cfg.value(tc.key)
			if tc.want == "" {
				assert.Nil(t, got)
				return
			}
			require.NotNil(t, got)
			assert.Equal(t, tc.want, *got)
		})
	}
}

func TestAPTConfigLists(t *testing.T) {
	cfg := readAPTConfig(memAPT(map[string]string{
		aptConfDir + "/10a": "U::Origins-Pattern { \"a\"; \"b\"; };\n",
		aptConfDir + "/20b": "U::Origins-Pattern:: \"c\";\n",
		aptConfDir + "/30c": "#clear U::Allowed;\nU::Allowed { \"x\"; };\nDPkg::Pre-Install-Pkgs {\"/usr/sbin/dpkg-preconfigure --apt || true\";};\n",
		aptConfMain:         "U::Allowed:: \"y\";\n",
	}))
	require.Nil(t, cfg.err)
	assert.Equal(t, []string{"a", "b", "c"}, cfg.list("U::Origins-Pattern"), "items append across files")
	assert.Equal(t, []string{"x", "y"}, cfg.list("U::Allowed"), "apt.conf after the parts")
	assert.Equal(t, []string{"/usr/sbin/dpkg-preconfigure --apt || true"}, cfg.list("DPkg::Pre-Install-Pkgs"))
	assert.Equal(t, []string{}, cfg.list("U::None"))
	assert.Equal(t, []string{aptConfDir + "/10a", aptConfDir + "/20b", aptConfDir + "/30c", aptConfMain}, cfg.files)
}

func TestAPTConfigErrors(t *testing.T) {
	cases := []struct {
		text string
		code string
		line int
	}{
		{"{ A \"1\"; };", aptCodeBlockNoName, 1},
		{"A::B x y;", aptCodeExtraJunk, 1},
		{"A {\n#clear A::B;\n};", aptCodeDirectiveNested, 2},
		{"#clearall A;", aptCodeBadDirective, 1},
		{"A { \"#clear\"; };", aptCodeClearNoTree, 1},
		{"A::B \"1\"", aptCodeJunkAtEnd, 1},
		{"A::B \"1;\n", aptCodeJunkAtEnd, 2}, // apt counts the empty last line too
		{"#include /etc/apt/apt.conf;", aptCodeIncludeDepth, 1},
	}
	for _, tc := range cases {
		t.Run(tc.text, func(t *testing.T) {
			cfg := readAPTConfig(memAPT(map[string]string{aptConfMain: tc.text}))
			require.NotNil(t, cfg.err)
			assert.Equal(t, lineRef{File: aptConfMain, Line: tc.line, Code: tc.code}, *cfg.err)
		})
	}

	t.Run("apt stops at the first error", func(t *testing.T) {
		cfg := readAPTConfig(memAPT(map[string]string{
			aptConfDir + "/10a": "A::B \"1\";\nA::C x y;\nA::D \"1\";\n",
			aptConfDir + "/20b": "A::E \"1\";\n",
		}))
		require.NotNil(t, cfg.err)
		assert.Equal(t, 2, cfg.err.Line)
		assert.NotNil(t, cfg.value("A::B"))
		assert.Nil(t, cfg.value("A::D"))
		assert.Nil(t, cfg.value("A::E"))
	})
}

func TestAPTConfigInclude(t *testing.T) {
	cfg := readAPTConfig(memAPT(map[string]string{
		aptConfMain:            "#include /etc/apt/extra.conf;\n#include /etc/apt/extra.d/;\n",
		"/etc/apt/extra.conf":  "A::B \"1\";\n",
		"/etc/apt/extra.d/10x": "A::C \"2\";\n",
	}))
	require.Nil(t, cfg.err)
	assert.Equal(t, "1", *cfg.value("A::B"))
	assert.Equal(t, "2", *cfg.value("A::C"))
}

func TestAPTPartName(t *testing.T) {
	for name, want := range map[string]bool{
		"50unattended-upgrades":          true,
		"20apt-esm-hook.conf":            true,
		"a:b":                            true,
		"50unattended-upgrades.dpkg-old": false,
		"50unattended-upgrades.ucf-dist": false,
		".hidden":                        false,
		"x.":                             false,
		"bad name":                       false,
		"99local~":                       false,
	} {
		assert.Equal(t, want, aptPartName(name), name)
	}
}

func FuzzAPTConfig(f *testing.F) {
	for _, seed := range []string{`A { B "1"; };`, "A::B \"x\" \"y\";", "/* x\n*/ #clear A;", `{"a";};`, `A::B "%41"`, "#include /x/;"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, text string) {
		files := map[string]string{aptConfMain: text}
		cfg := readAPTConfig(memAPT(files))
		if cfg.nodes > aptMaxNodes {
			t.Fatalf("%d nodes", cfg.nodes)
		}
	})
}
