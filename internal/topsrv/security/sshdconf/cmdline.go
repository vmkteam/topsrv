package sshdconf

import (
	"path"
	"strings"
)

// argOptions take a value in sshd's getopt string
// "C:E:b:c:f:g:h:k:o:p:u:46DGQRTdeiqrtV".
const argOptions = "CEbcfghkopu"

// DefaultConfig is where sshd reads its configuration without -f.
const DefaultConfig = sshDir + "/sshd_config"

// Flags are the sshd command-line options the configuration depends on.
type Flags struct {
	ConfigFile string // -f, DefaultConfig without it
	Options    []string
	Ports      []string
}

// ParseFlags reads -f, -o and -p from sshd arguments (argv[0] excluded),
// combined ("-De") or not, the value attached ("-p2222") or next. A title
// loses the quotes of "-o 'Key value'": a -o value without "=" takes the
// arguments after it up to the next option — a guess, as it can only be.
func ParseFlags(args []string) Flags {
	f := Flags{ConfigFile: DefaultConfig}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if len(a) < 2 || a[0] != '-' {
			continue
		}
		for j := 1; j < len(a); j++ {
			if !strings.ContainsRune(argOptions, rune(a[j])) {
				continue
			}
			opt, val := a[j], a[j+1:]
			if val == "" && i+1 < len(args) {
				i++
				val = args[i]
			}
			if opt == 'o' && !strings.Contains(val, "=") {
				words := []string{val}
				for i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
					i++
					words = append(words, args[i])
				}
				val = strings.Join(words, " ")
			}
			switch opt {
			case 'f':
				f.ConfigFile = val
			case 'o':
				f.Options = append(f.Options, val)
			case 'p':
				f.Ports = append(f.Ports, val)
			}
			break
		}
	}
	return f
}

// ListenerArgs returns the arguments of the sshd listener from its
// /proc/PID/cmdline, argv[0] excluded. sshd 8.2+ overwrites its argv with a
// title that keeps the original command line before " [listener]"; an older
// one leaves argv as it was. ok is false for any other sshd process: a
// session ("sshd: alice@pts/0") or a pre-auth child.
func ListenerArgs(cmdline []byte) (args []string, ok bool) {
	parts := strings.Split(strings.TrimRight(string(cmdline), "\x00"), "\x00")
	if len(parts) == 1 {
		title, isTitle := strings.CutPrefix(parts[0], "sshd: ")
		before, _, isListener := strings.Cut(title, " [listener]")
		if isTitle {
			if !isListener {
				return nil, false
			}
			parts = strings.Fields(before)
		}
	}
	if len(parts) == 0 || path.Base(parts[0]) != "sshd" {
		return nil, false
	}
	return parts[1:], true
}
