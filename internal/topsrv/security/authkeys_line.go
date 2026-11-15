package security

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"math/big"
	"slices"
	"strings"
)

// keyTypeRSA is the blob type of an RSA key.
const keyTypeRSA = "ssh-rsa"

// authKeyTypes sshd accepts as the key type of a line.
var authKeyTypes = []string{
	"ssh-ed25519", keyTypeRSA, "ssh-dss",
	"rsa-sha2-256", "rsa-sha2-512", // signature names sshd also takes for an RSA key
	"rsa-sha2-256-cert-v01@openssh.com", "rsa-sha2-512-cert-v01@openssh.com",
	"ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
	"sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com",
	"ssh-ed25519-cert-v01@openssh.com", "ssh-rsa-cert-v01@openssh.com", "ssh-dss-cert-v01@openssh.com",
	"ecdsa-sha2-nistp256-cert-v01@openssh.com", "ecdsa-sha2-nistp384-cert-v01@openssh.com",
	"ecdsa-sha2-nistp521-cert-v01@openssh.com", "sk-ssh-ed25519-cert-v01@openssh.com",
	"sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
}

// Options sshd knows (auth-options.c): value options need name="value",
// flags take none. Anything else makes sshd drop the whole line.
var (
	authKeyValueOptions = []string{"command", "environment", "expiry-time", "from", "permitlisten", "permitopen", "principals", "tunnel"}
	authKeyFlagOptions  = []string{
		"agent-forwarding", "cert-authority", "no-agent-forwarding", "no-port-forwarding", "no-pty", "no-user-rc",
		"no-x11-forwarding", "port-forwarding", "pty", "restrict", "user-rc", "x11-forwarding",
		"no-touch-required", "touch-required", "verify-required", "no-verify-required",
	}
)

// authKey is one key of an authorized_keys file. The comment is never
// read into it, option values never leave the host: only whether an option
// is there.
type authKey struct {
	FP           string         `json:"fp"`
	Type         string         `json:"type"`
	Bits         int            `json:"bits,omitempty"`
	TypeMismatch bool           `json:"typeMismatch,omitempty"` // the blob says another type than the line
	Options      authKeyOptions `json:"options"`
	// Rejected: sshd drops the line — an option it does not know or one
	// written wrong, or a blob of another type than the line says.
	Rejected bool `json:"rejected,omitempty"`
}

type authKeyOptions struct {
	Restrict         bool `json:"restrict,omitempty"`
	From             bool `json:"from,omitempty"`
	Command          bool `json:"command,omitempty"`
	NoPortForwarding bool `json:"noPortForwarding,omitempty"`
	NoPty            bool `json:"noPty,omitempty"`
	PermitOpen       bool `json:"permitopen,omitempty"`
	CertAuthority    bool `json:"certAuthority,omitempty"`
	Expiry           bool `json:"expiry,omitempty"`
	Environment      bool `json:"environment,omitempty"`
}

// parseAuthKeyLine parses one line as sshd does: "type base64" first, and
// only when that fails a leading options field, quotes and \" respected. ok
// is false for blank, comment and unparsable lines.
func parseAuthKeyLine(line string) (authKey, bool) {
	line = strings.TrimSpace(line)
	if line == "" || line[0] == '#' {
		return authKey{}, false
	}
	if k, ok := parseKeyPart(line); ok {
		return k, true
	}
	opts, rest, ok := splitOptions(line)
	if !ok {
		return authKey{}, false
	}
	k, ok := parseKeyPart(strings.TrimLeft(rest, " \t"))
	if !ok {
		return authKey{}, false
	}
	var badOption bool
	k.Options, badOption = parseOptions(opts)
	k.Rejected = k.Rejected || badOption
	return k, true
}

// parseKeyPart parses "type base64 [comment]"; the comment is dropped.
func parseKeyPart(s string) (authKey, bool) {
	f := strings.Fields(s)
	if len(f) < 2 || !slices.Contains(authKeyTypes, f[0]) {
		return authKey{}, false
	}
	blob, err := base64.StdEncoding.DecodeString(f[1])
	if err != nil || len(blob) == 0 {
		return authKey{}, false
	}
	sum := sha256.Sum256(blob)
	k := authKey{FP: "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:]), Type: f[0]}
	blobType, rest, ok := sshString(blob)
	if !ok {
		return authKey{}, false
	}
	k.TypeMismatch = string(blobType) != canonicalKeyType(f[0])
	k.Rejected = k.TypeMismatch
	k.Bits = keyBits(string(blobType), rest)
	return k, true
}

// canonicalKeyType is the blob type of a line's key type: rsa-sha2-* are
// names of RSA signatures, the key in the blob is ssh-rsa.
func canonicalKeyType(t string) string {
	switch t {
	case "rsa-sha2-256", "rsa-sha2-512":
		return keyTypeRSA
	case "rsa-sha2-256-cert-v01@openssh.com", "rsa-sha2-512-cert-v01@openssh.com":
		return "ssh-rsa-cert-v01@openssh.com"
	}
	return t
}

// splitOptions cuts the options field: up to the first whitespace outside
// quotes, where \" does not close a quote.
func splitOptions(s string) (opts, rest string, ok bool) {
	quoted := false
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '\\' && quoted && i+1 < len(s) && s[i+1] == '"':
			i++
		case c == '"':
			quoted = !quoted
		case (c == ' ' || c == '\t') && !quoted:
			return s[:i], s[i:], true
		}
	}
	return "", "", false
}

// parseOptions reads the option names; values are only checked to be
// quoted, never kept.
func parseOptions(s string) (o authKeyOptions, rejected bool) {
	for _, opt := range splitOptionList(s) {
		name, value, hasValue := strings.Cut(opt, "=")
		name = strings.ToLower(name)
		quoted := len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"'
		switch {
		case slices.Contains(authKeyValueOptions, name) && hasValue && quoted,
			slices.Contains(authKeyFlagOptions, name) && !hasValue:
		default:
			rejected = true
			continue
		}
		switch name {
		case "restrict":
			o.Restrict = true
		case "from":
			o.From = true
		case "command":
			o.Command = true
		case "no-port-forwarding":
			o.NoPortForwarding = true
		case "no-pty":
			o.NoPty = true
		case "permitopen":
			o.PermitOpen = true
		case "cert-authority":
			o.CertAuthority = true
		case "expiry-time":
			o.Expiry = true
		case "environment":
			o.Environment = true
		}
	}
	return o, rejected
}

// splitOptionList splits options at commas outside quotes.
func splitOptionList(s string) []string {
	var (
		out    []string
		quoted bool
		start  int
	)
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '\\' && quoted && i+1 < len(s) && s[i+1] == '"':
			i++
		case c == '"':
			quoted = !quoted
		case c == ',' && !quoted:
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

// sshString reads an SSH wire string: a uint32 length and the bytes.
func sshString(b []byte) (s, rest []byte, ok bool) {
	if len(b) < 4 {
		return nil, nil, false
	}
	n := binary.BigEndian.Uint32(b)
	if uint64(n) > uint64(len(b)-4) {
		return nil, nil, false
	}
	return b[4 : 4+n], b[4+n:], true
}

// keyBits is the size of the key in the blob: the modulus of RSA, p of DSA,
// the curve of ECDSA; 256 for Ed25519. 0 when unknown.
func keyBits(blobType string, rest []byte) int {
	switch {
	case strings.Contains(blobType, "ed25519"), strings.Contains(blobType, "nistp256"):
		return 256
	case strings.Contains(blobType, "nistp384"):
		return 384
	case strings.Contains(blobType, "nistp521"):
		return 521
	case blobType == keyTypeRSA:
		_, n, ok := sshString(rest) // e, then n
		if !ok {
			return 0
		}
		return mpintBits(n)
	case blobType == "ssh-dss":
		return mpintBits(rest) // p
	}
	return 0
}

func mpintBits(b []byte) int {
	n, _, ok := sshString(b)
	if !ok {
		return 0
	}
	return new(big.Int).SetBytes(n).BitLen()
}
