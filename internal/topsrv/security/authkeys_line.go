package security

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"math/big"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
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
	keyTypeWebAuthn, keyTypeWebAuthnCert, // the ECDSA security key, signed through a browser
	"ssh-mldsa44-ed25519", "ssh-mldsa44-ed25519-cert", // OpenSSH 10.4, post-quantum hybrid
}

// Names of the WebAuthn variant of the ECDSA security key: sshd takes them
// for the key type, the blob says sk-ecdsa.
const (
	keyTypeWebAuthn     = "webauthn-sk-ecdsa-sha2-nistp256@openssh.com"
	keyTypeWebAuthnCert = "webauthn-sk-ecdsa-sha2-nistp256-cert-v01@openssh.com"
)

// keyTypeNameRe is what a key type name looks like: a token of another
// type is reported when its blob names it too (see parseKeyPart).
var keyTypeNameRe = regexp.MustCompile(`^[a-z][a-z0-9.@-]{2,63}$`)

// tunMax is SSH_TUNID_MAX: the highest tun device number a2tun takes.
const tunMax = 0x7fffffff - 2

// authKey is one key of an authorized_keys file. The comment is never
// read into it, option values never leave the host: only whether an option
// is there.
type authKey struct {
	FP           string `json:"fp"`
	Type         string `json:"type"`
	Bits         int    `json:"bits,omitempty"`
	TypeMismatch bool   `json:"typeMismatch,omitempty"` // the blob says another type than the line
	// TypeUnknown: a type this agent does not know, named so by the blob too;
	// sshd takes the line only if it knows the type.
	TypeUnknown bool           `json:"typeUnknown,omitempty"`
	Options     authKeyOptions `json:"options"`
	// Rejected: sshd drops the line — an option it does not know or one
	// written wrong, or a blob of another type than the line says.
	Rejected bool `json:"rejected,omitempty"`
}

// authKeyOptions says which options a key has, never their values. The
// No* flags are what the line leaves denied, applied left to right as sshd
// does: restrict denies all five, a later port-forwarding allows it again.
type authKeyOptions struct {
	Restrict      bool       `json:"restrict,omitempty"`
	From          bool       `json:"from,omitempty"`
	Command       bool       `json:"command,omitempty"`
	Principals    bool       `json:"principals,omitempty"`
	PermitOpen    bool       `json:"permitopen,omitempty"`
	PermitListen  bool       `json:"permitlisten,omitempty"`
	Tunnel        bool       `json:"tunnel,omitempty"`
	CertAuthority bool       `json:"certAuthority,omitempty"`
	Expiry        bool       `json:"expiry,omitempty"`
	ExpiresAt     *time.Time `json:"expiresAt,omitempty"` // the earliest expiry-time, UTC
	Environment   bool       `json:"environment,omitempty"`

	NoPortForwarding  bool `json:"noPortForwarding,omitempty"`
	NoAgentForwarding bool `json:"noAgentForwarding,omitempty"`
	NoX11Forwarding   bool `json:"noX11Forwarding,omitempty"`
	NoPty             bool `json:"noPty,omitempty"`
	NoUserRC          bool `json:"noUserRc,omitempty"`
	NoTouchRequired   bool `json:"noTouchRequired,omitempty"` // a security key may sign without a touch
	VerifyRequired    bool `json:"verifyRequired,omitempty"`  // and must verify the user (PIN)
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

// parseKeyPart parses "type base64 [comment]"; the comment is dropped. A
// type the agent does not know is taken when the blob names the same type:
// a key of a newer OpenSSH is reported, not lost.
func parseKeyPart(s string) (authKey, bool) {
	f := strings.Fields(s)
	known := len(f) >= 2 && slices.Contains(authKeyTypes, f[0])
	if len(f) < 2 || !known && !keyTypeNameRe.MatchString(f[0]) {
		return authKey{}, false
	}
	blob, err := base64.StdEncoding.DecodeString(f[1])
	if err != nil || len(blob) == 0 {
		return authKey{}, false
	}
	sum := sha256.Sum256(blob)
	k := authKey{FP: "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:]), Type: f[0], TypeUnknown: !known}
	blobType, rest, ok := sshString(blob)
	if !ok || !known && string(blobType) != f[0] {
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
	case keyTypeWebAuthn:
		return "sk-ecdsa-sha2-nistp256@openssh.com"
	case keyTypeWebAuthnCert:
		return "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com"
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

// parseOptions reads the options as sshauthopt_parse does, left to right:
// names case-insensitive, flags without a value (most negated by "no-"),
// value options quoted. Values are checked as sshd checks them, never kept.
// rejected: sshd drops the line.
func parseOptions(s string) (o authKeyOptions, rejected bool) {
	denied := map[string]*bool{
		"port-forwarding": &o.NoPortForwarding, "agent-forwarding": &o.NoAgentForwarding,
		"x11-forwarding": &o.NoX11Forwarding, "pty": &o.NoPty, "user-rc": &o.NoUserRC,
	}
	seen := map[string]bool{}
	for _, opt := range splitOptionList(s) {
		name, value, hasValue := strings.Cut(opt, "=")
		name = strings.ToLower(name)
		if !hasValue {
			if !o.setFlag(name, denied) {
				rejected = true
			}
			continue
		}
		if len(value) < 2 || value[0] != '"' || value[len(value)-1] != '"' {
			rejected = true
			continue
		}
		if !o.setValue(name, unquoteOption(value[1:len(value)-1]), seen) {
			rejected = true
		}
	}
	return o, rejected
}

// setFlag applies a flag option; false for a name sshd does not know.
func (o *authKeyOptions) setFlag(name string, denied map[string]*bool) bool {
	switch name {
	case "restrict":
		o.Restrict = true
		for _, d := range denied {
			*d = true
		}
		return true
	case "cert-authority":
		o.CertAuthority = true
		return true
	}
	base, negated := strings.CutPrefix(name, "no-")
	if d, ok := denied[base]; ok {
		*d = negated
		return true
	}
	switch base {
	case "touch-required":
		o.NoTouchRequired = negated
	case "verify-required":
		o.VerifyRequired = !negated
	default:
		return false
	}
	return true
}

// setValue applies a value option; false where sshd fails the line: an
// unknown name, a second command, principals or from, a value of the wrong
// form. The value is looked at, never stored.
func (o *authKeyOptions) setValue(name, value string, seen map[string]bool) bool {
	switch name {
	case "command", "principals", "from":
		if seen[name] {
			return false // "multiple clauses"
		}
		seen[name] = true
		o.Command = o.Command || name == "command"
		o.Principals = o.Principals || name == "principals"
		o.From = o.From || name == "from"
	case "environment":
		envName, _, ok := strings.Cut(value, "=")
		if !ok || !envNameRe.MatchString(envName) {
			return false
		}
		o.Environment = true
	case "expiry-time":
		t, ok := parseExpiry(value, time.Local) // sshd reads it in the local time of the host
		if !ok {
			return false
		}
		if o.ExpiresAt == nil || t.Before(*o.ExpiresAt) {
			o.ExpiresAt = &t
		}
		o.Expiry = true
	case "tunnel":
		if n, err := strconv.ParseUint(value, 10, 32); !strings.EqualFold(value, "any") && (err != nil || n > tunMax) {
			return false
		}
		o.Tunnel = true
	case "permitopen":
		o.PermitOpen = true
	case "permitlisten":
		o.PermitListen = true
	default:
		return false
	}
	return true
}

// envNameRe is valid_env_name of misc.c.
var envNameRe = regexp.MustCompile(`^[A-Za-z0-9_]+$`)

// parseExpiry is parse_absolute_time of misc.c: YYYYMMDD[HHMM[SS]], local
// time unless it ends in Z or UTC. The result is UTC.
func parseExpiry(v string, local *time.Location) (time.Time, bool) {
	loc := local
	if u := strings.ToUpper(v); strings.HasSuffix(u, "Z") && len(v) > 1 {
		v, loc = v[:len(v)-1], time.UTC
	} else if strings.HasSuffix(u, "UTC") && len(v) > 3 {
		v, loc = v[:len(v)-3], time.UTC
	}
	layouts := map[int]string{8: "20060102", 12: "200601021504", 14: "20060102150405"}
	layout, ok := layouts[len(v)]
	if !ok {
		return time.Time{}, false
	}
	t, err := time.ParseInLocation(layout, v, loc)
	if err != nil || t.Unix() <= 0 {
		return time.Time{}, false
	}
	return t.UTC(), true
}

// unquoteOption is opt_dequote: \" stands for a quote.
func unquoteOption(v string) string { return strings.ReplaceAll(v, `\"`, `"`) }

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
