package security

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"path/filepath"

	"github.com/vmkteam/topsrv/internal/topsrv/spool"
)

const (
	keyFile        = "security.key"
	keySize        = 32
	ephemeralKeyID = "ephemeral"
)

// tokenKey makes tokens that change when a secret changes without revealing
// it: a plain sha256 of a DES hash, with its 12-bit salt, is brute-forced.
// The key never leaves the host; id tells the backend which key made the
// tokens, so a new key is not mistaken for every password changing.
type tokenKey struct {
	secret []byte
	id     string
}

// Why loadOrCreateKey made a new key.
const (
	keyMissing   = "missing"
	keyInvalid   = "invalid"   // not a regular file, or the wrong size
	keyUntrusted = "untrusted" // others could read it, or another user owns it
)

// errUntrustedKey: a key someone else may know lets them check guessed
// secrets against the tokens.
var errUntrustedKey = errors.New("key file is readable by others or owned by another user")

// loadOrCreateKey reads <stateDir>/security.key, creating it on first use or
// when the path holds no usable key; created says why, "" when the key was
// loaded. Any other read error is returned: a key that is there but
// unreadable right now must not be replaced.
func loadOrCreateKey(stateDir string) (k tokenKey, created string, err error) {
	b, err := readKey(filepath.Join(stateDir, keyFile))
	switch {
	case err == nil && len(b) == keySize:
		return tokenKey{secret: b, id: keyID(b)}, "", nil
	case errors.Is(err, fs.ErrNotExist):
		created = keyMissing
	case errors.Is(err, errUntrustedKey):
		created = keyUntrusted
	case err == nil, errors.Is(err, errNotRegular):
		created = keyInvalid
	default:
		return tokenKey{}, "", err
	}
	k = randomKey()
	// An exclusive 0600 temp file and a rename, which replaces whatever is at
	// the path (a symlink included) without writing through it.
	if err := (spool.Dir{Path: stateDir}).Write(keyFile, k.secret); err != nil {
		return tokenKey{}, "", err
	}
	return k, created, nil
}

// readKey reads up to keySize+1 bytes of the key file without following a
// symlink, and refuses a file that is not private to the agent's user.
func readKey(path string) ([]byte, error) {
	f, err := openFile(path, true)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !privateFile(st) {
		return nil, &fs.PathError{Op: opOpen, Path: path, Err: errUntrustedKey}
	}
	return io.ReadAll(io.LimitReader(f, keySize+1))
}

// randomKey is a new key with its real id: when it cannot be stored, a key
// per agent start still tells the backend that tokens are not comparable.
func randomKey() tokenKey {
	secret := make([]byte, keySize)
	rand.Read(secret) // never fails since Go 1.24
	return tokenKey{secret: secret, id: keyID(secret)}
}

// existingOrEphemeralKey is for dry-run, which must not write: the existing
// key, or a random one with id "ephemeral" where the agent would make a new
// one.
func existingOrEphemeralKey(stateDir string) tokenKey {
	if b, err := readKey(filepath.Join(stateDir, keyFile)); err == nil && len(b) == keySize {
		return tokenKey{secret: b, id: keyID(b)}
	}
	k := randomKey()
	k.id = ephemeralKeyID
	return k
}

// keyID is the first 4 bytes of sha256(key) in hex.
func keyID(secret []byte) string {
	sum := sha256.Sum256(secret)
	return hex.EncodeToString(sum[:4])
}

// token is the first 8 bytes of HMAC-SHA256(key, user ‖ field) in hex.
func (k tokenKey) token(user, field string) string {
	m := hmac.New(sha256.New, k.secret)
	m.Write([]byte(user))
	m.Write([]byte{0})
	m.Write([]byte(field))
	return hex.EncodeToString(m.Sum(nil)[:8])
}
