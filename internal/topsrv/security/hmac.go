package security

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
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

// loadOrCreateKey reads <stateDir>/security.key, creating it on first use or
// when the path holds no usable key (missing, not a regular file, wrong
// size). Any other read error is returned: a key that is there but
// unreadable right now must not be replaced.
func loadOrCreateKey(stateDir string) (tokenKey, error) {
	b, err := readFileNoFollow(filepath.Join(stateDir, keyFile), keySize)
	switch {
	case err == nil && len(b) == keySize:
		return tokenKey{secret: b, id: keyID(b)}, nil
	case err != nil && !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, errNotRegular) && !errors.Is(err, errTooLarge):
		return tokenKey{}, err
	}
	k := randomKey()
	// An exclusive 0600 temp file and a rename, which replaces whatever is at
	// the path (a symlink included) without writing through it.
	if err := (spool.Dir{Path: stateDir}).Write(keyFile, k.secret); err != nil {
		return tokenKey{}, err
	}
	return k, nil
}

// randomKey is a new key with its real id: when it cannot be stored, a key
// per agent start still tells the backend that tokens are not comparable.
func randomKey() tokenKey {
	secret := make([]byte, keySize)
	rand.Read(secret) // never fails since Go 1.24
	return tokenKey{secret: secret, id: keyID(secret)}
}

// existingOrEphemeralKey is for dry-run, which must not write: the existing
// key, or a random one with id "ephemeral".
func existingOrEphemeralKey(stateDir string) tokenKey {
	if b, err := readFileNoFollow(filepath.Join(stateDir, keyFile), keySize); err == nil && len(b) == keySize {
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
