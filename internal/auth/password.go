// Package auth handles password hashing, session management, and WebAuthn
// enrollment/verification.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2 parameters. Balanced for a small-team CA tool where login latency
// under ~100ms on modest hardware is acceptable. Values are documented in
// the encoded hash so a future bump is safe.
const (
	argonTime    uint32 = 2
	argonMemory  uint32 = 64 * 1024 // 64 MiB
	argonThreads uint8  = 4
	argonKeyLen  uint32 = 32
	saltLen             = 16
)

var ErrPasswordMismatch = errors.New("auth: password mismatch")

// HashPassword returns an argon2id encoded string:
//   $argon2id$v=19$m=65536,t=2,p=4$<salt>$<hash>
func HashPassword(password string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hash := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	), nil
}

// VerifyPassword compares a plaintext password against an argon2id encoded hash.
// Returns nil on match, ErrPasswordMismatch on mismatch, or another error if the
// encoded hash is malformed.
func VerifyPassword(encoded, password string) error {
	params, salt, hash, err := decodeArgon(encoded)
	if err != nil {
		return err
	}
	got := argon2.IDKey([]byte(password), salt, params.time, params.memory, params.threads, uint32(len(hash)))
	if subtle.ConstantTimeCompare(got, hash) == 1 {
		return nil
	}
	return ErrPasswordMismatch
}

type argonParams struct {
	memory  uint32
	time    uint32
	threads uint8
}

func decodeArgon(encoded string) (argonParams, []byte, []byte, error) {
	// $argon2id$v=19$m=65536,t=2,p=4$salt$hash
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return argonParams{}, nil, nil, errors.New("auth: bad hash format")
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return argonParams{}, nil, nil, fmt.Errorf("auth: bad version: %w", err)
	}
	if version != argon2.Version {
		return argonParams{}, nil, nil, errors.New("auth: unsupported argon2 version")
	}
	var p argonParams
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.memory, &p.time, &p.threads); err != nil {
		return argonParams{}, nil, nil, fmt.Errorf("auth: bad params: %w", err)
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return argonParams{}, nil, nil, fmt.Errorf("auth: bad salt: %w", err)
	}
	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return argonParams{}, nil, nil, fmt.Errorf("auth: bad hash: %w", err)
	}
	return p, salt, hash, nil
}
