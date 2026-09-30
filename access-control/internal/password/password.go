// Package password hashes passwords with Argon2id; it never encrypts or stores plaintext.
package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	memory      = 64 * 1024 // KiB: 64 MiB per hash.
	iterations  = 3
	parallelism = 1
	saltLength  = 16
	keyLength   = 32
	MaxLength   = 1024 // bytes, before invoking the KDF
)

var ErrInvalidHash = errors.New("некорректный формат хеша пароля")

// Hash returns a PHC string containing algorithm, version, parameters, salt and hash.
func Hash(plain string) (string, error) {
	if plain == "" || len(plain) > MaxLength {
		return "", errors.New("недопустимая длина пароля")
	}
	salt := make([]byte, saltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(plain), salt, iterations, memory, parallelism, keyLength)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, memory, iterations, parallelism, base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

// Verify rejects malformed or excessive work factors before allocating Argon2 memory.
// An empty hash is the explicit first-login state required by the assignment.
func Verify(encoded, plain string) (bool, error) {
	if len(plain) > MaxLength {
		return false, nil
	}
	if encoded == "" {
		return plain == "", nil
	}
	if len(encoded) > 256 {
		return false, ErrInvalidHash
	}
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v=19" {
		return false, ErrInvalidHash
	}
	params := strings.Split(parts[3], ",")
	if len(params) != 3 {
		return false, ErrInvalidHash
	}
	values := make([]uint32, 3)
	for i, prefix := range []string{"m=", "t=", "p="} {
		if !strings.HasPrefix(params[i], prefix) {
			return false, ErrInvalidHash
		}
		n, err := strconv.ParseUint(strings.TrimPrefix(params[i], prefix), 10, 32)
		if err != nil {
			return false, ErrInvalidHash
		}
		values[i] = uint32(n)
	}
	m, t, p := values[0], values[1], values[2]
	if m < 19*1024 || m > memory || t < 2 || t > iterations || p != parallelism {
		return false, ErrInvalidHash
	}
	salt, err := base64.RawStdEncoding.Strict().DecodeString(parts[4])
	if err != nil || len(salt) != saltLength {
		return false, ErrInvalidHash
	}
	expected, err := base64.RawStdEncoding.Strict().DecodeString(parts[5])
	if err != nil || len(expected) != keyLength {
		return false, ErrInvalidHash
	}
	actual := argon2.IDKey([]byte(plain), salt, t, m, uint8(p), keyLength)
	return subtle.ConstantTimeCompare(actual, expected) == 1, nil
}
