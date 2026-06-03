package sasl

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"hash"

	"golang.org/x/crypto/pbkdf2"
)

// DefaultScramIterations is the PBKDF2 iteration count used by
// GenerateScramCredentials when the caller does not pass an
// override. 600000 follows the 2023 OWASP recommendation for
// SHA-256-based PBKDF2; raise as compute budgets grow. RFC 5802's
// 4096 default is far too low for modern hardware.
const DefaultScramIterations = 600_000

// MinScramIterations refuses absurdly weak parameters at
// generation time. Operators that need lower can pass an explicit
// override, but the default tooling clamps this floor.
const MinScramIterations = 4096

// DeriveScramSha256Credentials runs PBKDF2-HMAC-SHA-256 against
// the supplied password + salt + iterations and returns the
// matching ScramCredentials. Salt is preserved verbatim — useful
// for re-derivation paths where the salt comes from a stored
// verifier (PLAIN-against-{SCRAM-SHA-256} compare).
//
// For new-user provisioning use GenerateScramSha256Credentials,
// which generates a fresh random salt.
func DeriveScramSha256Credentials(password string, salt []byte, iterations int) *ScramCredentials {
	return deriveScramCredentials(sha256.New, sha256.Size, password, salt, iterations)
}

// GenerateScramSha256Credentials derives a {SCRAM-SHA-256} verifier
// from a plain password. Salt is freshly generated (16 random
// bytes). The returned ScramCredentials is suitable for storage
// under the {SCRAM-SHA-256} scheme.
//
// iterations <= 0 substitutes DefaultScramIterations; any value
// below MinScramIterations is clamped up so a misconfigured
// caller never lands weak verifiers in the database.
func GenerateScramSha256Credentials(password string, iterations int) (*ScramCredentials, error) {
	if password == "" {
		return nil, errors.New("sasl/scram: empty password")
	}
	if iterations <= 0 {
		iterations = DefaultScramIterations
	}
	if iterations < MinScramIterations {
		iterations = MinScramIterations
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	return deriveScramCredentials(sha256.New, sha256.Size, password, salt, iterations), nil
}

// deriveScramCredentials runs the full SCRAM key derivation given
// a fixed salt + iteration count. Extracted so tests can pin the
// salt and reproduce known vectors.
func deriveScramCredentials(newHash func() hash.Hash, hashSize int, password string, salt []byte, iterations int) *ScramCredentials {
	salted := pbkdf2.Key([]byte(password), salt, iterations, hashSize, newHash)

	clientKey := hmacSum(newHash, salted, []byte("Client Key"))
	storedKey := hashSum(newHash, clientKey)
	serverKey := hmacSum(newHash, salted, []byte("Server Key"))
	return &ScramCredentials{
		Iterations: iterations,
		Salt:       salt,
		StoredKey:  storedKey,
		ServerKey:  serverKey,
	}
}

func hashSum(newHash func() hash.Hash, data []byte) []byte {
	h := newHash()
	h.Write(data)
	return h.Sum(nil)
}
