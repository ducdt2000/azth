package utils

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

// PasswordHashAlgorithm represents the password hashing algorithm
type PasswordHashAlgorithm string

const (
	PasswordHashArgon2ID PasswordHashAlgorithm = "argon2id" // Default, more secure
	PasswordHashBcrypt   PasswordHashAlgorithm = "bcrypt"   // Legacy support
)

// Argon2IDConfig holds Argon2ID configuration parameters
type Argon2IDConfig struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

// DefaultArgon2IDConfig returns default Argon2ID configuration
func DefaultArgon2IDConfig() *Argon2IDConfig {
	return &Argon2IDConfig{
		Memory:      7168, // 7 MiB (proper default)
		Iterations:  5,    // 5 iterations (proper default)
		Parallelism: 1,    // 1 degree of parallelism
		SaltLength:  16,
		KeyLength:   32,
	}
}

// HashPassword hashes a password using the specified algorithm
func HashPassword(password string, algorithm PasswordHashAlgorithm, config ...interface{}) (string, error) {
	switch algorithm {
	case PasswordHashArgon2ID:
		var argonConfig *Argon2IDConfig
		if len(config) > 0 {
			if cfg, ok := config[0].(*Argon2IDConfig); ok {
				argonConfig = cfg
			}
		}
		if argonConfig == nil {
			argonConfig = DefaultArgon2IDConfig()
		}
		return hashPasswordArgon2ID(password, argonConfig)
	case PasswordHashBcrypt:
		cost := 12 // Default cost
		if len(config) > 0 {
			if c, ok := config[0].(int); ok {
				cost = c
			}
		}
		return hashPasswordBcrypt(password, cost)
	default:
		return "", fmt.Errorf("unsupported password hashing algorithm: %s", algorithm)
	}
}

// VerifyPassword verifies a password against a hash
func VerifyPassword(password, hash string) bool {
	// Determine algorithm from hash format
	if strings.HasPrefix(hash, "$argon2id$") {
		return verifyPasswordArgon2ID(password, hash)
	} else if strings.HasPrefix(hash, "$2a$") || strings.HasPrefix(hash, "$2b$") || strings.HasPrefix(hash, "$2y$") {
		return verifyPasswordBcrypt(password, hash)
	}
	// Try bcrypt by default for legacy hashes
	return verifyPasswordBcrypt(password, hash)
}

// hashPasswordArgon2ID hashes a password using Argon2ID
func hashPasswordArgon2ID(password string, config *Argon2IDConfig) (string, error) {
	// Generate a random salt
	salt := make([]byte, config.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}

	// Generate the hash
	hash := argon2.IDKey([]byte(password), salt, config.Iterations, config.Memory, config.Parallelism, config.KeyLength)

	// Encode the salt and hash to base64
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	// Return the encoded hash in the format: $argon2id$v=19$m=memory,t=iterations,p=parallelism$salt$hash
	encodedHash := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, config.Memory, config.Iterations, config.Parallelism, b64Salt, b64Hash)

	return encodedHash, nil
}

// verifyPasswordArgon2ID verifies a password against an Argon2ID hash
func verifyPasswordArgon2ID(password, encodedHash string) bool {
	// Parse the encoded hash
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 {
		return false
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return false
	}

	if version != argon2.Version {
		return false
	}

	var memory, iterations uint32
	var parallelism uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &parallelism); err != nil {
		return false
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}

	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}

	// Generate hash from the provided password
	otherHash := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, uint32(len(hash)))

	// Compare hashes using constant-time comparison
	return subtle.ConstantTimeCompare(hash, otherHash) == 1
}

// hashPasswordBcrypt hashes a password using bcrypt
func hashPasswordBcrypt(password string, cost int) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		return "", fmt.Errorf("failed to hash password with bcrypt: %w", err)
	}
	return string(bytes), nil
}

// verifyPasswordBcrypt verifies a password against a bcrypt hash
func verifyPasswordBcrypt(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// GetPasswordHashAlgorithm determines the algorithm used for a hash
func GetPasswordHashAlgorithm(hash string) PasswordHashAlgorithm {
	if strings.HasPrefix(hash, "$argon2id$") {
		return PasswordHashArgon2ID
	}
	return PasswordHashBcrypt
}
