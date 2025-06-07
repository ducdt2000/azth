package strategy

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
)

// PasswordHashStrategyFactory creates password hash strategies
type PasswordHashStrategyFactory struct{}

// NewPasswordHashStrategyFactory creates a new password hash strategy factory
func NewPasswordHashStrategyFactory() *PasswordHashStrategyFactory {
	return &PasswordHashStrategyFactory{}
}

// CreateStrategy creates a password hash strategy for the given type
func (f *PasswordHashStrategyFactory) CreateStrategy(hashType PasswordHashType) (PasswordHashStrategy, error) {
	switch hashType {
	case PasswordHashTypeArgon2ID:
		return NewArgon2IDStrategy(), nil
	case PasswordHashTypeBcrypt:
		return NewBcryptStrategy(), nil
	case PasswordHashTypeSCrypt:
		return NewSCryptStrategy(), nil
	case PasswordHashTypePBKDF2:
		return NewPBKDF2Strategy(), nil
	default:
		return nil, fmt.Errorf("unsupported password hash type: %s", hashType)
	}
}

// Argon2IDStrategy implements Argon2ID password hashing
type Argon2IDStrategy struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	saltLength  uint32
	keyLength   uint32
}

// NewArgon2IDStrategy creates a new Argon2ID strategy with secure defaults
func NewArgon2IDStrategy() *Argon2IDStrategy {
	return &Argon2IDStrategy{
		memory:      19456, // 19 MiB (minimum recommended configuration)
		iterations:  2,     // 2 iterations
		parallelism: 1,     // 1 degree of parallelism
		saltLength:  16,
		keyLength:   32,
	}
}

// Hash hashes a password using Argon2ID with the provided salt
func (s *Argon2IDStrategy) Hash(password string, salt []byte) (string, error) {
	if len(salt) != int(s.saltLength) {
		return "", fmt.Errorf("invalid salt length: expected %d, got %d", s.saltLength, len(salt))
	}

	hash := argon2.IDKey([]byte(password), salt, s.iterations, s.memory, s.parallelism, s.keyLength)

	// Encode salt and hash to base64
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	// Format: $argon2id$v=19$m=memory,t=iterations,p=parallelism$salt$hash
	encodedHash := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, s.memory, s.iterations, s.parallelism, b64Salt, b64Hash)

	return encodedHash, nil
}

// Verify verifies a password against an Argon2ID hash
func (s *Argon2IDStrategy) Verify(password, hash string) bool {
	// Parse the encoded hash
	parts := strings.Split(hash, "$")
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

	expectedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}

	// Generate hash from the provided password
	actualHash := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, uint32(len(expectedHash)))

	// Compare hashes using constant-time comparison
	return subtle.ConstantTimeCompare(expectedHash, actualHash) == 1
}

// GenerateSalt generates a new random salt
func (s *Argon2IDStrategy) GenerateSalt() ([]byte, error) {
	salt := make([]byte, s.saltLength)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}
	return salt, nil
}

// GetAlgorithmName returns the algorithm name
func (s *Argon2IDStrategy) GetAlgorithmName() string {
	return "argon2id"
}

// BcryptStrategy implements bcrypt password hashing
type BcryptStrategy struct {
	cost int
}

// NewBcryptStrategy creates a new bcrypt strategy
func NewBcryptStrategy() *BcryptStrategy {
	return &BcryptStrategy{
		cost: 12, // Secure default
	}
}

// Hash hashes a password using bcrypt (salt is handled internally by bcrypt)
func (s *BcryptStrategy) Hash(password string, salt []byte) (string, error) {
	// bcrypt handles salt internally, so we ignore the provided salt
	hash, err := bcrypt.GenerateFromPassword([]byte(password), s.cost)
	if err != nil {
		return "", fmt.Errorf("failed to hash password with bcrypt: %w", err)
	}
	return string(hash), nil
}

// Verify verifies a password against a bcrypt hash
func (s *BcryptStrategy) Verify(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// GenerateSalt generates a salt (not needed for bcrypt, but required by interface)
func (s *BcryptStrategy) GenerateSalt() ([]byte, error) {
	// bcrypt handles salt internally, return empty slice
	return []byte{}, nil
}

// GetAlgorithmName returns the algorithm name
func (s *BcryptStrategy) GetAlgorithmName() string {
	return "bcrypt"
}

// SCryptStrategy implements scrypt password hashing
type SCryptStrategy struct {
	n         int // CPU/memory cost parameter
	r         int // Block size parameter
	p         int // Parallelization parameter
	keyLength int // Length of derived key
}

// NewSCryptStrategy creates a new scrypt strategy
func NewSCryptStrategy() *SCryptStrategy {
	return &SCryptStrategy{
		n:         32768, // 2^15
		r:         8,
		p:         1,
		keyLength: 32,
	}
}

// Hash hashes a password using scrypt with the provided salt
func (s *SCryptStrategy) Hash(password string, salt []byte) (string, error) {
	if len(salt) < 16 {
		return "", fmt.Errorf("salt must be at least 16 bytes")
	}

	hash, err := scrypt.Key([]byte(password), salt, s.n, s.r, s.p, s.keyLength)
	if err != nil {
		return "", fmt.Errorf("failed to hash password with scrypt: %w", err)
	}

	// Encode salt and hash
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	// Format: $scrypt$n=32768,r=8,p=1$salt$hash
	encodedHash := fmt.Sprintf("$scrypt$n=%d,r=%d,p=%d$%s$%s", s.n, s.r, s.p, b64Salt, b64Hash)
	return encodedHash, nil
}

// Verify verifies a password against a scrypt hash
func (s *SCryptStrategy) Verify(password, hash string) bool {
	parts := strings.Split(hash, "$")
	if len(parts) != 5 {
		return false
	}

	var n, r, p int
	if _, err := fmt.Sscanf(parts[2], "n=%d,r=%d,p=%d", &n, &r, &p); err != nil {
		return false
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return false
	}

	expectedHash, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}

	actualHash, err := scrypt.Key([]byte(password), salt, n, r, p, len(expectedHash))
	if err != nil {
		return false
	}

	return subtle.ConstantTimeCompare(expectedHash, actualHash) == 1
}

// GenerateSalt generates a new random salt
func (s *SCryptStrategy) GenerateSalt() ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}
	return salt, nil
}

// GetAlgorithmName returns the algorithm name
func (s *SCryptStrategy) GetAlgorithmName() string {
	return "scrypt"
}

// PBKDF2Strategy implements PBKDF2 password hashing
type PBKDF2Strategy struct {
	iterations int
	keyLength  int
}

// NewPBKDF2Strategy creates a new PBKDF2 strategy
func NewPBKDF2Strategy() *PBKDF2Strategy {
	return &PBKDF2Strategy{
		iterations: 100000, // OWASP recommended minimum
		keyLength:  32,
	}
}

// Hash hashes a password using PBKDF2 with the provided salt
func (s *PBKDF2Strategy) Hash(password string, salt []byte) (string, error) {
	if len(salt) < 16 {
		return "", fmt.Errorf("salt must be at least 16 bytes")
	}

	hash := pbkdf2.Key([]byte(password), salt, s.iterations, s.keyLength, sha256.New)

	// Encode salt and hash
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	// Format: $pbkdf2$i=100000$salt$hash
	encodedHash := fmt.Sprintf("$pbkdf2$i=%d$%s$%s", s.iterations, b64Salt, b64Hash)
	return encodedHash, nil
}

// Verify verifies a password against a PBKDF2 hash
func (s *PBKDF2Strategy) Verify(password, hash string) bool {
	parts := strings.Split(hash, "$")
	if len(parts) != 5 {
		return false
	}

	var iterations int
	if _, err := fmt.Sscanf(parts[2], "i=%d", &iterations); err != nil {
		return false
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return false
	}

	expectedHash, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}

	actualHash := pbkdf2.Key([]byte(password), salt, iterations, len(expectedHash), sha256.New)

	return subtle.ConstantTimeCompare(expectedHash, actualHash) == 1
}

// GenerateSalt generates a new random salt
func (s *PBKDF2Strategy) GenerateSalt() ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}
	return salt, nil
}

// GetAlgorithmName returns the algorithm name
func (s *PBKDF2Strategy) GetAlgorithmName() string {
	return "pbkdf2"
}
