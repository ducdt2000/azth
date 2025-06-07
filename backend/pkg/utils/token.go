package utils

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
)

// GenerateSecureToken generates a cryptographically secure random token
// length specifies the number of random bytes to generate
func GenerateSecureToken(length int) (string, error) {
	if length <= 0 {
		return "", fmt.Errorf("token length must be positive")
	}

	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate secure token: %w", err)
	}

	// Return as hex string for better compatibility
	return hex.EncodeToString(bytes), nil
}

// GenerateSecureTokenBase64 generates a secure token encoded as base64
func GenerateSecureTokenBase64(length int) (string, error) {
	if length <= 0 {
		return "", fmt.Errorf("token length must be positive")
	}

	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate secure token: %w", err)
	}

	return base64.URLEncoding.EncodeToString(bytes), nil
}

// GenerateSecureTokenBase64URL generates a secure token encoded as base64 URL-safe
func GenerateSecureTokenBase64URL(length int) (string, error) {
	if length <= 0 {
		return "", fmt.Errorf("token length must be positive")
	}

	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate secure token: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

// GenerateAlphanumericToken generates a secure alphanumeric token
func GenerateAlphanumericToken(length int) (string, error) {
	if length <= 0 {
		return "", fmt.Errorf("token length must be positive")
	}

	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, length)

	for i := 0; i < length; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", fmt.Errorf("failed to generate alphanumeric token: %w", err)
		}
		result[i] = charset[num.Int64()]
	}

	return string(result), nil
}

// GenerateSessionToken generates a session token (hex-encoded)
func GenerateSessionToken() (string, error) {
	return GenerateSecureToken(32) // 32 bytes = 64 hex characters
}

// GenerateCSRFToken generates a CSRF token
func GenerateCSRFToken() (string, error) {
	return GenerateSecureTokenBase64URL(32) // 32 bytes
}

// GenerateAPIKey generates an API key
func GenerateAPIKey() (string, error) {
	return GenerateSecureTokenBase64URL(48) // 48 bytes
}
