package utils

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// JWTConfig holds JWT configuration
type JWTConfig struct {
	Secret          string
	Issuer          string
	Audience        string
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
}

// JWTClaims represents JWT token claims
type JWTClaims struct {
	UserID    uuid.UUID `json:"user_id"`
	TenantID  uuid.UUID `json:"tenant_id"`
	Email     string    `json:"email"`
	Username  string    `json:"username"`
	TokenType string    `json:"token_type"` // "access" or "refresh"
	IPAddress string    `json:"ip_address,omitempty"`
	UserAgent string    `json:"user_agent,omitempty"`
	jwt.RegisteredClaims
}

// TokenType constants
const (
	TokenTypeAccess  = "access"
	TokenTypeRefresh = "refresh"
)

// GenerateJWT generates a JWT token with the specified claims
func GenerateJWT(config *JWTConfig, claims *JWTClaims) (string, error) {
	// Set standard claims
	now := time.Now()
	var expiresAt time.Time

	if claims.TokenType == TokenTypeAccess {
		expiresAt = now.Add(config.AccessTokenTTL)
	} else {
		expiresAt = now.Add(config.RefreshTokenTTL)
	}

	claims.RegisteredClaims = jwt.RegisteredClaims{
		ID:        uuid.New().String(),
		Issuer:    config.Issuer,
		Audience:  jwt.ClaimStrings{config.Audience},
		Subject:   claims.UserID.String(),
		IssuedAt:  jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(expiresAt),
	}

	// Create the token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign the token
	tokenString, err := token.SignedString([]byte(config.Secret))
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT token: %w", err)
	}

	return tokenString, nil
}

// ValidateJWT validates a JWT token and returns the claims
func ValidateJWT(config *JWTConfig, tokenString string) (*JWTClaims, error) {
	// Parse the token
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate the signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(config.Secret), nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT token: %w", err)
	}

	// Extract claims
	claims, ok := token.Claims.(*JWTClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}

	// Validate token
	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	// Additional validation
	if claims.Issuer != config.Issuer {
		return nil, fmt.Errorf("invalid token issuer")
	}

	// Check if token has expired
	if time.Now().After(claims.ExpiresAt.Time) {
		return nil, fmt.Errorf("token has expired")
	}

	return claims, nil
}

// GenerateAccessToken generates an access token
func GenerateAccessToken(config *JWTConfig, userID, tenantID uuid.UUID, email, username, ipAddress, userAgent string) (string, error) {
	claims := &JWTClaims{
		UserID:    userID,
		TenantID:  tenantID,
		Email:     email,
		Username:  username,
		TokenType: TokenTypeAccess,
		IPAddress: ipAddress,
		UserAgent: userAgent,
	}

	return GenerateJWT(config, claims)
}

// GenerateRefreshToken generates a refresh token
func GenerateRefreshToken(config *JWTConfig, userID, tenantID uuid.UUID, email, username, ipAddress, userAgent string) (string, error) {
	claims := &JWTClaims{
		UserID:    userID,
		TenantID:  tenantID,
		Email:     email,
		Username:  username,
		TokenType: TokenTypeRefresh,
		IPAddress: ipAddress,
		UserAgent: userAgent,
	}

	return GenerateJWT(config, claims)
}

// ExtractTokenFromBearer extracts the token from Bearer authorization header
func ExtractTokenFromBearer(authHeader string) string {
	const bearerPrefix = "Bearer "
	if len(authHeader) > len(bearerPrefix) && authHeader[:len(bearerPrefix)] == bearerPrefix {
		return authHeader[len(bearerPrefix):]
	}
	return ""
}

// ExtractJTIFromJWT extracts the JTI (JWT ID) from a JWT token without full validation
func ExtractJTIFromJWT(tokenString string) (string, error) {
	// Parse token without verification to extract JTI
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, &JWTClaims{})
	if err != nil {
		return "", fmt.Errorf("failed to parse JWT token: %w", err)
	}

	claims, ok := token.Claims.(*JWTClaims)
	if !ok {
		return "", fmt.Errorf("invalid token claims")
	}

	if claims.ID == "" {
		return "", fmt.Errorf("JWT token missing JTI claim")
	}

	return claims.ID, nil
}
