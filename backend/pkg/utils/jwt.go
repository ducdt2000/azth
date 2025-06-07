package utils

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// JWTConfig holds JWT configuration
type JWTConfig struct {
	Secret           string
	Issuer           string
	Audience         string
	AccessTokenTTL   time.Duration
	RefreshTokenTTL  time.Duration
	Algorithms       []string
	ValidateIssuer   bool
	ValidateIAT      bool
	SigningAlgorithm string
}

// JWTClaims represents JWT token claims
type JWTClaims struct {
	UserID      uuid.UUID `json:"user_id"`
	TenantID    uuid.UUID `json:"tenant_id"`
	Email       string    `json:"email"`
	Username    string    `json:"username"`
	Roles       []string  `json:"roles"`
	Permissions []string  `json:"permissions"`
	TokenType   string    `json:"token_type"` // "access" or "refresh"
	IPAddress   string    `json:"ip_address,omitempty"`
	UserAgent   string    `json:"user_agent,omitempty"`
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
	// Build validation options
	opts := []jwt.ParserOption{
		jwt.WithAudience(config.Audience),
		jwt.WithTimeFunc(time.Now),
	}

	if config.ValidateIssuer {
		opts = append(opts, jwt.WithIssuer(config.Issuer))
	}

	if config.ValidateIAT {
		opts = append(opts, jwt.WithIssuedAt())
	}

	if len(config.Algorithms) > 0 {
		opts = append(opts, jwt.WithValidMethods(config.Algorithms))
	}

	// Parse the token
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Check signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(config.Secret), nil
	}, opts...)

	if err != nil {
		return nil, fmt.Errorf("failed to parse or validate JWT token: %w", err)
	}

	// Extract claims
	claims, ok := token.Claims.(*JWTClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token or claims")
	}

	return claims, nil
}

// GenerateAccessToken generates an access token
func GenerateAccessToken(config *JWTConfig, userID, tenantID uuid.UUID, email, username string, roles, permissions []string, ipAddress, userAgent string) (string, error) {
	claims := &JWTClaims{
		UserID:      userID,
		TenantID:    tenantID,
		Email:       email,
		Username:    username,
		Roles:       roles,
		Permissions: permissions,
		TokenType:   TokenTypeAccess,
		IPAddress:   ipAddress,
		UserAgent:   userAgent,
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

// ExtractJTIFromJWT extracts the JTI (JWT ID) from a JWT token
func ExtractJTIFromJWT(tokenString string) (string, error) {
	// Parse the token without validation to extract the JTI
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return "", fmt.Errorf("failed to parse JWT: %w", err)
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		if jti, exists := claims["jti"]; exists {
			if jtiStr, ok := jti.(string); ok {
				return jtiStr, nil
			}
		}
	}

	return "", fmt.Errorf("JTI not found in JWT token")
}
