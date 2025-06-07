package strategy

import (
	"context"
	"time"

	"github.com/ducdt2000/azth/backend/internal/domain"
	"github.com/ducdt2000/azth/backend/internal/modules/auth/dto"
	"github.com/google/uuid"
)

// AuthStrategy defines the interface for different authentication strategies
type AuthStrategy interface {
	// Authenticate performs authentication and returns tokens
	Authenticate(ctx context.Context, req *dto.LoginRequest, user *domain.User) (*dto.LoginResponse, error)

	// ValidateToken validates an authentication token
	ValidateToken(ctx context.Context, token string) (*AuthContext, error)

	// RefreshToken refreshes an authentication token
	RefreshToken(ctx context.Context, refreshToken string) (*dto.RefreshResponse, error)

	// RevokeToken revokes an authentication token
	RevokeToken(ctx context.Context, token string) error

	// RevokeAllTokens revokes all tokens for a user
	RevokeAllTokens(ctx context.Context, userID uuid.UUID) error

	// GetStrategyType returns the strategy type
	GetStrategyType() StrategyType
}

// StrategyType represents different authentication strategy types
type StrategyType string

const (
	StrategyTypeSession StrategyType = "session"
	StrategyTypeJWT     StrategyType = "jwt"
	StrategyTypeOAuth   StrategyType = "oauth" // Future implementation
	StrategyTypeSAML    StrategyType = "saml"  // Future implementation
)

// AuthContext holds authentication context information
type AuthContext struct {
	UserID      uuid.UUID  `json:"user_id"`
	TenantID    uuid.UUID  `json:"tenant_id"`
	Email       string     `json:"email"`
	Username    string     `json:"username"`
	Roles       []string   `json:"roles"`
	Permissions []string   `json:"permissions"`
	IPAddress   string     `json:"ip_address"`
	UserAgent   string     `json:"user_agent"`
	ExpiresAt   time.Time  `json:"expires_at"`
	TokenType   string     `json:"token_type"`
	SessionID   *uuid.UUID `json:"session_id,omitempty"` // Only for session strategy
}

// PasswordHashStrategy defines interface for password hashing strategies
type PasswordHashStrategy interface {
	// Hash hashes a password with salt
	Hash(password string, salt []byte) (string, error)

	// Verify verifies a password against a hash
	Verify(password, hash string) bool

	// GenerateSalt generates a new salt
	GenerateSalt() ([]byte, error)

	// GetAlgorithmName returns the algorithm name
	GetAlgorithmName() string
}

// PasswordHashType represents different password hashing algorithms
type PasswordHashType string

const (
	PasswordHashTypeArgon2ID PasswordHashType = "argon2id"
	PasswordHashTypeBcrypt   PasswordHashType = "bcrypt"
	PasswordHashTypeSCrypt   PasswordHashType = "scrypt"
	PasswordHashTypePBKDF2   PasswordHashType = "pbkdf2"
)

// LoginIdentifierType represents different login identifier types
type LoginIdentifierType string

const (
	LoginIdentifierEmail    LoginIdentifierType = "email"
	LoginIdentifierUsername LoginIdentifierType = "username"
	LoginIdentifierPhone    LoginIdentifierType = "phone"
)

// AuthStrategyConfig holds configuration for authentication strategies
type AuthStrategyConfig struct {
	// Primary strategy type
	PrimaryStrategy StrategyType `json:"primary_strategy" yaml:"primary_strategy"`

	// Fallback strategies
	FallbackStrategies []StrategyType `json:"fallback_strategies" yaml:"fallback_strategies"`

	// Password hashing configuration
	PasswordHashType PasswordHashType `json:"password_hash_type" yaml:"password_hash_type"`

	// Login identifier configuration
	AllowedLoginIdentifiers []LoginIdentifierType `json:"allowed_login_identifiers" yaml:"allowed_login_identifiers"`
	DefaultLoginIdentifier  LoginIdentifierType   `json:"default_login_identifier" yaml:"default_login_identifier"`

	// Tenant-specific overrides
	TenantOverrides map[string]*TenantAuthConfig `json:"tenant_overrides" yaml:"tenant_overrides"`
}

// TenantAuthConfig holds tenant-specific authentication configuration
type TenantAuthConfig struct {
	Strategy                StrategyType          `json:"strategy" yaml:"strategy"`
	PasswordHashType        PasswordHashType      `json:"password_hash_type" yaml:"password_hash_type"`
	AllowedLoginIdentifiers []LoginIdentifierType `json:"allowed_login_identifiers" yaml:"allowed_login_identifiers"`
	DefaultLoginIdentifier  LoginIdentifierType   `json:"default_login_identifier" yaml:"default_login_identifier"`
	RequireMFA              bool                  `json:"require_mfa" yaml:"require_mfa"`
	SessionTTL              *time.Duration        `json:"session_ttl" yaml:"session_ttl"`
	JWTAccessTokenTTL       *time.Duration        `json:"jwt_access_token_ttl" yaml:"jwt_access_token_ttl"`
}

// AuthStrategyFactory creates authentication strategies
type AuthStrategyFactory struct {
	strategies map[StrategyType]AuthStrategy
	config     *AuthStrategyConfig
}

// NewAuthStrategyFactory creates a new authentication strategy factory
func NewAuthStrategyFactory(config *AuthStrategyConfig) *AuthStrategyFactory {
	return &AuthStrategyFactory{
		strategies: make(map[StrategyType]AuthStrategy),
		config:     config,
	}
}

// RegisterStrategy registers an authentication strategy
func (f *AuthStrategyFactory) RegisterStrategy(strategyType StrategyType, strategy AuthStrategy) {
	f.strategies[strategyType] = strategy
}

// GetStrategy returns the appropriate authentication strategy
func (f *AuthStrategyFactory) GetStrategy(tenantID *uuid.UUID) AuthStrategy {
	// Check for tenant-specific override
	if tenantID != nil && f.config.TenantOverrides != nil {
		if tenantConfig, exists := f.config.TenantOverrides[tenantID.String()]; exists {
			if strategy, found := f.strategies[tenantConfig.Strategy]; found {
				return strategy
			}
		}
	}

	// Return primary strategy
	if strategy, found := f.strategies[f.config.PrimaryStrategy]; found {
		return strategy
	}

	// Fallback to first available strategy
	for _, strategyType := range f.config.FallbackStrategies {
		if strategy, found := f.strategies[strategyType]; found {
			return strategy
		}
	}

	return nil
}

// GetPasswordHashStrategy returns the appropriate password hash strategy for a tenant
func (f *AuthStrategyFactory) GetPasswordHashStrategy(tenantID *uuid.UUID) PasswordHashType {
	// Check for tenant-specific override
	if tenantID != nil && f.config.TenantOverrides != nil {
		if tenantConfig, exists := f.config.TenantOverrides[tenantID.String()]; exists {
			return tenantConfig.PasswordHashType
		}
	}

	return f.config.PasswordHashType
}

// GetAllowedLoginIdentifiers returns allowed login identifiers for a tenant
func (f *AuthStrategyFactory) GetAllowedLoginIdentifiers(tenantID *uuid.UUID) []LoginIdentifierType {
	// Check for tenant-specific override
	if tenantID != nil && f.config.TenantOverrides != nil {
		if tenantConfig, exists := f.config.TenantOverrides[tenantID.String()]; exists {
			if len(tenantConfig.AllowedLoginIdentifiers) > 0 {
				return tenantConfig.AllowedLoginIdentifiers
			}
		}
	}

	return f.config.AllowedLoginIdentifiers
}

// GetDefaultLoginIdentifier returns the default login identifier for a tenant
func (f *AuthStrategyFactory) GetDefaultLoginIdentifier(tenantID *uuid.UUID) LoginIdentifierType {
	// Check for tenant-specific override
	if tenantID != nil && f.config.TenantOverrides != nil {
		if tenantConfig, exists := f.config.TenantOverrides[tenantID.String()]; exists {
			if tenantConfig.DefaultLoginIdentifier != "" {
				return tenantConfig.DefaultLoginIdentifier
			}
		}
	}

	return f.config.DefaultLoginIdentifier
}

// DefaultAuthStrategyConfig returns default authentication strategy configuration
func DefaultAuthStrategyConfig() *AuthStrategyConfig {
	return &AuthStrategyConfig{
		PrimaryStrategy:    StrategyTypeSession,
		FallbackStrategies: []StrategyType{StrategyTypeJWT},
		PasswordHashType:   PasswordHashTypeArgon2ID,
		AllowedLoginIdentifiers: []LoginIdentifierType{
			LoginIdentifierEmail,
			LoginIdentifierUsername,
		},
		DefaultLoginIdentifier: LoginIdentifierEmail,
		TenantOverrides:        make(map[string]*TenantAuthConfig),
	}
}
