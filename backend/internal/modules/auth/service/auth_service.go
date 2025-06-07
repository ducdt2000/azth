package service

import (
	"context"
	"time"

	"github.com/ducdt2000/azth/backend/internal/domain"
	"github.com/ducdt2000/azth/backend/internal/modules/auth/dto"
	roleSvc "github.com/ducdt2000/azth/backend/internal/modules/role/service"
	userRepo "github.com/ducdt2000/azth/backend/internal/modules/user/repository"
	"github.com/google/uuid"
)

// AuthMode represents the authentication mode
type AuthMode string

const (
	AuthModeStateful  AuthMode = "stateful"  // Session/Cookie based
	AuthModeStateless AuthMode = "stateless" // JWT based
)

// PasswordHashAlgorithm represents the password hashing algorithm
type PasswordHashAlgorithm string

const (
	PasswordHashArgon2ID PasswordHashAlgorithm = "argon2id" // Default, more secure
	PasswordHashBcrypt   PasswordHashAlgorithm = "bcrypt"   // Legacy support
)

// AuthService provides authentication and session management functionality
type AuthService interface {
	// Authentication methods
	Login(ctx context.Context, req *dto.LoginRequest) (*dto.LoginResponse, error)
	Logout(ctx context.Context, token string) error
	LogoutAll(ctx context.Context, userID uuid.UUID) error
	RefreshToken(ctx context.Context, refreshToken string) (*dto.RefreshResponse, error)

	// Session management (for stateful mode)
	CreateSession(ctx context.Context, userID uuid.UUID, req *dto.CreateSessionRequest) (*domain.Session, error)
	GetSession(ctx context.Context, token string) (*domain.Session, error)
	GetUserSessions(ctx context.Context, userID uuid.UUID) ([]*domain.Session, error)
	ValidateSession(ctx context.Context, token string) (*domain.Session, error)
	RevokeSession(ctx context.Context, sessionID uuid.UUID, reason string) error
	CleanupExpiredSessions(ctx context.Context) error

	// JWT methods (for stateless mode)
	GenerateJWT(ctx context.Context, userID uuid.UUID, tenantID uuid.UUID, req *dto.JWTRequest) (*dto.JWTResponse, error)
	ValidateJWT(ctx context.Context, token string) (*dto.JWTClaims, error)
	RefreshJWT(ctx context.Context, refreshToken string) (*dto.JWTResponse, error)
	RevokeJWT(ctx context.Context, token string) error

	// User authentication helpers
	ValidateCredentials(ctx context.Context, email, password string) (*domain.User, error)
	HashPassword(password string, algorithm ...PasswordHashAlgorithm) (string, error)
	VerifyPassword(password, hash string, algorithm ...PasswordHashAlgorithm) bool

	// MFA support
	EnableMFA(ctx context.Context, userID uuid.UUID) (*dto.MFASetupResponse, error)
	DisableMFA(ctx context.Context, userID uuid.UUID) error
	ValidateMFA(ctx context.Context, userID uuid.UUID, code string) (bool, error)
	GenerateBackupCodes(ctx context.Context, userID uuid.UUID) ([]string, error)

	// Account security
	UpdateLastLogin(ctx context.Context, userID uuid.UUID, ipAddress string) error
	RecordFailedLogin(ctx context.Context, email, ipAddress string) error
	IsAccountLocked(ctx context.Context, userID uuid.UUID) (bool, error)
	UnlockAccount(ctx context.Context, userID uuid.UUID) error

	// Password reset
	RequestPasswordReset(ctx context.Context, req *dto.RequestPasswordResetRequest) (*dto.RequestPasswordResetResponse, error)
	ConfirmPasswordReset(ctx context.Context, req *dto.ConfirmPasswordResetRequest) (*dto.ConfirmPasswordResetResponse, error)
	UpdatePassword(ctx context.Context, userID uuid.UUID, req *dto.UpdatePasswordRequest) (*dto.UpdatePasswordResponse, error)

	// Configuration
	GetAuthMode() AuthMode
	IsJWTMode() bool
	IsSessionMode() bool
}

// JWTBlacklistService interface for JWT token blacklisting
type JWTBlacklistService interface {
	// AddToBlacklist adds a JWT token to the blacklist
	AddToBlacklist(ctx context.Context, jti string, expiresAt time.Time) error
	// IsBlacklisted checks if a JWT token is blacklisted
	IsBlacklisted(ctx context.Context, jti string) (bool, error)
	// RemoveExpired removes expired tokens from the blacklist
	RemoveExpired(ctx context.Context) error
	// AddUserToBlacklist adds all tokens for a user to blacklist (for logout all)
	AddUserToBlacklist(ctx context.Context, userID uuid.UUID, issuedBefore time.Time) error
}

// AuthConfig holds authentication configuration
type AuthConfig struct {
	// Authentication mode
	Mode AuthMode `json:"mode" yaml:"mode"`

	// Session configuration (for stateful mode)
	SessionTTL       time.Duration `json:"session_ttl" yaml:"session_ttl"`
	RefreshTokenTTL  time.Duration `json:"refresh_token_ttl" yaml:"refresh_token_ttl"`
	MaxLoginAttempts int           `json:"max_login_attempts" yaml:"max_login_attempts"`
	LockoutDuration  time.Duration `json:"lockout_duration" yaml:"lockout_duration"`

	// JWT configuration (for stateless mode)
	JWTSecret          string        `json:"jwt_secret" yaml:"jwt_secret"`
	JWTAccessTokenTTL  time.Duration `json:"jwt_access_token_ttl" yaml:"jwt_access_token_ttl"`
	JWTRefreshTokenTTL time.Duration `json:"jwt_refresh_token_ttl" yaml:"jwt_refresh_token_ttl"`
	JWTIssuer          string        `json:"jwt_issuer" yaml:"jwt_issuer"`
	JWTAudience        string        `json:"jwt_audience" yaml:"jwt_audience"`
	JWTAlgorithms      []string      `json:"jwt_algorithms" yaml:"jwt_algorithms"`
	JWTValidateIssuer  bool          `json:"jwt_validate_issuer" yaml:"jwt_validate_issuer"`
	JWTValidateIAT     bool          `json:"jwt_validate_iat" yaml:"jwt_validate_iat"`

	// JWT blacklist configuration
	JWTBlacklistEnabled bool `json:"jwt_blacklist_enabled" yaml:"jwt_blacklist_enabled"`

	// Password hashing configuration
	PasswordHashAlgorithm PasswordHashAlgorithm `json:"password_hash_algorithm" yaml:"password_hash_algorithm"`
	BCryptCost            int                   `json:"bcrypt_cost" yaml:"bcrypt_cost"`
	Argon2IDMemory        uint32                `json:"argon2id_memory" yaml:"argon2id_memory"`
	Argon2IDIterations    uint32                `json:"argon2id_iterations" yaml:"argon2id_iterations"`
	Argon2IDParallelism   uint8                 `json:"argon2id_parallelism" yaml:"argon2id_parallelism"`
	Argon2IDSaltLength    uint32                `json:"argon2id_salt_length" yaml:"argon2id_salt_length"`
	Argon2IDKeyLength     uint32                `json:"argon2id_key_length" yaml:"argon2id_key_length"`
}

// DefaultAuthConfig returns default authentication configuration
func DefaultAuthConfig() *AuthConfig {
	return &AuthConfig{
		Mode:                  AuthModeStateful,
		SessionTTL:            24 * time.Hour,
		RefreshTokenTTL:       30 * 24 * time.Hour, // 30 days
		MaxLoginAttempts:      5,
		LockoutDuration:       15 * time.Minute,
		JWTAccessTokenTTL:     15 * time.Minute,
		JWTRefreshTokenTTL:    7 * 24 * time.Hour, // 7 days
		JWTIssuer:             "azth-auth-service",
		JWTAudience:           "azth-api",
		JWTAlgorithms:         []string{"HS256"},
		JWTValidateIssuer:     true,
		JWTValidateIAT:        true,
		JWTBlacklistEnabled:   true, // Enable JWT blacklist by default
		PasswordHashAlgorithm: PasswordHashArgon2ID,
		BCryptCost:            12,
		Argon2IDMemory:        7168, // 7 MiB (proper default)
		Argon2IDIterations:    5,    // 5 iterations (proper default)
		Argon2IDParallelism:   1,    // 1 degree of parallelism
		Argon2IDSaltLength:    16,
		Argon2IDKeyLength:     32,
	}
}

// Dependencies interfaces
type SessionRepository interface {
	Create(ctx context.Context, session *domain.Session) error
	GetByToken(ctx context.Context, token string) (*domain.Session, error)
	GetByID(ctx context.Context, id uuid.UUID) (*domain.Session, error)
	GetByUserID(ctx context.Context, userID uuid.UUID) ([]*domain.Session, error)
	Update(ctx context.Context, session *domain.Session) error
	RevokeByID(ctx context.Context, sessionID uuid.UUID, reason string) error
	RevokeByUserID(ctx context.Context, userID uuid.UUID, reason string) error
	DeleteExpired(ctx context.Context) error
	UpdateLastActivity(ctx context.Context, sessionID uuid.UUID, lastActivity time.Time) error
}

type Logger interface {
	Info(msg string, fields ...interface{})
	Error(msg string, fields ...interface{})
	Warn(msg string, fields ...interface{})
	Debug(msg string, fields ...interface{})
}

// NewAuthService creates a new authentication service
func NewAuthService(
	userRepo userRepo.UserRepository,
	sessionRepo SessionRepository,
	roleService roleSvc.RoleService,
	logger Logger,
	config *AuthConfig,
	blacklistService ...JWTBlacklistService,
) AuthService {
	if config == nil {
		config = DefaultAuthConfig()
	}

	var blacklist JWTBlacklistService
	if len(blacklistService) > 0 {
		blacklist = blacklistService[0]
	}

	return &authServiceImpl{
		userRepo:         userRepo,
		sessionRepo:      sessionRepo,
		roleService:      roleService,
		logger:           logger,
		config:           config,
		blacklistService: blacklist,
	}
}
