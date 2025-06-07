package service

import (
	"context"
	"time"

	"github.com/ducdt2000/azth/backend/internal/domain"
	"github.com/ducdt2000/azth/backend/internal/modules/auth/dto"
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

	// Configuration
	GetAuthMode() AuthMode
	IsJWTMode() bool
	IsSessionMode() bool
}

// authService implements AuthService interface
type authService struct {
	userRepo    UserRepository
	sessionRepo SessionRepository
	logger      Logger
	config      *AuthConfig
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
		PasswordHashAlgorithm: PasswordHashArgon2ID,
		BCryptCost:            12,
		Argon2IDMemory:        64 * 1024, // 64MB
		Argon2IDIterations:    3,
		Argon2IDParallelism:   2,
		Argon2IDSaltLength:    16,
		Argon2IDKeyLength:     32,
	}
}

// Dependencies interfaces
type UserRepository interface {
	GetByEmail(ctx context.Context, email string) (*domain.User, error)
	GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error)
	UpdateLastLogin(ctx context.Context, userID uuid.UUID, loginTime time.Time) error
	UpdateLoginAttempts(ctx context.Context, userID uuid.UUID, attempts int) error
	UpdateLockedUntil(ctx context.Context, userID uuid.UUID, lockedUntil *time.Time) error
	UpdateMFASecret(ctx context.Context, userID uuid.UUID, secret string) error
	UpdateBackupCodes(ctx context.Context, userID uuid.UUID, codes []string) error
}

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
	userRepo UserRepository,
	sessionRepo SessionRepository,
	logger Logger,
	config *AuthConfig,
) AuthService {
	if config == nil {
		config = DefaultAuthConfig()
	}

	return &authService{
		userRepo:    userRepo,
		sessionRepo: sessionRepo,
		logger:      logger,
		config:      config,
	}
}

// GetAuthMode returns the current authentication mode
func (s *authService) GetAuthMode() AuthMode {
	return s.config.Mode
}

// IsJWTMode returns true if the service is configured for JWT mode
func (s *authService) IsJWTMode() bool {
	return s.config.Mode == AuthModeStateless
}

// IsSessionMode returns true if the service is configured for session mode
func (s *authService) IsSessionMode() bool {
	return s.config.Mode == AuthModeStateful
}
