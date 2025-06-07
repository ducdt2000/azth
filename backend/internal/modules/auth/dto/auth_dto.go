package dto

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// LoginRequest represents a login request
type LoginRequest struct {
	Email     string     `json:"email" validate:"required,email"`
	Password  string     `json:"password" validate:"required,min=8"`
	TenantID  *uuid.UUID `json:"tenant_id,omitempty"`
	IPAddress string     `json:"-"`
	UserAgent string     `json:"-"`
	MFACode   string     `json:"mfa_code,omitempty"`
	Remember  bool       `json:"remember"`
}

// LoginResponse represents a login response
type LoginResponse struct {
	AccessToken  string       `json:"access_token"`
	RefreshToken string       `json:"refresh_token"`
	TokenType    string       `json:"token_type"`
	ExpiresIn    int64        `json:"expires_in"`
	ExpiresAt    time.Time    `json:"expires_at"`
	User         UserInfo     `json:"user"`
	Session      *SessionInfo `json:"session,omitempty"` // Only for stateful mode
	RequiresMFA  bool         `json:"requires_mfa,omitempty"`
}

// RefreshRequest represents a token refresh request
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
	IPAddress    string `json:"-"`
	UserAgent    string `json:"-"`
}

// RefreshResponse represents a token refresh response
type RefreshResponse struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	TokenType    string    `json:"token_type"`
	ExpiresIn    int64     `json:"expires_in"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// CreateSessionRequest represents a session creation request
type CreateSessionRequest struct {
	IPAddress string    `json:"ip_address" validate:"required"`
	UserAgent string    `json:"user_agent" validate:"required"`
	TenantID  uuid.UUID `json:"tenant_id" validate:"required"`
	Remember  bool      `json:"remember"`
}

// JWT-related DTOs

// JWTRequest represents a JWT token generation request
type JWTRequest struct {
	IPAddress string `json:"ip_address"`
	UserAgent string `json:"user_agent"`
	Remember  bool   `json:"remember"`
}

// JWTResponse represents a JWT token response
type JWTResponse struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	TokenType    string    `json:"token_type"`
	ExpiresIn    int64     `json:"expires_in"`
	ExpiresAt    time.Time `json:"expires_at"`
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

// UserInfo represents user information in responses
type UserInfo struct {
	ID            uuid.UUID `json:"id"`
	Email         string    `json:"email"`
	Username      string    `json:"username"`
	FirstName     string    `json:"first_name"`
	LastName      string    `json:"last_name"`
	Avatar        *string   `json:"avatar"`
	EmailVerified bool      `json:"email_verified"`
	MFAEnabled    bool      `json:"mfa_enabled"`
	Status        string    `json:"status"`
	TenantID      uuid.UUID `json:"tenant_id"`
}

// SessionInfo represents session information in responses
type SessionInfo struct {
	ID           uuid.UUID `json:"id"`
	IPAddress    string    `json:"ip_address"`
	UserAgent    string    `json:"user_agent"`
	LastActivity time.Time `json:"last_activity"`
	ExpiresAt    time.Time `json:"expires_at"`
	CreatedAt    time.Time `json:"created_at"`
}

// MFASetupRequest represents an MFA setup request
type MFASetupRequest struct {
	UserID uuid.UUID `json:"user_id" validate:"required"`
}

// MFASetupResponse represents an MFA setup response
type MFASetupResponse struct {
	Secret      string   `json:"secret"`
	QRCodeURL   string   `json:"qr_code_url"`
	BackupCodes []string `json:"backup_codes"`
}

// MFAValidateRequest represents an MFA validation request
type MFAValidateRequest struct {
	UserID uuid.UUID `json:"user_id" validate:"required"`
	Code   string    `json:"code" validate:"required,len=6"`
}

// ChangePasswordRequest represents a password change request
type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password" validate:"required"`
	NewPassword     string `json:"new_password" validate:"required,min=8"`
	MFACode         string `json:"mfa_code,omitempty"`
}

// ResetPasswordRequest represents a password reset request
type ResetPasswordRequest struct {
	Email string `json:"email" validate:"required,email"`
}

// ResetPasswordConfirmRequest represents a password reset confirmation request
type ResetPasswordConfirmRequest struct {
	Token       string `json:"token" validate:"required"`
	NewPassword string `json:"new_password" validate:"required,min=8"`
}

// SessionListResponse represents a list of user sessions
type SessionListResponse struct {
	Sessions []SessionInfo `json:"sessions"`
	Total    int           `json:"total"`
}

// LogoutRequest represents a logout request
type LogoutRequest struct {
	All bool `json:"all"` // If true, logout from all sessions
}

// AuthError represents authentication errors
type AuthError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
}

// Error implements the error interface
func (e *AuthError) Error() string {
	return e.Message
}

// Authentication error codes
const (
	ErrCodeInvalidCredentials = "INVALID_CREDENTIALS"
	ErrCodeAccountLocked      = "ACCOUNT_LOCKED"
	ErrCodeMFARequired        = "MFA_REQUIRED"
	ErrCodeInvalidMFA         = "INVALID_MFA"
	ErrCodeSessionExpired     = "SESSION_EXPIRED"
	ErrCodeSessionNotFound    = "SESSION_NOT_FOUND"
	ErrCodeInvalidToken       = "INVALID_TOKEN"
	ErrCodeUserNotFound       = "USER_NOT_FOUND"
	ErrCodeTenantNotFound     = "TENANT_NOT_FOUND"
	ErrCodeInvalidJWT         = "INVALID_JWT"
	ErrCodeJWTExpired         = "JWT_EXPIRED"
	ErrCodeJWTMalformed       = "JWT_MALFORMED"
)
