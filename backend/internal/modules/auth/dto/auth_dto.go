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

// Password Reset DTOs

// RequestPasswordResetRequest represents a password reset request
type RequestPasswordResetRequest struct {
	Email     string     `json:"email" validate:"required,email"`
	TenantID  *uuid.UUID `json:"tenant_id,omitempty"`
	IPAddress string     `json:"-"`
	UserAgent string     `json:"-"`
}

// RequestPasswordResetResponse represents a password reset request response
type RequestPasswordResetResponse struct {
	Message   string `json:"message"`
	TokenSent bool   `json:"token_sent"`
}

// ConfirmPasswordResetRequest represents a password reset confirmation request
type ConfirmPasswordResetRequest struct {
	Token       string     `json:"token" validate:"required"`
	NewPassword string     `json:"new_password" validate:"required,min=8"`
	TenantID    *uuid.UUID `json:"tenant_id,omitempty"`
	IPAddress   string     `json:"-"`
	UserAgent   string     `json:"-"`
}

// ConfirmPasswordResetResponse represents a password reset confirmation response
type ConfirmPasswordResetResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// UpdatePasswordRequest represents a password update request (for authenticated users)
type UpdatePasswordRequest struct {
	CurrentPassword string  `json:"current_password,omitempty"` // Optional if admin is updating
	NewPassword     string  `json:"new_password" validate:"required,min=8"`
	MFACode         *string `json:"mfa_code,omitempty"`
	IPAddress       string  `json:"-"`
	UserAgent       string  `json:"-"`
}

// UpdatePasswordResponse represents a password update response
type UpdatePasswordResponse struct {
	Success         bool   `json:"success"`
	Message         string `json:"message"`
	RequiresMFA     bool   `json:"requires_mfa,omitempty"`
	SessionsRevoked bool   `json:"sessions_revoked"`
}

// OTP DTOs

// SendOTPRequest represents a request to send an OTP
type SendOTPRequest struct {
	UserID    *uuid.UUID `json:"user_id,omitempty"`
	Type      string     `json:"type" validate:"required,oneof=email sms"`
	Purpose   string     `json:"purpose" validate:"required"`
	Target    string     `json:"target" validate:"required"` // email or phone number
	IPAddress string     `json:"-"`
	UserAgent string     `json:"-"`
}

// SendOTPResponse represents a response to sending an OTP
type SendOTPResponse struct {
	Success   bool   `json:"success"`
	Message   string `json:"message"`
	CodeSent  bool   `json:"code_sent"`
	ExpiresIn int    `json:"expires_in"` // seconds
}

// VerifyOTPRequest represents a request to verify an OTP
type VerifyOTPRequest struct {
	UserID    *uuid.UUID `json:"user_id,omitempty"`
	Code      string     `json:"code" validate:"required"`
	Type      string     `json:"type" validate:"required,oneof=email sms totp"`
	Purpose   string     `json:"purpose" validate:"required"`
	Target    string     `json:"target,omitempty"` // email or phone number
	IPAddress string     `json:"-"`
	UserAgent string     `json:"-"`
}

// VerifyOTPResponse represents a response to verifying an OTP
type VerifyOTPResponse struct {
	Valid             bool   `json:"valid"`
	Message           string `json:"message"`
	Verified          bool   `json:"verified"`
	Purpose           string `json:"purpose"`
	Target            string `json:"target,omitempty"`
	RemainingAttempts int    `json:"remaining_attempts,omitempty"`
}

// MFA Configuration DTOs

// MFAConfigRequest represents a request to update MFA configuration
type MFAConfigRequest struct {
	SMSEnabled           *bool    `json:"sms_enabled,omitempty"`
	EmailEnabled         *bool    `json:"email_enabled,omitempty"`
	TOTPEnabled          *bool    `json:"totp_enabled,omitempty"`
	TOTPIssuer           *string  `json:"totp_issuer,omitempty"`
	RequiredForLogin     *bool    `json:"required_for_login,omitempty"`
	RequiredForSensitive *bool    `json:"required_for_sensitive,omitempty"`
	Rule                 *string  `json:"rule,omitempty" validate:"omitempty,oneof=required optional prompt"`
	BackupCodesEnabled   *bool    `json:"backup_codes_enabled,omitempty"`
	BackupCodesCount     *int     `json:"backup_codes_count,omitempty"`
	TrustedDevicesDays   *int     `json:"trusted_devices_days,omitempty"`
	Settings             JSONData `json:"settings,omitempty"`
}

// MFAConfigResponse represents MFA configuration
type MFAConfigResponse struct {
	ID                   uuid.UUID  `json:"id"`
	TenantID             *uuid.UUID `json:"tenant_id"`
	SMSEnabled           bool       `json:"sms_enabled"`
	EmailEnabled         bool       `json:"email_enabled"`
	TOTPEnabled          bool       `json:"totp_enabled"`
	TOTPIssuer           string     `json:"totp_issuer"`
	RequiredForLogin     bool       `json:"required_for_login"`
	RequiredForSensitive bool       `json:"required_for_sensitive"`
	Rule                 string     `json:"rule"`
	BackupCodesEnabled   bool       `json:"backup_codes_enabled"`
	BackupCodesCount     int        `json:"backup_codes_count"`
	TrustedDevicesDays   int        `json:"trusted_devices_days"`
	Settings             JSONData   `json:"settings"`
	CreatedAt            time.Time  `json:"created_at"`
	UpdatedAt            time.Time  `json:"updated_at"`
}

// OTP Configuration DTOs

// OTPConfigRequest represents a request to update OTP configuration
type OTPConfigRequest struct {
	Purpose          string     `json:"purpose" validate:"required"`
	Type             string     `json:"type" validate:"required,oneof=email sms"`
	Enabled          *bool      `json:"enabled,omitempty"`
	CodeLength       *int       `json:"code_length,omitempty" validate:"omitempty,min=4,max=10"`
	ExpiryMinutes    *int       `json:"expiry_minutes,omitempty" validate:"omitempty,min=1,max=60"`
	MaxAttempts      *int       `json:"max_attempts,omitempty" validate:"omitempty,min=1,max=10"`
	CooldownMinutes  *int       `json:"cooldown_minutes,omitempty" validate:"omitempty,min=0,max=60"`
	RateLimitPerHour *int       `json:"rate_limit_per_hour,omitempty" validate:"omitempty,min=1,max=100"`
	RateLimitPerDay  *int       `json:"rate_limit_per_day,omitempty" validate:"omitempty,min=1,max=1000"`
	IsNumericOnly    *bool      `json:"is_numeric_only,omitempty"`
	TemplateID       *uuid.UUID `json:"template_id,omitempty"`
	Settings         JSONData   `json:"settings,omitempty"`
}

// OTPConfigResponse represents OTP configuration
type OTPConfigResponse struct {
	ID               uuid.UUID  `json:"id"`
	TenantID         *uuid.UUID `json:"tenant_id"`
	Purpose          string     `json:"purpose"`
	Type             string     `json:"type"`
	Enabled          bool       `json:"enabled"`
	CodeLength       int        `json:"code_length"`
	ExpiryMinutes    int        `json:"expiry_minutes"`
	MaxAttempts      int        `json:"max_attempts"`
	CooldownMinutes  int        `json:"cooldown_minutes"`
	RateLimitPerHour int        `json:"rate_limit_per_hour"`
	RateLimitPerDay  int        `json:"rate_limit_per_day"`
	IsNumericOnly    bool       `json:"is_numeric_only"`
	TemplateID       *uuid.UUID `json:"template_id"`
	Settings         JSONData   `json:"settings"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

// Notification Template DTOs

// NotificationTemplateRequest represents a request to create/update a notification template
type NotificationTemplateRequest struct {
	Name      string   `json:"name" validate:"required,min=1,max=100"`
	Type      string   `json:"type" validate:"required,oneof=email sms"`
	Purpose   string   `json:"purpose" validate:"required"`
	Language  string   `json:"language" validate:"required,len=2"`
	Subject   *string  `json:"subject,omitempty"` // Required for email templates
	Body      string   `json:"body" validate:"required"`
	BodyHTML  *string  `json:"body_html,omitempty"`
	Variables []string `json:"variables,omitempty"`
	IsDefault *bool    `json:"is_default,omitempty"`
	IsActive  *bool    `json:"is_active,omitempty"`
	Metadata  JSONData `json:"metadata,omitempty"`
}

// NotificationTemplateResponse represents a notification template
type NotificationTemplateResponse struct {
	ID        uuid.UUID  `json:"id"`
	TenantID  *uuid.UUID `json:"tenant_id"`
	Name      string     `json:"name"`
	Type      string     `json:"type"`
	Purpose   string     `json:"purpose"`
	Language  string     `json:"language"`
	Subject   *string    `json:"subject,omitempty"`
	Body      string     `json:"body"`
	BodyHTML  *string    `json:"body_html,omitempty"`
	Variables []string   `json:"variables"`
	IsDefault bool       `json:"is_default"`
	IsActive  bool       `json:"is_active"`
	Metadata  JSONData   `json:"metadata"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
}

// Trusted Device DTOs

// TrustedDeviceRequest represents a request to trust a device
type TrustedDeviceRequest struct {
	Name      string `json:"name" validate:"required,min=1,max=100"`
	DeviceID  string `json:"device_id" validate:"required"`
	Days      *int   `json:"days,omitempty" validate:"omitempty,min=1,max=365"`
	IPAddress string `json:"-"`
	UserAgent string `json:"-"`
}

// TrustedDeviceResponse represents a trusted device
type TrustedDeviceResponse struct {
	ID         uuid.UUID `json:"id"`
	Name       string    `json:"name"`
	DeviceID   string    `json:"device_id"`
	UserAgent  string    `json:"user_agent"`
	IPAddress  string    `json:"ip_address"`
	LastUsedAt time.Time `json:"last_used_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	IsActive   bool      `json:"is_active"`
	CreatedAt  time.Time `json:"created_at"`
}

// Notification Log DTOs

// NotificationLogResponse represents a notification log entry
type NotificationLogResponse struct {
	ID           uuid.UUID  `json:"id"`
	Type         string     `json:"type"`
	Purpose      string     `json:"purpose"`
	Recipient    string     `json:"recipient"`
	Subject      *string    `json:"subject,omitempty"`
	Status       string     `json:"status"`
	ErrorMessage *string    `json:"error_message,omitempty"`
	ExternalID   *string    `json:"external_id,omitempty"`
	SentAt       *time.Time `json:"sent_at,omitempty"`
	DeliveredAt  *time.Time `json:"delivered_at,omitempty"`
	FailedAt     *time.Time `json:"failed_at,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
}

// ListResponse represents a paginated list response
type ListResponse struct {
	Items    interface{} `json:"items"`
	Total    int         `json:"total"`
	Page     int         `json:"page"`
	PageSize int         `json:"page_size"`
	Pages    int         `json:"pages"`
}

// JSONData represents JSON data for flexible configuration
type JSONData map[string]interface{}
