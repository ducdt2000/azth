package service

import (
	"context"
	"time"

	"github.com/ducdt2000/azth/backend/internal/domain"
	"github.com/ducdt2000/azth/backend/internal/modules/auth/dto"
	"github.com/google/uuid"
)

// OTPService defines the interface for OTP operations
type OTPService interface {
	// OTP generation and verification
	GenerateOTP(ctx context.Context, req *GenerateOTPRequest) (*GenerateOTPResponse, error)
	VerifyOTP(ctx context.Context, req *dto.VerifyOTPRequest) (*dto.VerifyOTPResponse, error)
	SendOTP(ctx context.Context, req *dto.SendOTPRequest) (*dto.SendOTPResponse, error)

	// OTP configuration management
	CreateOTPConfig(ctx context.Context, tenantID *uuid.UUID, req *dto.OTPConfigRequest) (*dto.OTPConfigResponse, error)
	UpdateOTPConfig(ctx context.Context, id uuid.UUID, req *dto.OTPConfigRequest) (*dto.OTPConfigResponse, error)
	GetOTPConfig(ctx context.Context, tenantID *uuid.UUID, purpose domain.OTPPurpose, otpType domain.OTPType) (*domain.OTPConfig, error)
	ListOTPConfigs(ctx context.Context, tenantID *uuid.UUID) ([]*dto.OTPConfigResponse, error)
	DeleteOTPConfig(ctx context.Context, id uuid.UUID) error

	// OTP management
	InvalidateOTP(ctx context.Context, userID uuid.UUID, purpose domain.OTPPurpose, target string) error
	InvalidateAllOTPs(ctx context.Context, userID uuid.UUID) error
	CheckRateLimit(ctx context.Context, userID uuid.UUID, purpose domain.OTPPurpose, otpType domain.OTPType) error
	GetActiveCodes(ctx context.Context, userID uuid.UUID, purpose domain.OTPPurpose) ([]*domain.OTPCode, error)

	// TOTP specific methods
	GenerateTOTPSecret(userID uuid.UUID, email string) (string, string, error) // secret, qrURL
	ValidateTOTP(secret, code string) bool
	GenerateBackupCodes(count int) []string
}

// MFAService defines the interface for MFA operations
type MFAService interface {
	// MFA configuration
	GetMFAConfig(ctx context.Context, tenantID *uuid.UUID) (*dto.MFAConfigResponse, error)
	UpdateMFAConfig(ctx context.Context, tenantID *uuid.UUID, req *dto.MFAConfigRequest) (*dto.MFAConfigResponse, error)

	// MFA validation
	ValidateMFA(ctx context.Context, userID uuid.UUID, code string, mfaType domain.OTPType) (*MFAValidationResult, error)
	RequiresMFA(ctx context.Context, userID uuid.UUID, action MFAAction) (bool, *MFARequirement, error)

	// Trusted devices
	TrustDevice(ctx context.Context, req *dto.TrustedDeviceRequest, userID uuid.UUID) (*dto.TrustedDeviceResponse, error)
	IsTrustedDevice(ctx context.Context, userID uuid.UUID, deviceID string) (bool, error)
	ListTrustedDevices(ctx context.Context, userID uuid.UUID) ([]*dto.TrustedDeviceResponse, error)
	RevokeTrustedDevice(ctx context.Context, userID uuid.UUID, deviceID string) error
	CleanupExpiredDevices(ctx context.Context) error
}

// PasswordResetService defines the interface for password reset operations
type PasswordResetService interface {
	// Password reset flow
	RequestPasswordReset(ctx context.Context, req *dto.RequestPasswordResetRequest) (*dto.RequestPasswordResetResponse, error)
	ConfirmPasswordReset(ctx context.Context, req *dto.ConfirmPasswordResetRequest) (*dto.ConfirmPasswordResetResponse, error)
	UpdatePassword(ctx context.Context, userID uuid.UUID, req *dto.UpdatePasswordRequest) (*dto.UpdatePasswordResponse, error)

	// Token management
	ValidateResetToken(ctx context.Context, token string) (*domain.PasswordResetToken, error)
	InvalidateResetToken(ctx context.Context, tokenID uuid.UUID) error
	CleanupExpiredTokens(ctx context.Context) error
}

// GenerateOTPRequest represents a request to generate an OTP
type GenerateOTPRequest struct {
	UserID    uuid.UUID         `validate:"required"`
	TenantID  uuid.UUID         `validate:"required"`
	Type      domain.OTPType    `validate:"required"`
	Purpose   domain.OTPPurpose `validate:"required"`
	Target    string            `validate:"required"`
	IPAddress string
	UserAgent string
}

// GenerateOTPResponse represents the response from OTP generation
type GenerateOTPResponse struct {
	ID        uuid.UUID `json:"id"`
	Code      string    `json:"code,omitempty"` // Only returned for testing
	ExpiresAt time.Time `json:"expires_at"`
	ExpiresIn int       `json:"expires_in"` // seconds
}

// MFAAction represents the action requiring MFA validation
type MFAAction string

const (
	MFAActionLogin           MFAAction = "login"
	MFAActionPasswordChange  MFAAction = "password_change"
	MFAActionSensitiveChange MFAAction = "sensitive_change"
	MFAActionAdminAction     MFAAction = "admin_action"
	MFAActionPasswordReset   MFAAction = "password_reset"
)

// MFARequirement represents MFA requirements for an action
type MFARequirement struct {
	Required      bool             `json:"required"`
	Rule          domain.MFARule   `json:"rule"`
	Methods       []domain.OTPType `json:"methods"`
	TrustedDevice bool             `json:"trusted_device"`
	Reason        string           `json:"reason"`
}

// MFAValidationResult represents the result of MFA validation
type MFAValidationResult struct {
	Valid       bool              `json:"valid"`
	Method      domain.OTPType    `json:"method"`
	UserID      uuid.UUID         `json:"user_id"`
	Purpose     domain.OTPPurpose `json:"purpose"`
	ValidatedAt time.Time         `json:"validated_at"`
	TrustToken  *string           `json:"trust_token,omitempty"`
}

// OTPGenerator defines the interface for OTP code generation
type OTPGenerator interface {
	GenerateCode(length int, numericOnly bool) string
	GenerateToken(length int) string
	HashCode(code string) string
	VerifyCode(code, hash string) bool
}

// RateLimiter defines the interface for rate limiting
type RateLimiter interface {
	Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, error)
	Reset(ctx context.Context, key string) error
	GetCount(ctx context.Context, key string, window time.Duration) (int, error)
}
