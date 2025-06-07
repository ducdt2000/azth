package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/ducdt2000/azth/backend/internal/domain"
	"github.com/ducdt2000/azth/backend/internal/modules/auth/dto"
	notificationService "github.com/ducdt2000/azth/backend/internal/modules/notification/service"
	otpService "github.com/ducdt2000/azth/backend/internal/modules/otp/service"
	userRepo "github.com/ducdt2000/azth/backend/internal/modules/user/repository"
	"github.com/ducdt2000/azth/backend/pkg/logger"
	"github.com/ducdt2000/azth/backend/pkg/utils"
	"github.com/google/uuid"
)

// PasswordResetService handles password reset operations
type PasswordResetService struct {
	userRepo        userRepo.UserRepository
	resetTokenRepo  PasswordResetTokenRepository
	notificationSvc notificationService.NotificationService
	otpService      otpService.OTPService
	mfaService      otpService.MFAService
	logger          logger.Logger
	config          *PasswordResetConfig
}

// PasswordResetConfig contains configuration for password reset operations
type PasswordResetConfig struct {
	TokenTTL           time.Duration `default:"30m"`
	TokenLength        int           `default:"32"`
	MaxAttemptsPerHour int           `default:"5"`
	MaxAttemptsPerDay  int           `default:"10"`
	RequireMFA         bool          `default:"false"`
	CooldownDuration   time.Duration `default:"5m"`
}

// PasswordResetTokenRepository defines the interface for password reset token operations
type PasswordResetTokenRepository interface {
	Create(ctx context.Context, token *domain.PasswordResetToken) error
	GetByToken(ctx context.Context, tokenHash string) (*domain.PasswordResetToken, error)
	GetByUserID(ctx context.Context, userID uuid.UUID) ([]*domain.PasswordResetToken, error)
	MarkAsUsed(ctx context.Context, tokenID uuid.UUID) error
	DeleteExpired(ctx context.Context) error
	DeleteByUserID(ctx context.Context, userID uuid.UUID) error
	CountRecentAttempts(ctx context.Context, userID uuid.UUID, window time.Duration) (int, error)
}

// NewPasswordResetService creates a new password reset service
func NewPasswordResetService(
	userRepo userRepo.UserRepository,
	resetTokenRepo PasswordResetTokenRepository,
	notificationSvc notificationService.NotificationService,
	otpService otpService.OTPService,
	mfaService otpService.MFAService,
	logger logger.Logger,
	config *PasswordResetConfig,
) otpService.PasswordResetService {
	if config == nil {
		config = &PasswordResetConfig{
			TokenTTL:           30 * time.Minute,
			TokenLength:        32,
			MaxAttemptsPerHour: 5,
			MaxAttemptsPerDay:  10,
			RequireMFA:         false,
			CooldownDuration:   5 * time.Minute,
		}
	}

	return &PasswordResetService{
		userRepo:        userRepo,
		resetTokenRepo:  resetTokenRepo,
		notificationSvc: notificationSvc,
		otpService:      otpService,
		mfaService:      mfaService,
		logger:          logger,
		config:          config,
	}
}

// RequestPasswordReset initiates a password reset request
func (s *PasswordResetService) RequestPasswordReset(ctx context.Context, req *dto.RequestPasswordResetRequest) (*dto.RequestPasswordResetResponse, error) {
	s.logger.Info("Password reset requested", "email", req.Email, "ip", req.IPAddress)

	// Get user by email
	user, err := s.userRepo.GetByEmail(ctx, req.Email)
	if err != nil {
		s.logger.Warn("Password reset requested for non-existent email", "email", req.Email)
		// Return success to prevent email enumeration
		return &dto.RequestPasswordResetResponse{
			Message:   "If the email exists, a password reset code has been sent",
			TokenSent: false,
		}, nil
	}

	// Check rate limiting
	recentAttempts, err := s.resetTokenRepo.CountRecentAttempts(ctx, user.ID, time.Hour)
	if err != nil {
		s.logger.Error("Failed to check recent password reset attempts", "error", err)
		return nil, fmt.Errorf("failed to check rate limits: %w", err)
	}

	if recentAttempts >= s.config.MaxAttemptsPerHour {
		s.logger.Warn("Password reset rate limit exceeded", "user_id", user.ID, "attempts", recentAttempts)
		return &dto.RequestPasswordResetResponse{
			Message:   "Too many password reset attempts. Please try again later",
			TokenSent: false,
		}, nil
	}

	// Invalidate existing tokens for this user
	if err := s.resetTokenRepo.DeleteByUserID(ctx, user.ID); err != nil {
		s.logger.Error("Failed to invalidate existing reset tokens", "error", err, "user_id", user.ID)
	}

	// Generate reset token
	token, tokenHash, err := s.generateResetToken()
	if err != nil {
		s.logger.Error("Failed to generate reset token", "error", err)
		return nil, fmt.Errorf("failed to generate reset token: %w", err)
	}

	// Create reset token record
	resetToken := &domain.PasswordResetToken{
		ID:        uuid.New(),
		UserID:    user.ID,
		TenantID:  user.TenantID,
		Token:     token,
		TokenHash: tokenHash,
		ExpiresAt: time.Now().Add(s.config.TokenTTL),
		Used:      false,
		IPAddress: req.IPAddress,
		UserAgent: req.UserAgent,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := s.resetTokenRepo.Create(ctx, resetToken); err != nil {
		s.logger.Error("Failed to save reset token", "error", err)
		return nil, fmt.Errorf("failed to save reset token: %w", err)
	}

	// Send reset code via email
	err = s.notificationSvc.SendEmailWithTemplate(ctx, &notificationService.SendEmailWithTemplateRequest{
		TenantID: user.TenantID,
		UserID:   &user.ID,
		To:       user.Email,
		Purpose:  domain.OTPPurposePasswordReset,
		Language: "en", // TODO: Get from user preferences
		Variables: map[string]interface{}{
			"FirstName":     user.FirstName,
			"Code":          token,
			"ExpiryMinutes": int(s.config.TokenTTL.Minutes()),
		},
	})

	if err != nil {
		s.logger.Error("Failed to send password reset email", "error", err, "user_id", user.ID)
		// Don't fail the request if email sending fails
		return &dto.RequestPasswordResetResponse{
			Message:   "Password reset initiated, but email delivery failed",
			TokenSent: false,
		}, nil
	}

	s.logger.Info("Password reset token sent", "user_id", user.ID, "email", user.Email)
	return &dto.RequestPasswordResetResponse{
		Message:   "Password reset code sent to your email",
		TokenSent: true,
	}, nil
}

// ConfirmPasswordReset confirms a password reset with the provided token
func (s *PasswordResetService) ConfirmPasswordReset(ctx context.Context, req *dto.ConfirmPasswordResetRequest) (*dto.ConfirmPasswordResetResponse, error) {
	s.logger.Info("Password reset confirmation attempted", "ip", req.IPAddress)

	// Hash the provided token to look up in database
	tokenHash := s.hashToken(req.Token)

	// Get reset token
	resetToken, err := s.resetTokenRepo.GetByToken(ctx, tokenHash)
	if err != nil {
		s.logger.Warn("Invalid password reset token used", "token_hash", tokenHash)
		return &dto.ConfirmPasswordResetResponse{
			Success: false,
			Message: "Invalid or expired reset token",
		}, nil
	}

	// Check if token is expired
	if time.Now().After(resetToken.ExpiresAt) {
		s.logger.Warn("Expired password reset token used", "token_id", resetToken.ID, "user_id", resetToken.UserID)
		return &dto.ConfirmPasswordResetResponse{
			Success: false,
			Message: "Reset token has expired",
		}, nil
	}

	// Check if token is already used
	if resetToken.Used {
		s.logger.Warn("Already used password reset token", "token_id", resetToken.ID, "user_id", resetToken.UserID)
		return &dto.ConfirmPasswordResetResponse{
			Success: false,
			Message: "Reset token has already been used",
		}, nil
	}

	// Get user
	user, err := s.userRepo.GetByID(ctx, resetToken.UserID)
	if err != nil {
		s.logger.Error("Failed to get user for password reset", "error", err, "user_id", resetToken.UserID)
		return &dto.ConfirmPasswordResetResponse{
			Success: false,
			Message: "User not found",
		}, nil
	}

	// Hash new password using utils package
	hashedPassword, err := utils.HashPassword(req.NewPassword, utils.PasswordHashArgon2ID)
	if err != nil {
		s.logger.Error("Failed to hash new password", "error", err)
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Update user password
	user.PasswordHash = hashedPassword
	user.PasswordChangedAt = &time.Time{}
	*user.PasswordChangedAt = time.Now()
	user.UpdatedAt = time.Now()

	if err := s.userRepo.Update(ctx, user); err != nil {
		s.logger.Error("Failed to update user password", "error", err, "user_id", user.ID)
		return nil, fmt.Errorf("failed to update password: %w", err)
	}

	// Mark token as used
	if err := s.resetTokenRepo.MarkAsUsed(ctx, resetToken.ID); err != nil {
		s.logger.Error("Failed to mark reset token as used", "error", err, "token_id", resetToken.ID)
		// Don't fail the request if this fails
	}

	// Invalidate all other tokens for this user
	if err := s.resetTokenRepo.DeleteByUserID(ctx, user.ID); err != nil {
		s.logger.Error("Failed to invalidate other reset tokens", "error", err, "user_id", user.ID)
		// Don't fail the request if this fails
	}

	s.logger.Info("Password reset completed successfully", "user_id", user.ID)
	return &dto.ConfirmPasswordResetResponse{
		Success: true,
		Message: "Password has been reset successfully",
	}, nil
}

// UpdatePassword updates a user's password for authenticated users
func (s *PasswordResetService) UpdatePassword(ctx context.Context, userID uuid.UUID, req *dto.UpdatePasswordRequest) (*dto.UpdatePasswordResponse, error) {
	s.logger.Info("Password update requested", "user_id", userID, "ip", req.IPAddress)

	// Get user
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		s.logger.Error("Failed to get user for password update", "error", err, "user_id", userID)
		return nil, fmt.Errorf("user not found: %w", err)
	}

	// Verify current password if provided
	if req.CurrentPassword != "" {
		if !utils.VerifyPassword(req.CurrentPassword, user.PasswordHash) {
			s.logger.Warn("Invalid current password provided for password update", "user_id", userID)
			return &dto.UpdatePasswordResponse{
				Success: false,
				Message: "Current password is incorrect",
			}, nil
		}
	}

	// Check if MFA is required for password changes
	requiresMFA, mfaReq, err := s.mfaService.RequiresMFA(ctx, userID, otpService.MFAActionPasswordChange)
	if err != nil {
		s.logger.Error("Failed to check MFA requirements", "error", err, "user_id", userID)
		requiresMFA = false // Default to not requiring MFA if check fails
	}

	if requiresMFA && req.MFACode == nil {
		s.logger.Info("MFA required for password change", "user_id", userID)
		return &dto.UpdatePasswordResponse{
			Success:     false,
			RequiresMFA: true,
			Message:     fmt.Sprintf("MFA verification required: %s", mfaReq.Reason),
		}, nil
	}

	// Validate MFA if provided
	if req.MFACode != nil && *req.MFACode != "" {
		mfaResult, err := s.mfaService.ValidateMFA(ctx, userID, *req.MFACode, domain.OTPTypeTOTP)
		if err != nil || !mfaResult.Valid {
			s.logger.Warn("Invalid MFA code for password change", "user_id", userID)
			return &dto.UpdatePasswordResponse{
				Success: false,
				Message: "Invalid MFA code",
			}, nil
		}
	}

	// Hash new password using utils package
	hashedPassword, err := utils.HashPassword(req.NewPassword, utils.PasswordHashArgon2ID)
	if err != nil {
		s.logger.Error("Failed to hash new password", "error", err)
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Update user password
	user.PasswordHash = hashedPassword
	user.PasswordChangedAt = &time.Time{}
	*user.PasswordChangedAt = time.Now()
	user.UpdatedAt = time.Now()

	if err := s.userRepo.Update(ctx, user); err != nil {
		s.logger.Error("Failed to update user password", "error", err, "user_id", userID)
		return nil, fmt.Errorf("failed to update password: %w", err)
	}

	s.logger.Info("Password updated successfully", "user_id", userID)
	return &dto.UpdatePasswordResponse{
		Success:         true,
		Message:         "Password updated successfully",
		SessionsRevoked: false, // TODO: Implement session revocation if needed
	}, nil
}

// ValidateResetToken validates a password reset token
func (s *PasswordResetService) ValidateResetToken(ctx context.Context, token string) (*domain.PasswordResetToken, error) {
	tokenHash := s.hashToken(token)
	resetToken, err := s.resetTokenRepo.GetByToken(ctx, tokenHash)
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	if time.Now().After(resetToken.ExpiresAt) {
		return nil, fmt.Errorf("token expired")
	}

	if resetToken.Used {
		return nil, fmt.Errorf("token already used")
	}

	return resetToken, nil
}

// InvalidateResetToken invalidates a password reset token
func (s *PasswordResetService) InvalidateResetToken(ctx context.Context, tokenID uuid.UUID) error {
	return s.resetTokenRepo.MarkAsUsed(ctx, tokenID)
}

// CleanupExpiredTokens removes expired password reset tokens
func (s *PasswordResetService) CleanupExpiredTokens(ctx context.Context) error {
	return s.resetTokenRepo.DeleteExpired(ctx)
}

// generateResetToken generates a cryptographically secure reset token
func (s *PasswordResetService) generateResetToken() (token, hash string, err error) {
	bytes := make([]byte, s.config.TokenLength)
	if _, err := rand.Read(bytes); err != nil {
		return "", "", err
	}

	token = hex.EncodeToString(bytes)
	hash = s.hashToken(token)
	return token, hash, nil
}

// hashToken creates a SHA-256 hash of the token for storage
func (s *PasswordResetService) hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}
