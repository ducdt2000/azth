package service

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base32"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"

	"github.com/ducdt2000/azth/backend/internal/domain"
	"github.com/ducdt2000/azth/backend/internal/modules/auth/dto"
	"github.com/ducdt2000/azth/backend/pkg/utils"
)

// Login authenticates a user and creates a new session or JWT
func (s *authService) Login(ctx context.Context, req *dto.LoginRequest) (*dto.LoginResponse, error) {
	s.logger.Info("Login attempt", "email", req.Email, "ip", req.IPAddress, "mode", s.config.Mode)

	// Validate credentials
	user, err := s.ValidateCredentials(ctx, req.Email, req.Password)
	if err != nil {
		s.logger.Error("Login failed - invalid credentials", "email", req.Email, "error", err)
		return nil, err
	}

	// Check if account is locked
	if locked, err := s.IsAccountLocked(ctx, user.ID); err != nil {
		s.logger.Error("Failed to check account lock status", "user_id", user.ID, "error", err)
		return nil, fmt.Errorf("authentication service error: %w", err)
	} else if locked {
		s.logger.Warn("Login attempted on locked account", "user_id", user.ID, "email", req.Email)
		return nil, &dto.AuthError{
			Code:    dto.ErrCodeAccountLocked,
			Message: "Account is temporarily locked due to too many failed login attempts",
		}
	}

	// Check MFA requirements
	if user.MFAEnabled && req.MFACode == "" {
		s.logger.Info("MFA required for user", "user_id", user.ID)
		return &dto.LoginResponse{
			RequiresMFA: true,
			User:        s.mapUserToUserInfo(user),
		}, nil
	}

	// Validate MFA if enabled and code provided
	if user.MFAEnabled && req.MFACode != "" {
		valid, err := s.ValidateMFA(ctx, user.ID, req.MFACode)
		if err != nil {
			s.logger.Error("MFA validation error", "user_id", user.ID, "error", err)
			return nil, fmt.Errorf("MFA validation failed: %w", err)
		}
		if !valid {
			s.logger.Warn("Invalid MFA code", "user_id", user.ID)
			return nil, &dto.AuthError{
				Code:    dto.ErrCodeInvalidMFA,
				Message: "Invalid MFA code provided",
			}
		}
	}

	// Determine tenant ID
	tenantID := user.TenantID
	if req.TenantID != nil {
		tenantID = *req.TenantID
	}

	// Update last login
	if err := s.UpdateLastLogin(ctx, user.ID, req.IPAddress); err != nil {
		s.logger.Error("Failed to update last login", "user_id", user.ID, "error", err)
		// Don't fail login for this error
	}

	// Reset login attempts on successful login
	if err := s.userRepo.UpdateLoginAttempts(ctx, user.ID, 0); err != nil {
		s.logger.Error("Failed to reset login attempts", "user_id", user.ID, "error", err)
		// Don't fail login for this error
	}

	var response *dto.LoginResponse

	// Handle different authentication modes
	if s.IsJWTMode() {
		// JWT Mode (Stateless)
		jwtResponse, err := s.GenerateJWT(ctx, user.ID, tenantID, &dto.JWTRequest{
			IPAddress: req.IPAddress,
			UserAgent: req.UserAgent,
			Remember:  req.Remember,
		})
		if err != nil {
			s.logger.Error("Failed to generate JWT", "user_id", user.ID, "error", err)
			return nil, fmt.Errorf("failed to generate JWT: %w", err)
		}

		response = &dto.LoginResponse{
			AccessToken:  jwtResponse.AccessToken,
			RefreshToken: jwtResponse.RefreshToken,
			TokenType:    jwtResponse.TokenType,
			ExpiresIn:    jwtResponse.ExpiresIn,
			ExpiresAt:    jwtResponse.ExpiresAt,
			User:         s.mapUserToUserInfo(user),
			Session:      nil, // No session in JWT mode
			RequiresMFA:  false,
		}
	} else {
		// Session Mode (Stateful)
		sessionReq := &dto.CreateSessionRequest{
			IPAddress: req.IPAddress,
			UserAgent: req.UserAgent,
			TenantID:  tenantID,
			Remember:  req.Remember,
		}

		session, err := s.CreateSession(ctx, user.ID, sessionReq)
		if err != nil {
			s.logger.Error("Failed to create session", "user_id", user.ID, "error", err)
			return nil, fmt.Errorf("failed to create session: %w", err)
		}

		sessionInfo := s.mapSessionToSessionInfo(session)
		response = &dto.LoginResponse{
			AccessToken:  session.Token,
			RefreshToken: session.RefreshToken,
			TokenType:    "Bearer",
			ExpiresIn:    int64(s.config.SessionTTL.Seconds()),
			ExpiresAt:    session.ExpiresAt,
			User:         s.mapUserToUserInfo(user),
			Session:      &sessionInfo,
			RequiresMFA:  false,
		}
	}

	s.logger.Info("Login successful", "user_id", user.ID, "mode", s.config.Mode)
	return response, nil
}

// Logout revokes a session or invalidates JWT
func (s *authService) Logout(ctx context.Context, token string) error {
	s.logger.Info("Logout attempt", "token", token[:8]+"...", "mode", s.config.Mode)

	if s.IsJWTMode() {
		// For JWT mode, we can't really invalidate tokens without a blacklist
		// In production, you might want to implement a token blacklist
		s.logger.Info("JWT logout - token cannot be invalidated without blacklist")
		return nil
	}

	// Session mode
	session, err := s.sessionRepo.GetByToken(ctx, token)
	if err != nil {
		s.logger.Error("Failed to get session for logout", "error", err)
		return fmt.Errorf("failed to get session: %w", err)
	}

	if err := s.sessionRepo.RevokeByID(ctx, session.ID, "user_logout"); err != nil {
		s.logger.Error("Failed to revoke session", "session_id", session.ID, "error", err)
		return fmt.Errorf("failed to revoke session: %w", err)
	}

	s.logger.Info("Logout successful", "session_id", session.ID, "user_id", session.UserID)
	return nil
}

// LogoutAll revokes all sessions for a user
func (s *authService) LogoutAll(ctx context.Context, userID uuid.UUID) error {
	s.logger.Info("Logout all attempt", "user_id", userID, "mode", s.config.Mode)

	if s.IsJWTMode() {
		// For JWT mode, we can't really invalidate tokens without a blacklist
		s.logger.Info("JWT logout all - tokens cannot be invalidated without blacklist")
		return nil
	}

	// Session mode
	if err := s.sessionRepo.RevokeByUserID(ctx, userID, "user_logout_all"); err != nil {
		s.logger.Error("Failed to revoke all sessions", "user_id", userID, "error", err)
		return fmt.Errorf("failed to revoke all sessions: %w", err)
	}

	s.logger.Info("Logout all successful", "user_id", userID)
	return nil
}

// RefreshToken refreshes an existing token (session or JWT)
func (s *authService) RefreshToken(ctx context.Context, refreshToken string) (*dto.RefreshResponse, error) {
	s.logger.Info("Refresh token attempt", "mode", s.config.Mode)

	if s.IsJWTMode() {
		// JWT mode
		jwtResponse, err := s.RefreshJWT(ctx, refreshToken)
		if err != nil {
			s.logger.Error("Failed to refresh JWT", "error", err)
			return nil, err
		}

		return &dto.RefreshResponse{
			AccessToken:  jwtResponse.AccessToken,
			RefreshToken: jwtResponse.RefreshToken,
			TokenType:    jwtResponse.TokenType,
			ExpiresIn:    jwtResponse.ExpiresIn,
			ExpiresAt:    jwtResponse.ExpiresAt,
		}, nil
	}

	// Session mode
	session, err := s.sessionRepo.GetByToken(ctx, refreshToken)
	if err != nil {
		s.logger.Error("Failed to get session for refresh", "error", err)
		return nil, &dto.AuthError{
			Code:    dto.ErrCodeInvalidToken,
			Message: "Invalid refresh token",
		}
	}

	// Check if session is valid and not expired
	if session.Revoked || time.Now().After(session.ExpiresAt) {
		s.logger.Warn("Attempted to refresh expired or revoked session", "session_id", session.ID)
		return nil, &dto.AuthError{
			Code:    dto.ErrCodeSessionExpired,
			Message: "Session has expired or been revoked",
		}
	}

	// Generate new tokens
	newToken, err := s.generateSessionToken()
	if err != nil {
		s.logger.Error("Failed to generate new session token", "error", err)
		return nil, fmt.Errorf("failed to generate session token: %w", err)
	}

	newRefreshToken, err := s.generateSessionToken()
	if err != nil {
		s.logger.Error("Failed to generate new refresh token", "error", err)
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// Update session with new tokens and extend expiry
	session.Token = newToken
	session.RefreshToken = newRefreshToken
	session.ExpiresAt = time.Now().Add(s.config.SessionTTL)
	session.LastActivity = time.Now()
	session.UpdatedAt = time.Now()

	if err := s.sessionRepo.Update(ctx, session); err != nil {
		s.logger.Error("Failed to update session", "session_id", session.ID, "error", err)
		return nil, fmt.Errorf("failed to update session: %w", err)
	}

	s.logger.Info("Token refreshed successfully", "session_id", session.ID)

	return &dto.RefreshResponse{
		AccessToken:  newToken,
		RefreshToken: newRefreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(s.config.SessionTTL.Seconds()),
		ExpiresAt:    session.ExpiresAt,
	}, nil
}

// GenerateJWT generates JWT tokens for a user
func (s *authService) GenerateJWT(ctx context.Context, userID uuid.UUID, tenantID uuid.UUID, req *dto.JWTRequest) (*dto.JWTResponse, error) {
	if !s.IsJWTMode() {
		return nil, fmt.Errorf("JWT generation not available in session mode")
	}

	// Get user details
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Create JWT config
	jwtConfig := &utils.JWTConfig{
		Secret:          s.config.JWTSecret,
		Issuer:          s.config.JWTIssuer,
		Audience:        s.config.JWTAudience,
		AccessTokenTTL:  s.config.JWTAccessTokenTTL,
		RefreshTokenTTL: s.config.JWTRefreshTokenTTL,
	}

	// Generate access token
	accessToken, err := utils.GenerateAccessToken(jwtConfig, userID, tenantID, user.Email, user.Username, req.IPAddress, req.UserAgent)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	// Generate refresh token
	refreshToken, err := utils.GenerateRefreshToken(jwtConfig, userID, tenantID, user.Email, user.Username, req.IPAddress, req.UserAgent)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// Calculate expiry
	expiresAt := time.Now().Add(s.config.JWTAccessTokenTTL)

	return &dto.JWTResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(s.config.JWTAccessTokenTTL.Seconds()),
		ExpiresAt:    expiresAt,
	}, nil
}

// ValidateJWT validates a JWT token
func (s *authService) ValidateJWT(ctx context.Context, token string) (*dto.JWTClaims, error) {
	if !s.IsJWTMode() {
		return nil, fmt.Errorf("JWT validation not available in session mode")
	}

	// Create JWT config
	jwtConfig := &utils.JWTConfig{
		Secret:   s.config.JWTSecret,
		Issuer:   s.config.JWTIssuer,
		Audience: s.config.JWTAudience,
	}

	// Validate token
	claims, err := utils.ValidateJWT(jwtConfig, token)
	if err != nil {
		return nil, &dto.AuthError{
			Code:    dto.ErrCodeInvalidJWT,
			Message: fmt.Sprintf("Invalid JWT token: %v", err),
		}
	}

	// Convert to DTO claims
	dtoClaims := &dto.JWTClaims{
		UserID:           claims.UserID,
		TenantID:         claims.TenantID,
		Email:            claims.Email,
		Username:         claims.Username,
		TokenType:        claims.TokenType,
		IPAddress:        claims.IPAddress,
		UserAgent:        claims.UserAgent,
		RegisteredClaims: claims.RegisteredClaims,
	}

	return dtoClaims, nil
}

// RefreshJWT refreshes a JWT token
func (s *authService) RefreshJWT(ctx context.Context, refreshToken string) (*dto.JWTResponse, error) {
	if !s.IsJWTMode() {
		return nil, fmt.Errorf("JWT refresh not available in session mode")
	}

	// Validate refresh token
	claims, err := s.ValidateJWT(ctx, refreshToken)
	if err != nil {
		return nil, err
	}

	// Check if it's a refresh token
	if claims.TokenType != dto.TokenTypeRefresh {
		return nil, &dto.AuthError{
			Code:    dto.ErrCodeInvalidToken,
			Message: "Invalid refresh token type",
		}
	}

	// Generate new JWT tokens
	return s.GenerateJWT(ctx, claims.UserID, claims.TenantID, &dto.JWTRequest{
		IPAddress: claims.IPAddress,
		UserAgent: claims.UserAgent,
		Remember:  true, // Refresh tokens are typically for remembered sessions
	})
}

// CreateSession creates a new session for a user
func (s *authService) CreateSession(ctx context.Context, userID uuid.UUID, req *dto.CreateSessionRequest) (*domain.Session, error) {
	s.logger.Info("Creating session", "user_id", userID)

	token, err := s.generateSessionToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate session token: %w", err)
	}

	refreshToken, err := s.generateSessionToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	sessionTTL := s.config.SessionTTL
	if req.Remember {
		sessionTTL = s.config.RefreshTokenTTL
	}

	now := time.Now()
	session := &domain.Session{
		ID:           uuid.New(),
		UserID:       userID,
		TenantID:     req.TenantID,
		Token:        token,
		RefreshToken: refreshToken,
		IPAddress:    req.IPAddress,
		UserAgent:    req.UserAgent,
		LastActivity: now,
		ExpiresAt:    now.Add(sessionTTL),
		Revoked:      false,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := s.sessionRepo.Create(ctx, session); err != nil {
		s.logger.Error("Failed to create session", "user_id", userID, "error", err)
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	s.logger.Info("Session created successfully", "session_id", session.ID, "user_id", userID)
	return session, nil
}

// GetSession retrieves a session by token
func (s *authService) GetSession(ctx context.Context, token string) (*domain.Session, error) {
	session, err := s.sessionRepo.GetByToken(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("failed to get session: %w", err)
	}
	return session, nil
}

// GetUserSessions retrieves all sessions for a user
func (s *authService) GetUserSessions(ctx context.Context, userID uuid.UUID) ([]*domain.Session, error) {
	sessions, err := s.sessionRepo.GetByUserID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user sessions: %w", err)
	}
	return sessions, nil
}

// ValidateSession validates a session token and returns the session if valid
func (s *authService) ValidateSession(ctx context.Context, token string) (*domain.Session, error) {
	session, err := s.sessionRepo.GetByToken(ctx, token)
	if err != nil {
		return nil, &dto.AuthError{
			Code:    dto.ErrCodeSessionNotFound,
			Message: "Session not found",
		}
	}

	// Check if session is revoked
	if session.Revoked {
		return nil, &dto.AuthError{
			Code:    dto.ErrCodeSessionExpired,
			Message: "Session has been revoked",
		}
	}

	// Check if session is expired
	if time.Now().After(session.ExpiresAt) {
		return nil, &dto.AuthError{
			Code:    dto.ErrCodeSessionExpired,
			Message: "Session has expired",
		}
	}

	// Update last activity
	if err := s.sessionRepo.UpdateLastActivity(ctx, session.ID, time.Now()); err != nil {
		s.logger.Error("Failed to update session activity", "session_id", session.ID, "error", err)
		// Don't fail validation for this error
	}

	return session, nil
}

// RevokeSession revokes a specific session
func (s *authService) RevokeSession(ctx context.Context, sessionID uuid.UUID, reason string) error {
	return s.sessionRepo.RevokeByID(ctx, sessionID, reason)
}

// CleanupExpiredSessions removes expired sessions from the database
func (s *authService) CleanupExpiredSessions(ctx context.Context) error {
	s.logger.Info("Cleaning up expired sessions")

	if err := s.sessionRepo.DeleteExpired(ctx); err != nil {
		s.logger.Error("Failed to cleanup expired sessions", "error", err)
		return fmt.Errorf("failed to cleanup expired sessions: %w", err)
	}

	s.logger.Info("Expired sessions cleaned up successfully")
	return nil
}

// ValidateCredentials validates user email and password
func (s *authService) ValidateCredentials(ctx context.Context, email, password string) (*domain.User, error) {
	user, err := s.userRepo.GetByEmail(ctx, email)
	if err != nil {
		s.logger.Warn("User not found", "email", email)
		return nil, &dto.AuthError{
			Code:    dto.ErrCodeInvalidCredentials,
			Message: "Invalid email or password",
		}
	}

	// Verify password using the new utility
	if !s.VerifyPassword(password, user.PasswordHash) {
		s.logger.Warn("Invalid password", "user_id", user.ID, "email", email)

		// Record failed login attempt
		if err := s.RecordFailedLogin(ctx, email, ""); err != nil {
			s.logger.Error("Failed to record failed login", "email", email, "error", err)
		}

		return nil, &dto.AuthError{
			Code:    dto.ErrCodeInvalidCredentials,
			Message: "Invalid email or password",
		}
	}

	// Check user status
	if user.Status != domain.UserStatusActive {
		s.logger.Warn("User account not active", "user_id", user.ID, "status", user.Status)
		return nil, &dto.AuthError{
			Code:    dto.ErrCodeInvalidCredentials,
			Message: "Account is not active",
		}
	}

	return user, nil
}

// HashPassword hashes a password using the configured algorithm
func (s *authService) HashPassword(password string, algorithm ...PasswordHashAlgorithm) (string, error) {
	var algo PasswordHashAlgorithm
	if len(algorithm) > 0 {
		algo = algorithm[0]
	} else {
		algo = s.config.PasswordHashAlgorithm
	}

	switch algo {
	case PasswordHashArgon2ID:
		argonConfig := &utils.Argon2IDConfig{
			Memory:      s.config.Argon2IDMemory,
			Iterations:  s.config.Argon2IDIterations,
			Parallelism: s.config.Argon2IDParallelism,
			SaltLength:  s.config.Argon2IDSaltLength,
			KeyLength:   s.config.Argon2IDKeyLength,
		}
		return utils.HashPassword(password, utils.PasswordHashArgon2ID, argonConfig)
	case PasswordHashBcrypt:
		return utils.HashPassword(password, utils.PasswordHashBcrypt, s.config.BCryptCost)
	default:
		return "", fmt.Errorf("unsupported password hash algorithm: %s", algo)
	}
}

// VerifyPassword verifies a password against a hash
func (s *authService) VerifyPassword(password, hash string, algorithm ...PasswordHashAlgorithm) bool {
	// If algorithm is specified, use utils directly
	if len(algorithm) > 0 {
		switch algorithm[0] {
		case PasswordHashArgon2ID:
			return utils.VerifyPassword(password, hash)
		case PasswordHashBcrypt:
			err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
			return err == nil
		}
	}

	// Auto-detect algorithm from hash format
	return utils.VerifyPassword(password, hash)
}

// EnableMFA enables multi-factor authentication for a user
func (s *authService) EnableMFA(ctx context.Context, userID uuid.UUID) (*dto.MFASetupResponse, error) {
	s.logger.Info("Enabling MFA", "user_id", userID)

	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Generate secret
	secret := make([]byte, 20)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("failed to generate MFA secret: %w", err)
	}

	secretBase32 := base32.StdEncoding.EncodeToString(secret)

	// Generate backup codes
	backupCodes, err := s.GenerateBackupCodes(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate backup codes: %w", err)
	}

	// Save secret to database
	if err := s.userRepo.UpdateMFASecret(ctx, userID, secretBase32); err != nil {
		return nil, fmt.Errorf("failed to save MFA secret: %w", err)
	}

	// Generate QR code URL
	qrURL, err := s.generateQRCodeURL(user.Email, secretBase32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate QR code URL: %w", err)
	}

	s.logger.Info("MFA enabled successfully", "user_id", userID)

	return &dto.MFASetupResponse{
		Secret:      secretBase32,
		QRCodeURL:   qrURL,
		BackupCodes: backupCodes,
	}, nil
}

// DisableMFA disables multi-factor authentication for a user
func (s *authService) DisableMFA(ctx context.Context, userID uuid.UUID) error {
	s.logger.Info("Disabling MFA", "user_id", userID)

	if err := s.userRepo.UpdateMFASecret(ctx, userID, ""); err != nil {
		return fmt.Errorf("failed to disable MFA: %w", err)
	}

	if err := s.userRepo.UpdateBackupCodes(ctx, userID, []string{}); err != nil {
		return fmt.Errorf("failed to clear backup codes: %w", err)
	}

	s.logger.Info("MFA disabled successfully", "user_id", userID)
	return nil
}

// ValidateMFA validates a TOTP code or backup code
func (s *authService) ValidateMFA(ctx context.Context, userID uuid.UUID, code string) (bool, error) {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return false, fmt.Errorf("failed to get user: %w", err)
	}

	if !user.MFAEnabled || user.MFASecret == nil {
		return false, fmt.Errorf("MFA not enabled for user")
	}

	// Try TOTP validation first
	valid := totp.Validate(code, *user.MFASecret)
	if valid {
		return true, nil
	}

	// Check backup codes
	for i, backupCode := range user.BackupCodes {
		if subtle.ConstantTimeCompare([]byte(code), []byte(backupCode)) == 1 {
			// Remove used backup code
			user.BackupCodes = append(user.BackupCodes[:i], user.BackupCodes[i+1:]...)
			if err := s.userRepo.UpdateBackupCodes(ctx, userID, user.BackupCodes); err != nil {
				s.logger.Error("Failed to update backup codes", "user_id", userID, "error", err)
			}
			return true, nil
		}
	}

	return false, nil
}

// GenerateBackupCodes generates backup codes for MFA
func (s *authService) GenerateBackupCodes(ctx context.Context, userID uuid.UUID) ([]string, error) {
	codes := make([]string, 8) // Generate 8 backup codes

	for i := range codes {
		code := make([]byte, 8)
		if _, err := rand.Read(code); err != nil {
			return nil, fmt.Errorf("failed to generate backup code: %w", err)
		}
		codes[i] = fmt.Sprintf("%x", code)
	}

	if err := s.userRepo.UpdateBackupCodes(ctx, userID, codes); err != nil {
		return nil, fmt.Errorf("failed to save backup codes: %w", err)
	}

	return codes, nil
}

// UpdateLastLogin updates the user's last login time and IP
func (s *authService) UpdateLastLogin(ctx context.Context, userID uuid.UUID, ipAddress string) error {
	return s.userRepo.UpdateLastLogin(ctx, userID, time.Now())
}

// RecordFailedLogin records a failed login attempt
func (s *authService) RecordFailedLogin(ctx context.Context, email, ipAddress string) error {
	user, err := s.userRepo.GetByEmail(ctx, email)
	if err != nil {
		// Don't reveal if user exists
		s.logger.Debug("Failed login for non-existent user", "email", email)
		return nil
	}

	attempts := user.LoginAttempts + 1
	if err := s.userRepo.UpdateLoginAttempts(ctx, user.ID, attempts); err != nil {
		return fmt.Errorf("failed to update login attempts: %w", err)
	}

	// Lock account if too many attempts
	if attempts >= s.config.MaxLoginAttempts {
		lockUntil := time.Now().Add(s.config.LockoutDuration)
		if err := s.userRepo.UpdateLockedUntil(ctx, user.ID, &lockUntil); err != nil {
			return fmt.Errorf("failed to lock account: %w", err)
		}
		s.logger.Warn("Account locked due to failed login attempts", "user_id", user.ID, "attempts", attempts)
	}

	return nil
}

// IsAccountLocked checks if an account is currently locked
func (s *authService) IsAccountLocked(ctx context.Context, userID uuid.UUID) (bool, error) {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return false, fmt.Errorf("failed to get user: %w", err)
	}

	if user.LockedUntil == nil {
		return false, nil
	}

	if time.Now().Before(*user.LockedUntil) {
		return true, nil
	}

	// Unlock account if lock period has passed
	if err := s.UnlockAccount(ctx, userID); err != nil {
		s.logger.Error("Failed to unlock expired account", "user_id", userID, "error", err)
	}

	return false, nil
}

// UnlockAccount unlocks a user account
func (s *authService) UnlockAccount(ctx context.Context, userID uuid.UUID) error {
	if err := s.userRepo.UpdateLockedUntil(ctx, userID, nil); err != nil {
		return fmt.Errorf("failed to unlock account: %w", err)
	}

	if err := s.userRepo.UpdateLoginAttempts(ctx, userID, 0); err != nil {
		return fmt.Errorf("failed to reset login attempts: %w", err)
	}

	s.logger.Info("Account unlocked", "user_id", userID)
	return nil
}

// Helper methods

func (s *authService) generateSessionToken() (string, error) {
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", token), nil
}

func (s *authService) mapUserToUserInfo(user *domain.User) dto.UserInfo {
	return dto.UserInfo{
		ID:            user.ID,
		Email:         user.Email,
		Username:      user.Username,
		FirstName:     user.FirstName,
		LastName:      user.LastName,
		Avatar:        user.Avatar,
		EmailVerified: user.EmailVerified,
		MFAEnabled:    user.MFAEnabled,
		Status:        string(user.Status),
		TenantID:      user.TenantID,
	}
}

func (s *authService) mapSessionToSessionInfo(session *domain.Session) dto.SessionInfo {
	return dto.SessionInfo{
		ID:           session.ID,
		IPAddress:    session.IPAddress,
		UserAgent:    session.UserAgent,
		LastActivity: session.LastActivity,
		ExpiresAt:    session.ExpiresAt,
		CreatedAt:    session.CreatedAt,
	}
}

func (s *authService) generateQRCodeURL(email, secret string) (string, error) {
	key, err := otp.NewKeyFromURL(fmt.Sprintf("otpauth://totp/AZTH:%s?secret=%s&issuer=AZTH", email, secret))
	if err != nil {
		return "", err
	}
	return key.URL(), nil
}
