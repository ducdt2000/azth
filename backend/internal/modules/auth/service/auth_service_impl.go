package service

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"github.com/ducdt2000/azth/backend/internal/domain"
	"github.com/ducdt2000/azth/backend/internal/modules/auth/dto"
	roleSvc "github.com/ducdt2000/azth/backend/internal/modules/role/service"
	userRepo "github.com/ducdt2000/azth/backend/internal/modules/user/repository"
	"github.com/ducdt2000/azth/backend/pkg/utils"
)

type authServiceImpl struct {
	userRepo         userRepo.UserRepository
	sessionRepo      SessionRepository
	roleService      roleSvc.RoleService
	logger           Logger
	config           *AuthConfig
	blacklistService JWTBlacklistService
}

// Login authenticates a user and creates a new session or JWT
func (s *authServiceImpl) Login(ctx context.Context, req *dto.LoginRequest) (*dto.LoginResponse, error) {
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
	if err := s.userRepo.ResetLoginAttempts(ctx, user.ID); err != nil {
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
func (s *authServiceImpl) Logout(ctx context.Context, token string) error {
	s.logger.Info("Logout attempt", "token", token[:8]+"...", "mode", s.config.Mode)

	if s.IsJWTMode() {
		// For JWT mode, use blacklist if enabled
		if s.config.JWTBlacklistEnabled && s.blacklistService != nil {
			return s.RevokeJWT(ctx, token)
		} else {
			s.logger.Info("JWT logout - blacklist disabled or service unavailable")
			return nil
		}
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
func (s *authServiceImpl) LogoutAll(ctx context.Context, userID uuid.UUID) error {
	s.logger.Info("Logout all attempt", "user_id", userID, "mode", s.config.Mode)

	if s.IsJWTMode() {
		// For JWT mode, use blacklist if enabled
		if s.config.JWTBlacklistEnabled && s.blacklistService != nil {
			// Add all user tokens issued before now to blacklist
			issuedBefore := time.Now()
			if err := s.blacklistService.AddUserToBlacklist(ctx, userID, issuedBefore); err != nil {
				s.logger.Error("Failed to blacklist user tokens", "user_id", userID, "error", err)
				return fmt.Errorf("failed to blacklist user tokens: %w", err)
			}
			s.logger.Info("JWT logout all successful - added to blacklist", "user_id", userID)
			return nil
		} else {
			s.logger.Info("JWT logout all - blacklist disabled or service unavailable")
			return nil
		}
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
func (s *authServiceImpl) RefreshToken(ctx context.Context, refreshToken string) (*dto.RefreshResponse, error) {
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
func (s *authServiceImpl) GenerateJWT(ctx context.Context, userID uuid.UUID, tenantID uuid.UUID, req *dto.JWTRequest) (*dto.JWTResponse, error) {
	if !s.IsJWTMode() {
		return nil, fmt.Errorf("JWT generation not available in session mode")
	}

	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Get user roles and permissions
	userRoles, err := s.roleService.GetUserRoles(ctx, userID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}
	roles := make([]string, len(userRoles))
	for i, r := range userRoles {
		roles[i] = r.Role.Slug
	}

	userPermissions, err := s.roleService.GetUserPermissions(ctx, userID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user permissions: %w", err)
	}
	permissions := make([]string, len(userPermissions))
	for i, p := range userPermissions {
		permissions[i] = p.Code
	}

	// Create JWT config
	jwtConfig := &utils.JWTConfig{
		Secret:          s.config.JWTSecret,
		Issuer:          s.config.JWTIssuer,
		Audience:        s.config.JWTAudience,
		AccessTokenTTL:  s.config.JWTAccessTokenTTL,
		RefreshTokenTTL: s.config.JWTRefreshTokenTTL,
		Algorithms:      s.config.JWTAlgorithms,
		ValidateIssuer:  s.config.JWTValidateIssuer,
		ValidateIAT:     s.config.JWTValidateIAT,
	}

	accessToken, err := utils.GenerateAccessToken(jwtConfig, userID, tenantID, user.Email, user.Username, roles, permissions, req.IPAddress, req.UserAgent)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	refreshToken, err := utils.GenerateRefreshToken(jwtConfig, userID, tenantID, user.Email, user.Username, req.IPAddress, req.UserAgent)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

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
func (s *authServiceImpl) ValidateJWT(ctx context.Context, token string) (*dto.JWTClaims, error) {
	if !s.IsJWTMode() {
		return nil, fmt.Errorf("JWT validation not available in session mode")
	}

	// Check blacklist if enabled
	if s.config.JWTBlacklistEnabled && s.blacklistService != nil {
		// Extract JTI to check blacklist
		jti, err := utils.ExtractJTIFromJWT(token)
		if err != nil {
			s.logger.Warn("Failed to extract JTI for blacklist check", "error", err)
			// Continue validation even if JTI extraction fails
		} else {
			// Check if token is blacklisted
			isBlacklisted, err := s.blacklistService.IsBlacklisted(ctx, jti)
			if err != nil {
				s.logger.Warn("Failed to check JWT blacklist", "jti", jti, "error", err)
				// Continue validation even if blacklist check fails
			} else if isBlacklisted {
				return nil, &dto.AuthError{
					Code:    dto.ErrCodeInvalidJWT,
					Message: "JWT token has been revoked",
				}
			}
		}
	}

	// Create JWT config
	jwtConfig := &utils.JWTConfig{
		Secret:         s.config.JWTSecret,
		Issuer:         s.config.JWTIssuer,
		Audience:       s.config.JWTAudience,
		Algorithms:     s.config.JWTAlgorithms,
		ValidateIssuer: s.config.JWTValidateIssuer,
		ValidateIAT:    s.config.JWTValidateIAT,
	}

	// Validate JWT
	claims, err := utils.ValidateJWT(jwtConfig, token)
	if err != nil {
		return nil, &dto.AuthError{
			Code:    dto.ErrCodeInvalidJWT,
			Message: fmt.Sprintf("Invalid JWT token: %v", err),
		}
	}

	dtoClaims := &dto.JWTClaims{
		UserID:           claims.UserID,
		TenantID:         claims.TenantID,
		Email:            claims.Email,
		Username:         claims.Username,
		Roles:            claims.Roles,
		Permissions:      claims.Permissions,
		RegisteredClaims: claims.RegisteredClaims,
	}

	return dtoClaims, nil
}

// RefreshJWT refreshes a JWT token
func (s *authServiceImpl) RefreshJWT(ctx context.Context, refreshToken string) (*dto.JWTResponse, error) {
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
func (s *authServiceImpl) CreateSession(ctx context.Context, userID uuid.UUID, req *dto.CreateSessionRequest) (*domain.Session, error) {
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
func (s *authServiceImpl) GetSession(ctx context.Context, token string) (*domain.Session, error) {
	session, err := s.sessionRepo.GetByToken(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("failed to get session: %w", err)
	}
	return session, nil
}

// GetUserSessions retrieves all sessions for a user
func (s *authServiceImpl) GetUserSessions(ctx context.Context, userID uuid.UUID) ([]*domain.Session, error) {
	sessions, err := s.sessionRepo.GetByUserID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user sessions: %w", err)
	}
	return sessions, nil
}

// ValidateSession validates a session token and returns the session if valid
func (s *authServiceImpl) ValidateSession(ctx context.Context, token string) (*domain.Session, error) {
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
func (s *authServiceImpl) RevokeSession(ctx context.Context, sessionID uuid.UUID, reason string) error {
	return s.sessionRepo.RevokeByID(ctx, sessionID, reason)
}

// CleanupExpiredSessions removes expired sessions from the database
func (s *authServiceImpl) CleanupExpiredSessions(ctx context.Context) error {
	s.logger.Info("Cleaning up expired sessions")

	if err := s.sessionRepo.DeleteExpired(ctx); err != nil {
		s.logger.Error("Failed to cleanup expired sessions", "error", err)
		return fmt.Errorf("failed to cleanup expired sessions: %w", err)
	}

	s.logger.Info("Expired sessions cleaned up successfully")
	return nil
}

// ValidateCredentials validates user credentials using the shared repository
func (s *authServiceImpl) ValidateCredentials(ctx context.Context, email, password string) (*domain.User, error) {
	// Get user by email using shared repository
	user, err := s.userRepo.GetByEmail(ctx, email)
	if err != nil {
		s.logger.Warn("User not found", "email", email)
		return nil, fmt.Errorf("invalid credentials")
	}

	// Check if user is active
	if user.Status != domain.UserStatusActive {
		s.logger.Warn("Inactive user login attempt", "user_id", user.ID, "status", user.Status)
		return nil, fmt.Errorf("account is not active")
	}

	// Check if account is locked
	if user.LockedUntil != nil && time.Now().Before(*user.LockedUntil) {
		s.logger.Warn("Locked account login attempt", "user_id", user.ID, "locked_until", user.LockedUntil)
		return nil, fmt.Errorf("account is locked")
	}

	// Verify password using auth service
	if !s.VerifyPassword(password, user.PasswordHash) {
		// Increment failed login attempts
		if err := s.userRepo.IncrementLoginAttempts(ctx, user.ID); err != nil {
			s.logger.Error("Failed to increment login attempts", "error", err, "user_id", user.ID)
		}

		// Check if we should lock the account
		if user.LoginAttempts+1 >= s.config.MaxLoginAttempts {
			lockUntil := time.Now().Add(s.config.LockoutDuration)
			if err := s.userRepo.LockUser(ctx, user.ID, &lockUntil); err != nil {
				s.logger.Error("Failed to lock user account", "error", err, "user_id", user.ID)
			} else {
				s.logger.Warn("User account locked due to failed login attempts", "user_id", user.ID, "locked_until", lockUntil)
			}
		}

		s.logger.Warn("Invalid password", "user_id", user.ID)
		return nil, fmt.Errorf("invalid credentials")
	}

	// Reset login attempts on successful authentication
	if err := s.userRepo.ResetLoginAttempts(ctx, user.ID); err != nil {
		s.logger.Error("Failed to reset login attempts", "error", err, "user_id", user.ID)
	}

	return user, nil
}

// HashPassword hashes a password using the service configuration
func (s *authServiceImpl) HashPassword(password string, algorithm ...PasswordHashAlgorithm) (string, error) {
	// Use configured algorithm or default
	algo := s.config.PasswordHashAlgorithm
	if len(algorithm) > 0 {
		algo = algorithm[0]
	}

	switch algo {
	case PasswordHashArgon2ID:
		// Create Argon2ID config from service config
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
		return "", fmt.Errorf("unsupported password hashing algorithm: %s", algo)
	}
}

// VerifyPassword verifies a password using the utils package
func (s *authServiceImpl) VerifyPassword(password, hash string, algorithm ...PasswordHashAlgorithm) bool {
	return utils.VerifyPassword(password, hash)
}

// UpdateLastLogin updates the user's last login timestamp
func (s *authServiceImpl) UpdateLastLogin(ctx context.Context, userID uuid.UUID, ipAddress string) error {
	// Update last login using shared repository
	return s.userRepo.UpdateLastLogin(ctx, userID, time.Now())
}

// RequestPasswordReset initiates a password reset request
func (s *authServiceImpl) RequestPasswordReset(ctx context.Context, req *dto.RequestPasswordResetRequest) (*dto.RequestPasswordResetResponse, error) {
	// Example implementation using shared repository
	user, err := s.userRepo.GetByEmail(ctx, req.Email)
	if err != nil {
		// Don't reveal if email exists for security
		return &dto.RequestPasswordResetResponse{
			Message:   "If the email exists, a password reset code has been sent",
			TokenSent: false,
		}, nil
	}

	// TODO: Generate reset token and send email
	s.logger.Info("Password reset requested", "user_id", user.ID, "email", req.Email)

	return &dto.RequestPasswordResetResponse{
		Message:   "Password reset code sent to your email",
		TokenSent: true,
	}, nil
}

// ConfirmPasswordReset confirms a password reset with token
func (s *authServiceImpl) ConfirmPasswordReset(ctx context.Context, req *dto.ConfirmPasswordResetRequest) (*dto.ConfirmPasswordResetResponse, error) {
	// TODO: Validate reset token

	// Hash new password using auth service
	hashedPassword, err := s.HashPassword(req.NewPassword)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Update password using shared repository
	// Note: This would need the user ID from the validated token
	// userID := getFromValidatedToken(req.Token)
	// err = s.userRepo.UpdatePassword(ctx, userID, hashedPassword)

	s.logger.Info("Password reset confirmed", "hashed_password_length", len(hashedPassword))

	return &dto.ConfirmPasswordResetResponse{
		Success: true,
		Message: "Password has been reset successfully",
	}, nil
}

// UpdatePassword updates a user's password
func (s *authServiceImpl) UpdatePassword(ctx context.Context, userID uuid.UUID, req *dto.UpdatePasswordRequest) (*dto.UpdatePasswordResponse, error) {
	// Get user to verify current password
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	// Verify current password using auth service
	if !s.VerifyPassword(req.CurrentPassword, user.PasswordHash) {
		return &dto.UpdatePasswordResponse{
			Success: false,
			Message: "Current password is incorrect",
		}, nil
	}

	// Hash new password using auth service
	hashedPassword, err := s.HashPassword(req.NewPassword)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Update password using shared repository
	if err := s.userRepo.UpdatePassword(ctx, userID, hashedPassword); err != nil {
		return nil, fmt.Errorf("failed to update password: %w", err)
	}

	s.logger.Info("Password updated successfully", "user_id", userID)

	return &dto.UpdatePasswordResponse{
		Success: true,
		Message: "Password updated successfully",
	}, nil
}

// EnableMFA enables MFA for a user
func (s *authServiceImpl) EnableMFA(ctx context.Context, userID uuid.UUID) (*dto.MFASetupResponse, error) {
	// Get user details for QR code generation
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Generate TOTP secret
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      s.config.JWTIssuer, // Use the configured issuer URL
		AccountName: user.Email,
		SecretSize:  32,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to generate TOTP key: %w", err)
	}

	secret := key.Secret()

	// Generate backup codes
	backupCodes, err := s.generateSecureBackupCodes(8) // Generate 8 backup codes
	if err != nil {
		return nil, fmt.Errorf("failed to generate backup codes: %w", err)
	}

	// Update MFA secret and backup codes using shared repository
	if err := s.userRepo.UpdateMFASecret(ctx, userID, secret); err != nil {
		return nil, fmt.Errorf("failed to enable MFA: %w", err)
	}

	if err := s.userRepo.UpdateBackupCodes(ctx, userID, backupCodes); err != nil {
		return nil, fmt.Errorf("failed to update backup codes: %w", err)
	}

	// Generate QR code URL
	qrCodeURL, err := s.generateQRCodeURL(user.Email, secret)
	if err != nil {
		return nil, fmt.Errorf("failed to generate QR code URL: %w", err)
	}

	s.logger.Info("MFA enabled for user", "user_id", userID)

	return &dto.MFASetupResponse{
		Secret:      secret,
		QRCodeURL:   qrCodeURL,
		BackupCodes: backupCodes,
	}, nil
}

// GenerateBackupCodes generates new backup codes for a user
func (s *authServiceImpl) GenerateBackupCodes(ctx context.Context, userID uuid.UUID) ([]string, error) {
	// Generate secure backup codes
	backupCodes, err := s.generateSecureBackupCodes(8) // Generate 8 backup codes
	if err != nil {
		return nil, fmt.Errorf("failed to generate backup codes: %w", err)
	}

	// Update backup codes using shared repository
	if err := s.userRepo.UpdateBackupCodes(ctx, userID, backupCodes); err != nil {
		return nil, fmt.Errorf("failed to update backup codes: %w", err)
	}

	s.logger.Info("Backup codes generated", "user_id", userID, "count", len(backupCodes))

	return backupCodes, nil
}

// IsAccountLocked checks if an account is currently locked
func (s *authServiceImpl) IsAccountLocked(ctx context.Context, userID uuid.UUID) (bool, error) {
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
func (s *authServiceImpl) UnlockAccount(ctx context.Context, userID uuid.UUID) error {
	if err := s.userRepo.UpdateLockedUntil(ctx, userID, nil); err != nil {
		return fmt.Errorf("failed to unlock account: %w", err)
	}

	if err := s.userRepo.UpdateLoginAttempts(ctx, userID, 0); err != nil {
		return fmt.Errorf("failed to reset login attempts: %w", err)
	}

	s.logger.Info("Account unlocked", "user_id", userID)
	return nil
}

// ValidateMFA validates a TOTP code or backup code
func (s *authServiceImpl) ValidateMFA(ctx context.Context, userID uuid.UUID, code string) (bool, error) {
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

// Helper methods

// GetAuthMode returns the current authentication mode
func (s *authServiceImpl) GetAuthMode() AuthMode {
	return s.config.Mode
}

// IsJWTMode returns true if the service is configured for JWT mode
func (s *authServiceImpl) IsJWTMode() bool {
	return s.config.Mode == AuthModeStateless
}

// IsSessionMode returns true if the service is configured for session mode
func (s *authServiceImpl) IsSessionMode() bool {
	return s.config.Mode == AuthModeStateful
}

// RecordFailedLogin records a failed login attempt
func (s *authServiceImpl) RecordFailedLogin(ctx context.Context, email, ipAddress string) error {
	user, err := s.userRepo.GetByEmail(ctx, email)
	if err != nil {
		// Don't reveal if email exists
		return nil
	}

	if err := s.userRepo.IncrementLoginAttempts(ctx, user.ID); err != nil {
		s.logger.Error("Failed to record failed login", "error", err, "user_id", user.ID)
		return err
	}

	return nil
}

// DisableMFA disables MFA for a user
func (s *authServiceImpl) DisableMFA(ctx context.Context, userID uuid.UUID) error {
	if err := s.userRepo.UpdateMFASecret(ctx, userID, ""); err != nil {
		return fmt.Errorf("failed to disable MFA: %w", err)
	}

	s.logger.Info("MFA disabled for user", "user_id", userID)
	return nil
}

func (s *authServiceImpl) generateSessionToken() (string, error) {
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", token), nil
}

func (s *authServiceImpl) mapUserToUserInfo(user *domain.User) dto.UserInfo {
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

func (s *authServiceImpl) mapSessionToSessionInfo(session *domain.Session) dto.SessionInfo {
	return dto.SessionInfo{
		ID:           session.ID,
		IPAddress:    session.IPAddress,
		UserAgent:    session.UserAgent,
		LastActivity: session.LastActivity,
		ExpiresAt:    session.ExpiresAt,
		CreatedAt:    session.CreatedAt,
	}
}

func (s *authServiceImpl) generateQRCodeURL(email, secret string) (string, error) {
	key, err := otp.NewKeyFromURL(fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s", s.config.JWTIssuer, email, secret, s.config.JWTIssuer))
	if err != nil {
		return "", err
	}
	return key.URL(), nil
}

// generateSecureBackupCodes generates cryptographically secure backup codes
func (s *authServiceImpl) generateSecureBackupCodes(count int) ([]string, error) {
	backupCodes := make([]string, count)

	for i := 0; i < count; i++ {
		// Generate 6-digit backup code
		codeBytes := make([]byte, 3) // 3 bytes = 24 bits, enough for 6 digits
		if _, err := rand.Read(codeBytes); err != nil {
			return nil, fmt.Errorf("failed to generate random bytes: %w", err)
		}

		// Convert to 6-digit number (000000-999999)
		codeNum := int(codeBytes[0])<<16 + int(codeBytes[1])<<8 + int(codeBytes[2])
		code := fmt.Sprintf("%06d", codeNum%1000000)
		backupCodes[i] = code
	}

	return backupCodes, nil
}

// RevokeJWT revokes a JWT token by adding it to the blacklist
func (s *authServiceImpl) RevokeJWT(ctx context.Context, token string) error {
	if !s.IsJWTMode() {
		return fmt.Errorf("JWT revocation not available in session mode")
	}

	if !s.config.JWTBlacklistEnabled || s.blacklistService == nil {
		return fmt.Errorf("JWT blacklist not enabled or service unavailable")
	}

	// Extract JTI from token
	jti, err := utils.ExtractJTIFromJWT(token)
	if err != nil {
		s.logger.Error("Failed to extract JTI from JWT", "error", err)
		return fmt.Errorf("failed to extract JTI from JWT: %w", err)
	}

	// Validate token to get expiration time
	claims, err := s.ValidateJWT(ctx, token)
	if err != nil {
		s.logger.Error("Failed to validate JWT for revocation", "error", err)
		return fmt.Errorf("failed to validate JWT: %w", err)
	}

	// Add to blacklist
	if err := s.blacklistService.AddToBlacklist(ctx, jti, claims.ExpiresAt.Time); err != nil {
		s.logger.Error("Failed to add JWT to blacklist", "jti", jti, "error", err)
		return fmt.Errorf("failed to add JWT to blacklist: %w", err)
	}

	s.logger.Info("JWT revoked successfully", "jti", jti)
	return nil
}
