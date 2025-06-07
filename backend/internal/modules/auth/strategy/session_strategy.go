package strategy

import (
	"context"
	"fmt"
	"time"

	"github.com/ducdt2000/azth/backend/internal/domain"
	"github.com/ducdt2000/azth/backend/internal/modules/auth/dto"
	authRepo "github.com/ducdt2000/azth/backend/internal/modules/auth/repository"
	permRepo "github.com/ducdt2000/azth/backend/internal/modules/permission/repository"
	roleRepo "github.com/ducdt2000/azth/backend/internal/modules/role/repository"
	userRepo "github.com/ducdt2000/azth/backend/internal/modules/user/repository"
	"github.com/ducdt2000/azth/backend/pkg/utils"
	"github.com/google/uuid"
)

// SessionStrategy implements session-based authentication
type SessionStrategy struct {
	sessionRepo authRepo.SessionRepository
	userRepo    userRepo.UserRepository
	roleRepo    roleRepo.RoleRepository
	permRepo    permRepo.PermissionRepository
	config      *SessionConfig
}

// SessionConfig holds session strategy configuration
type SessionConfig struct {
	SessionTTL     time.Duration `json:"session_ttl" yaml:"session_ttl"`
	RefreshTTL     time.Duration `json:"refresh_ttl" yaml:"refresh_ttl"`
	MaxSessions    int           `json:"max_sessions" yaml:"max_sessions"`
	CheckIPChange  bool          `json:"check_ip_change" yaml:"check_ip_change"`
	CheckUserAgent bool          `json:"check_user_agent" yaml:"check_user_agent"`
}

// NewSessionStrategy creates a new session strategy
func NewSessionStrategy(
	sessionRepo authRepo.SessionRepository,
	userRepo userRepo.UserRepository,
	roleRepo roleRepo.RoleRepository,
	permRepo permRepo.PermissionRepository,
	config *SessionConfig,
) *SessionStrategy {
	if config == nil {
		config = &SessionConfig{
			SessionTTL:     24 * time.Hour,
			RefreshTTL:     7 * 24 * time.Hour,
			MaxSessions:    5,
			CheckIPChange:  true,
			CheckUserAgent: false,
		}
	}

	return &SessionStrategy{
		sessionRepo: sessionRepo,
		userRepo:    userRepo,
		roleRepo:    roleRepo,
		permRepo:    permRepo,
		config:      config,
	}
}

// Authenticate creates a new session for the user
func (s *SessionStrategy) Authenticate(ctx context.Context, req *dto.LoginRequest, user *domain.User) (*dto.LoginResponse, error) {
	// Generate session token
	sessionToken, err := utils.GenerateSecureToken(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate session token: %w", err)
	}

	// Generate refresh token
	refreshToken, err := utils.GenerateSecureToken(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// Create session using domain.Session (not AuthSession)
	session := &domain.Session{
		ID:           uuid.New(),
		UserID:       user.ID,
		TenantID:     user.TenantID,
		Token:        sessionToken,
		RefreshToken: refreshToken,
		IPAddress:    req.IPAddress,
		UserAgent:    req.UserAgent,
		LastActivity: time.Now(),
		ExpiresAt:    time.Now().Add(s.config.SessionTTL),
		Revoked:      false,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	// Check session limits
	if s.config.MaxSessions > 0 {
		activeSessions, err := s.sessionRepo.GetByUserID(ctx, user.ID)
		if err != nil {
			return nil, fmt.Errorf("failed to get active sessions: %w", err)
		}

		// Filter for non-revoked sessions
		activeCount := 0
		for _, sess := range activeSessions {
			if !sess.Revoked && time.Now().Before(sess.ExpiresAt) {
				activeCount++
			}
		}

		if activeCount >= s.config.MaxSessions {
			// Remove oldest session
			var oldestSession *domain.Session
			for _, sess := range activeSessions {
				if !sess.Revoked && time.Now().Before(sess.ExpiresAt) {
					if oldestSession == nil || sess.LastActivity.Before(oldestSession.LastActivity) {
						oldestSession = sess
					}
				}
			}
			if oldestSession != nil {
				if err := s.sessionRepo.RevokeByID(ctx, oldestSession.ID, "session_limit_exceeded"); err != nil {
					return nil, fmt.Errorf("failed to revoke old session: %w", err)
				}
			}
		}
	}

	// Save session
	if err := s.sessionRepo.Create(ctx, session); err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	// Get user roles - using GetUserRoles which returns UserRoles with Role information
	userRoles, err := s.userRepo.GetUserRoles(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}

	// Extract role names from UserRole relationships
	roleNames := make([]string, 0)
	for _, userRole := range userRoles {
		// Get the role details
		role, err := s.roleRepo.GetByID(ctx, userRole.RoleID)
		if err == nil && role != nil {
			roleNames = append(roleNames, role.Name)
		}
	}

	// Get user permissions through their roles
	permissions := make([]*domain.Permission, 0)
	for _, userRole := range userRoles {
		rolePermissions, err := s.permRepo.GetPermissionsByIDs(ctx, []uuid.UUID{userRole.RoleID})
		if err == nil {
			permissions = append(permissions, rolePermissions...)
		}
	}

	// Convert permissions to strings
	permNames := make([]string, len(permissions))
	for i, perm := range permissions {
		permNames[i] = perm.Name
	}

	return &dto.LoginResponse{
		AccessToken:  sessionToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(s.config.SessionTTL.Seconds()),
		TokenType:    "Bearer",
		User: dto.UserInfo{
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
		},
		Session: &dto.SessionInfo{
			ID:           session.ID,
			IPAddress:    session.IPAddress,
			UserAgent:    session.UserAgent,
			LastActivity: session.LastActivity,
			ExpiresAt:    session.ExpiresAt,
			CreatedAt:    session.CreatedAt,
		},
	}, nil
}

// ValidateToken validates a session token
func (s *SessionStrategy) ValidateToken(ctx context.Context, token string) (*AuthContext, error) {
	// Get session by token
	session, err := s.sessionRepo.GetByToken(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("invalid session token: %w", err)
	}

	// Check if session is revoked
	if session.Revoked {
		return nil, fmt.Errorf("session has been revoked")
	}

	// Check if session is expired
	if time.Now().After(session.ExpiresAt) {
		// Clean up expired session
		_ = s.sessionRepo.RevokeByID(ctx, session.ID, "expired")
		return nil, fmt.Errorf("session expired")
	}

	// Get user
	user, err := s.userRepo.GetByID(ctx, session.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Check if user is active
	if user.Status != domain.UserStatusActive {
		return nil, fmt.Errorf("user account is not active")
	}

	// Get user roles
	userRoles, err := s.userRepo.GetUserRoles(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}

	// Extract role names
	roleNames := make([]string, 0)
	for _, userRole := range userRoles {
		role, err := s.roleRepo.GetByID(ctx, userRole.RoleID)
		if err == nil && role != nil {
			roleNames = append(roleNames, role.Name)
		}
	}

	// Get user permissions through their roles
	permissions := make([]*domain.Permission, 0)
	for _, userRole := range userRoles {
		rolePermissions, err := s.permRepo.GetPermissionsByIDs(ctx, []uuid.UUID{userRole.RoleID})
		if err == nil {
			permissions = append(permissions, rolePermissions...)
		}
	}

	// Convert permissions to strings
	permNames := make([]string, len(permissions))
	for i, perm := range permissions {
		permNames[i] = perm.Name
	}

	// Update last activity
	_ = s.sessionRepo.UpdateLastActivity(ctx, session.ID, time.Now())

	return &AuthContext{
		UserID:      user.ID,
		TenantID:    user.TenantID,
		Email:       user.Email,
		Username:    user.Username,
		Roles:       roleNames,
		Permissions: permNames,
		IPAddress:   session.IPAddress,
		UserAgent:   session.UserAgent,
		ExpiresAt:   session.ExpiresAt,
		TokenType:   "session",
		SessionID:   &session.ID,
	}, nil
}

// RefreshToken refreshes a session token
func (s *SessionStrategy) RefreshToken(ctx context.Context, refreshToken string) (*dto.RefreshResponse, error) {
	// Get session by refresh token
	session, err := s.sessionRepo.GetByToken(ctx, refreshToken)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token: %w", err)
	}

	// Check if session is revoked
	if session.Revoked {
		return nil, fmt.Errorf("refresh token has been revoked")
	}

	// Check if session is expired
	if time.Now().After(session.ExpiresAt) {
		// Clean up expired session
		_ = s.sessionRepo.RevokeByID(ctx, session.ID, "expired")
		return nil, fmt.Errorf("refresh token expired")
	}

	// Generate new session token
	newSessionToken, err := utils.GenerateSecureToken(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate new session token: %w", err)
	}

	// Update session
	session.Token = newSessionToken
	session.ExpiresAt = time.Now().Add(s.config.SessionTTL)
	session.LastActivity = time.Now()
	session.UpdatedAt = time.Now()

	if err := s.sessionRepo.Update(ctx, session); err != nil {
		return nil, fmt.Errorf("failed to update session: %w", err)
	}

	return &dto.RefreshResponse{
		AccessToken:  newSessionToken,
		RefreshToken: refreshToken, // Keep the same refresh token
		ExpiresIn:    int64(s.config.SessionTTL.Seconds()),
		TokenType:    "Bearer",
		ExpiresAt:    session.ExpiresAt,
	}, nil
}

// RevokeToken revokes a session token
func (s *SessionStrategy) RevokeToken(ctx context.Context, token string) error {
	// Get session by token
	session, err := s.sessionRepo.GetByToken(ctx, token)
	if err != nil {
		return fmt.Errorf("invalid session token: %w", err)
	}

	// Revoke session
	if err := s.sessionRepo.RevokeByID(ctx, session.ID, "user_logout"); err != nil {
		return fmt.Errorf("failed to revoke session: %w", err)
	}

	return nil
}

// RevokeAllTokens revokes all tokens for a user
func (s *SessionStrategy) RevokeAllTokens(ctx context.Context, userID uuid.UUID) error {
	// Revoke all sessions for user
	if err := s.sessionRepo.RevokeByUserID(ctx, userID, "user_logout_all"); err != nil {
		return fmt.Errorf("failed to revoke user sessions: %w", err)
	}

	return nil
}

// GetStrategyType returns the strategy type
func (s *SessionStrategy) GetStrategyType() StrategyType {
	return StrategyTypeSession
}
