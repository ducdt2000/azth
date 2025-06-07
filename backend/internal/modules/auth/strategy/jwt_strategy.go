package strategy

import (
	"context"
	"fmt"
	"time"

	"github.com/ducdt2000/azth/backend/internal/domain"
	"github.com/ducdt2000/azth/backend/internal/modules/auth/dto"
	roleSvc "github.com/ducdt2000/azth/backend/internal/modules/role/service"
	userRepo "github.com/ducdt2000/azth/backend/internal/modules/user/repository"
	"github.com/ducdt2000/azth/backend/pkg/logger"
	"github.com/ducdt2000/azth/backend/pkg/utils"
	"github.com/google/uuid"
)

// JWTStrategy implements authentication using JWT tokens
type JWTStrategy struct {
	userRepo    userRepo.UserRepository
	roleService roleSvc.RoleService
	logger      *logger.Logger
	config      *JWTConfig
}

// JWTConfig holds JWT-specific configuration
type JWTConfig struct {
	Secret           string
	AccessTokenTTL   time.Duration
	RefreshTokenTTL  time.Duration
	Issuer           string
	Audience         string
	SigningAlgorithm string // e.g., "HS256", "RS256"
	Algorithms       []string
	ValidateIssuer   bool
	ValidateIAT      bool
}

// NewJWTStrategy creates a new JWT authentication strategy
func NewJWTStrategy(
	userRepo userRepo.UserRepository,
	roleService roleSvc.RoleService,
	logger *logger.Logger,
	config *JWTConfig,
) *JWTStrategy {
	return &JWTStrategy{
		userRepo:    userRepo,
		roleService: roleService,
		logger:      logger,
		config:      config,
	}
}

// Authenticate creates JWT tokens for the user
func (j *JWTStrategy) Authenticate(ctx context.Context, req *dto.LoginRequest, user *domain.User) (*dto.LoginResponse, error) {
	// Create JWT config
	jwtConfig := &utils.JWTConfig{
		Secret:           j.config.Secret,
		Issuer:           j.config.Issuer,
		Audience:         j.config.Audience,
		AccessTokenTTL:   j.config.AccessTokenTTL,
		RefreshTokenTTL:  j.config.RefreshTokenTTL,
		SigningAlgorithm: j.config.SigningAlgorithm,
		Algorithms:       j.config.Algorithms,
		ValidateIssuer:   j.config.ValidateIssuer,
		ValidateIAT:      j.config.ValidateIAT,
	}

	// Get user roles
	userRoles, err := j.roleService.GetUserRoles(ctx, user.ID, user.TenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}
	roleSlugs := make([]string, len(userRoles))
	for i, ur := range userRoles {
		roleSlugs[i] = ur.Role.Slug
	}

	// Get user permissions
	permissions, err := j.roleService.GetUserPermissions(ctx, user.ID, user.TenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user permissions: %w", err)
	}
	permissionCodes := make([]string, len(permissions))
	for i, p := range permissions {
		permissionCodes[i] = p.Code
	}

	// Generate access token
	accessToken, err := utils.GenerateAccessToken(
		jwtConfig,
		user.ID,
		user.TenantID,
		user.Email,
		user.Username,
		roleSlugs,
		permissionCodes,
		req.IPAddress,
		req.UserAgent,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	// Generate refresh token
	refreshToken, err := utils.GenerateRefreshToken(
		jwtConfig,
		user.ID,
		user.TenantID,
		user.Email,
		user.Username,
		req.IPAddress,
		req.UserAgent,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	return &dto.LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(j.config.AccessTokenTTL.Seconds()),
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(j.config.AccessTokenTTL),
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
		Session:     nil, // No session in JWT mode
		RequiresMFA: false,
	}, nil
}

// ValidateToken validates a JWT token
func (j *JWTStrategy) ValidateToken(ctx context.Context, token string) (*AuthContext, error) {
	// Create JWT config
	jwtConfig := &utils.JWTConfig{
		Secret:         j.config.Secret,
		Issuer:         j.config.Issuer,
		Audience:       j.config.Audience,
		Algorithms:     j.config.Algorithms,
		ValidateIssuer: j.config.ValidateIssuer,
		ValidateIAT:    j.config.ValidateIAT,
	}

	// Validate token
	claims, err := utils.ValidateJWT(jwtConfig, token)
	if err != nil {
		return nil, fmt.Errorf("invalid JWT token: %w", err)
	}

	// Get user to verify they still exist and are active
	user, err := j.userRepo.GetByID(ctx, claims.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Check if user is active
	if user.Status != domain.UserStatusActive {
		return nil, fmt.Errorf("user account is not active")
	}

	// Get user roles
	userRoles, err := j.roleService.GetUserRoles(ctx, user.ID, user.TenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}

	// Extract role names
	roleNames := make([]string, 0)
	for _, userRole := range userRoles {
		roleNames = append(roleNames, userRole.Role.Name)
	}

	// Get user permissions
	permissions, err := j.roleService.GetUserPermissions(ctx, claims.UserID, claims.TenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user permissions: %w", err)
	}

	// Convert permissions to strings
	permNames := make([]string, len(permissions))
	for i, perm := range permissions {
		permNames[i] = perm.Name
	}

	return &AuthContext{
		UserID:      claims.UserID,
		TenantID:    claims.TenantID,
		Email:       claims.Email,
		Username:    claims.Username,
		Roles:       roleNames,
		Permissions: permNames,
		IPAddress:   claims.IPAddress,
		UserAgent:   claims.UserAgent,
		ExpiresAt:   claims.ExpiresAt.Time,
		TokenType:   "jwt",
		SessionID:   nil, // No session in JWT mode
	}, nil
}

// RefreshToken refreshes a JWT token
func (j *JWTStrategy) RefreshToken(ctx context.Context, refreshToken string) (*dto.RefreshResponse, error) {
	// Create JWT config
	jwtConfig := &utils.JWTConfig{
		Secret:         j.config.Secret,
		Issuer:         j.config.Issuer,
		Audience:       j.config.Audience,
		Algorithms:     j.config.Algorithms,
		ValidateIssuer: j.config.ValidateIssuer,
		ValidateIAT:    j.config.ValidateIAT,
	}

	// Validate refresh token
	claims, err := utils.ValidateJWT(jwtConfig, refreshToken)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token: %w", err)
	}

	// Check if it's a refresh token
	if claims.TokenType != utils.TokenTypeRefresh {
		return nil, fmt.Errorf("invalid token type: expected refresh token")
	}

	// Get user to verify they still exist and are active
	user, err := j.userRepo.GetByID(ctx, claims.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Check if user is active
	if user.Status != domain.UserStatusActive {
		return nil, fmt.Errorf("user account is not active")
	}

	// Get user roles
	userRoles, err := j.roleService.GetUserRoles(ctx, user.ID, claims.TenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}
	roleSlugs := make([]string, len(userRoles))
	for i, ur := range userRoles {
		roleSlugs[i] = ur.Role.Slug
	}

	// Get user permissions
	permissions, err := j.roleService.GetUserPermissions(ctx, claims.UserID, claims.TenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user permissions: %w", err)
	}
	permissionCodes := make([]string, len(permissions))
	for i, p := range permissions {
		permissionCodes[i] = p.Code
	}

	// Generate new access token
	newAccessToken, err := utils.GenerateAccessToken(
		jwtConfig,
		claims.UserID,
		claims.TenantID,
		claims.Email,
		claims.Username,
		roleSlugs,
		permissionCodes,
		claims.IPAddress,
		claims.UserAgent,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate new access token: %w", err)
	}

	// Generate new refresh token
	newRefreshToken, err := utils.GenerateRefreshToken(
		jwtConfig,
		claims.UserID,
		claims.TenantID,
		claims.Email,
		claims.Username,
		claims.IPAddress,
		claims.UserAgent,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate new refresh token: %w", err)
	}

	return &dto.RefreshResponse{
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
		ExpiresIn:    int64(j.config.AccessTokenTTL.Seconds()),
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(j.config.AccessTokenTTL),
	}, nil
}

// RevokeToken revokes a JWT token (in practice, JWT tokens can't be revoked without a blacklist)
func (j *JWTStrategy) RevokeToken(ctx context.Context, token string) error {
	// JWT tokens are stateless and cannot be revoked without implementing a token blacklist
	// In production, you would want to implement a redis-based blacklist or similar mechanism
	// For now, we'll just return success as this is mainly used for logout
	return nil
}

// RevokeAllTokens revokes all tokens for a user (for JWT, this is typically handled by changing user credentials)
func (j *JWTStrategy) RevokeAllTokens(ctx context.Context, userID uuid.UUID) error {
	// JWT tokens are stateless and cannot be revoked without implementing a token blacklist
	// In production, you might implement this by:
	// 1. Adding user ID to a blacklist until all current tokens expire
	// 2. Changing the user's secret/salt to invalidate existing tokens
	// 3. Implementing a global token blacklist
	// For now, we'll just return success
	return nil
}

// GetStrategyType returns the strategy type
func (j *JWTStrategy) GetStrategyType() StrategyType {
	return StrategyTypeJWT
}
