package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ducdt2000/azth/backend/internal/kv"
	authSvc "github.com/ducdt2000/azth/backend/internal/modules/auth/service"
	"github.com/ducdt2000/azth/backend/internal/modules/auth/strategy"
	roleSvc "github.com/ducdt2000/azth/backend/internal/modules/role/service"
	"github.com/ducdt2000/azth/backend/pkg/logger"
	"github.com/ducdt2000/azth/backend/pkg/utils"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

const (
	// Cache keys for performance
	UserPermissionsCacheKey = "user:permissions:%s:%s" // user_id:tenant_id
	UserRolesCacheKey       = "user:roles:%s:%s"       // user_id:tenant_id
	SessionDataCacheKey     = "session:data:%s"        // session_token
	JWTBlacklistKey         = "jwt:blacklist:%s"       // jwt_jti
	RefreshTokenKey         = "refresh:token:%s"       // refresh_token

	// Cache TTL
	PermissionsCacheTTL = 5 * time.Minute
	RolesCacheTTL       = 5 * time.Minute
	SessionCacheTTL     = 30 * time.Minute
	JWTBlacklistTTL     = 24 * time.Hour
)

var enhancedTracer = otel.Tracer("enhanced-auth-middleware")

// EnhancedAuthMiddleware provides comprehensive authentication and authorization
type EnhancedAuthMiddleware struct {
	authService authSvc.AuthService
	roleService roleSvc.RoleService
	kvStore     kv.KVStore
	logger      *logger.Logger
}

// NewEnhancedAuthMiddleware creates a new enhanced authentication middleware
func NewEnhancedAuthMiddleware(
	authService authSvc.AuthService,
	roleService roleSvc.RoleService,
	kvStore kv.KVStore,
	logger *logger.Logger,
) *EnhancedAuthMiddleware {
	return &EnhancedAuthMiddleware{
		authService: authService,
		roleService: roleService,
		kvStore:     kvStore,
		logger:      logger,
	}
}

// AuthConfig holds authentication configuration for middleware
type AuthConfig struct {
	Required            bool     `json:"required"`
	RequiredRoles       []string `json:"required_roles"`
	RequiredPermissions []string `json:"required_permissions"`
	AllowOwnership      bool     `json:"allow_ownership"`
	ResourceIDParam     string   `json:"resource_id_param"`
	TenantIDParam       string   `json:"tenant_id_param"`
	CacheEnabled        bool     `json:"cache_enabled"`
	RequireAll          bool     `json:"require_all"` // true=AND, false=OR
}

// AuthWithConfig creates middleware with custom configuration
func (m *EnhancedAuthMiddleware) AuthWithConfig(config AuthConfig) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			ctx, span := enhancedTracer.Start(c.Request().Context(), "EnhancedAuthMiddleware.AuthWithConfig")
			defer span.End()

			// Extract and validate token
			authCtx, err := m.authenticateRequest(ctx, c)
			if err != nil {
				if config.Required {
					return m.handleAuthError(c, err)
				}
				// Optional auth failed, continue without auth context
				return next(c)
			}

			// Set auth context in Echo context
			c.Set("auth_context", authCtx)
			c.Set("user_id", authCtx.UserID.String())
			c.Set("tenant_id", authCtx.TenantID.String())

			span.SetAttributes(
				attribute.String("user.id", authCtx.UserID.String()),
				attribute.String("tenant.id", authCtx.TenantID.String()),
				attribute.String("token.type", authCtx.TokenType),
			)

			// Check role requirements
			if len(config.RequiredRoles) > 0 {
				if err := m.checkRoleRequirements(ctx, authCtx, config.RequiredRoles, config.RequireAll); err != nil {
					m.logger.Warn("Role check failed", "user_id", authCtx.UserID, "required_roles", config.RequiredRoles, "error", err)
					return echo.NewHTTPError(http.StatusForbidden, fmt.Sprintf("Required roles: %s", strings.Join(config.RequiredRoles, ", ")))
				}
			}

			// Check permission requirements
			if len(config.RequiredPermissions) > 0 {
				if err := m.checkPermissionRequirements(ctx, authCtx, config.RequiredPermissions, config.RequireAll); err != nil {
					m.logger.Warn("Permission check failed", "user_id", authCtx.UserID, "required_permissions", config.RequiredPermissions, "error", err)
					return echo.NewHTTPError(http.StatusForbidden, fmt.Sprintf("Required permissions: %s", strings.Join(config.RequiredPermissions, ", ")))
				}
			}

			// Check tenant access
			if config.TenantIDParam != "" {
				requestedTenantID := m.extractTenantID(c, config.TenantIDParam)
				if requestedTenantID != nil && *requestedTenantID != authCtx.TenantID {
					m.logger.Warn("Tenant access denied", "user_id", authCtx.UserID, "user_tenant", authCtx.TenantID, "requested_tenant", *requestedTenantID)
					return echo.NewHTTPError(http.StatusForbidden, "Access denied for this tenant")
				}
			}

			return next(c)
		}
	}
}

// RequireAuth creates middleware that requires authentication
func (m *EnhancedAuthMiddleware) RequireAuth() echo.MiddlewareFunc {
	return m.AuthWithConfig(AuthConfig{Required: true, CacheEnabled: true})
}

// OptionalAuth creates middleware that optionally extracts auth info
func (m *EnhancedAuthMiddleware) OptionalAuth() echo.MiddlewareFunc {
	return m.AuthWithConfig(AuthConfig{Required: false, CacheEnabled: true})
}

// RequireRole creates middleware that requires specific roles
func (m *EnhancedAuthMiddleware) RequireRole(roles ...string) echo.MiddlewareFunc {
	return m.AuthWithConfig(AuthConfig{
		Required:      true,
		RequiredRoles: roles,
		CacheEnabled:  true,
		RequireAll:    false, // OR logic by default
	})
}

// RequireAllRoles creates middleware that requires ALL specified roles
func (m *EnhancedAuthMiddleware) RequireAllRoles(roles ...string) echo.MiddlewareFunc {
	return m.AuthWithConfig(AuthConfig{
		Required:      true,
		RequiredRoles: roles,
		CacheEnabled:  true,
		RequireAll:    true, // AND logic
	})
}

// RequirePermission creates middleware that requires specific permissions
func (m *EnhancedAuthMiddleware) RequirePermission(permissions ...string) echo.MiddlewareFunc {
	return m.AuthWithConfig(AuthConfig{
		Required:            true,
		RequiredPermissions: permissions,
		CacheEnabled:        true,
		RequireAll:          false, // OR logic by default
	})
}

// RequireAllPermissions creates middleware that requires ALL specified permissions
func (m *EnhancedAuthMiddleware) RequireAllPermissions(permissions ...string) echo.MiddlewareFunc {
	return m.AuthWithConfig(AuthConfig{
		Required:            true,
		RequiredPermissions: permissions,
		CacheEnabled:        true,
		RequireAll:          true, // AND logic
	})
}

// RequireTenantAccess creates middleware that validates tenant access
func (m *EnhancedAuthMiddleware) RequireTenantAccess(tenantIDParam string) echo.MiddlewareFunc {
	return m.AuthWithConfig(AuthConfig{
		Required:      true,
		TenantIDParam: tenantIDParam,
		CacheEnabled:  true,
	})
}

// authenticateRequest extracts and validates authentication from request
func (m *EnhancedAuthMiddleware) authenticateRequest(ctx context.Context, c echo.Context) (*strategy.AuthContext, error) {
	ctx, span := enhancedTracer.Start(ctx, "EnhancedAuthMiddleware.authenticateRequest")
	defer span.End()

	token := m.extractToken(c)
	if token == "" {
		return nil, fmt.Errorf("no authentication token provided")
	}

	// Handle different authentication modes
	if m.authService.IsJWTMode() {
		return m.validateJWTWithKV(ctx, token)
	} else {
		return m.validateSessionWithKV(ctx, token)
	}
}

// validateJWTWithKV validates JWT token with KV store optimizations
func (m *EnhancedAuthMiddleware) validateJWTWithKV(ctx context.Context, token string) (*strategy.AuthContext, error) {
	ctx, span := enhancedTracer.Start(ctx, "EnhancedAuthMiddleware.validateJWTWithKV")
	defer span.End()

	// Parse JWT to get JTI for blacklist check
	jti, err := utils.ExtractJTIFromJWT(token)
	if err != nil {
		return nil, fmt.Errorf("failed to extract JTI from JWT: %w", err)
	}

	// Check JWT blacklist in KV store
	blacklistKey := fmt.Sprintf(JWTBlacklistKey, jti)
	isBlacklisted, err := m.kvStore.Exists(ctx, blacklistKey)
	if err != nil {
		m.logger.Warn("Failed to check JWT blacklist", "jti", jti, "error", err)
		// Continue validation even if blacklist check fails
	} else if isBlacklisted {
		return nil, fmt.Errorf("JWT token has been revoked")
	}

	// Validate JWT - this returns *dto.JWTClaims, convert to AuthContext
	claims, err := m.authService.ValidateJWT(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("JWT validation failed: %w", err)
	}

	// Convert JWTClaims to AuthContext
	authCtx := &strategy.AuthContext{
		UserID:    claims.UserID,
		TenantID:  claims.TenantID,
		Email:     claims.Email,
		Username:  claims.Username,
		IPAddress: claims.IPAddress,
		UserAgent: claims.UserAgent,
		ExpiresAt: claims.ExpiresAt.Time,
		TokenType: "jwt",
		SessionID: nil, // No session in JWT mode
	}

	// Enhance auth context with cached roles and permissions
	if err := m.enhanceAuthContextWithCache(ctx, authCtx); err != nil {
		m.logger.Warn("Failed to enhance auth context with cache", "user_id", authCtx.UserID, "error", err)
		// Continue without cache enhancement
	}

	span.SetAttributes(
		attribute.String("auth.type", "jwt"),
		attribute.String("user.id", authCtx.UserID.String()),
		attribute.String("jwt.jti", jti),
	)

	return authCtx, nil
}

// validateSessionWithKV validates session token with KV store optimizations
func (m *EnhancedAuthMiddleware) validateSessionWithKV(ctx context.Context, token string) (*strategy.AuthContext, error) {
	ctx, span := enhancedTracer.Start(ctx, "EnhancedAuthMiddleware.validateSessionWithKV")
	defer span.End()

	// Try to get session data from cache first
	cacheKey := fmt.Sprintf(SessionDataCacheKey, token)
	cachedData, err := m.kvStore.Get(ctx, cacheKey)
	if err == nil && cachedData != "" {
		var authCtx strategy.AuthContext
		if err := json.Unmarshal([]byte(cachedData), &authCtx); err == nil {
			span.SetAttributes(
				attribute.String("auth.type", "session"),
				attribute.String("user.id", authCtx.UserID.String()),
				attribute.Bool("cache.hit", true),
			)
			return &authCtx, nil
		}
	}

	// Cache miss, validate session normally - this returns *domain.Session, convert to AuthContext
	session, err := m.authService.ValidateSession(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("session validation failed: %w", err)
	}

	// Convert Session to AuthContext
	authCtx := &strategy.AuthContext{
		UserID:    session.UserID,
		TenantID:  session.TenantID,
		Email:     "", // Will be filled by enhancement
		Username:  "", // Will be filled by enhancement
		IPAddress: session.IPAddress,
		UserAgent: session.UserAgent,
		ExpiresAt: session.ExpiresAt,
		TokenType: "session",
		SessionID: &session.ID,
	}

	// Enhance auth context with roles and permissions
	if err := m.enhanceAuthContextWithCache(ctx, authCtx); err != nil {
		m.logger.Warn("Failed to enhance auth context", "user_id", authCtx.UserID, "error", err)
	}

	// Cache the session data
	if authCtxJSON, err := json.Marshal(authCtx); err == nil {
		if err := m.kvStore.Set(ctx, cacheKey, string(authCtxJSON), SessionCacheTTL); err != nil {
			m.logger.Warn("Failed to cache session data", "token", token[:8]+"...", "error", err)
		}
	}

	span.SetAttributes(
		attribute.String("auth.type", "session"),
		attribute.String("user.id", authCtx.UserID.String()),
		attribute.Bool("cache.hit", false),
	)

	return authCtx, nil
}

// enhanceAuthContextWithCache enhances auth context with cached roles and permissions
func (m *EnhancedAuthMiddleware) enhanceAuthContextWithCache(ctx context.Context, authCtx *strategy.AuthContext) error {
	ctx, span := enhancedTracer.Start(ctx, "EnhancedAuthMiddleware.enhanceAuthContextWithCache")
	defer span.End()

	// Get cached roles
	rolesCacheKey := fmt.Sprintf(UserRolesCacheKey, authCtx.UserID.String(), authCtx.TenantID.String())
	cachedRoles, err := m.kvStore.Get(ctx, rolesCacheKey)
	if err == nil && cachedRoles != "" {
		var roles []string
		if err := json.Unmarshal([]byte(cachedRoles), &roles); err == nil {
			authCtx.Roles = roles
		}
	} else {
		// Cache miss, fetch from database
		roles, err := m.fetchUserRoles(ctx, authCtx.UserID, authCtx.TenantID)
		if err == nil {
			authCtx.Roles = roles
			// Cache the roles
			if rolesJSON, err := json.Marshal(roles); err == nil {
				m.kvStore.Set(ctx, rolesCacheKey, string(rolesJSON), RolesCacheTTL)
			}
		}
	}

	// Get cached permissions
	permsCacheKey := fmt.Sprintf(UserPermissionsCacheKey, authCtx.UserID.String(), authCtx.TenantID.String())
	cachedPerms, err := m.kvStore.Get(ctx, permsCacheKey)
	if err == nil && cachedPerms != "" {
		var permissions []string
		if err := json.Unmarshal([]byte(cachedPerms), &permissions); err == nil {
			authCtx.Permissions = permissions
		}
	} else {
		// Cache miss, fetch from database
		permissions, err := m.fetchUserPermissions(ctx, authCtx.UserID, authCtx.TenantID)
		if err == nil {
			authCtx.Permissions = permissions
			// Cache the permissions
			if permsJSON, err := json.Marshal(permissions); err == nil {
				m.kvStore.Set(ctx, permsCacheKey, string(permsJSON), PermissionsCacheTTL)
			}
		}
	}

	return nil
}

// fetchUserRoles fetches user roles from database
func (m *EnhancedAuthMiddleware) fetchUserRoles(ctx context.Context, userID, tenantID uuid.UUID) ([]string, error) {
	userRoles, err := m.roleService.GetUserRoles(ctx, userID, tenantID)
	if err != nil {
		return nil, err
	}

	roleNames := make([]string, 0, len(userRoles))
	for _, userRole := range userRoles {
		if userRole.Role != nil {
			roleNames = append(roleNames, userRole.Role.Name)
		}
	}

	return roleNames, nil
}

// fetchUserPermissions fetches user permissions from database
func (m *EnhancedAuthMiddleware) fetchUserPermissions(ctx context.Context, userID, tenantID uuid.UUID) ([]string, error) {
	permissions, err := m.roleService.GetUserPermissions(ctx, userID, tenantID)
	if err != nil {
		return nil, err
	}

	permissionCodes := make([]string, len(permissions))
	for i, perm := range permissions {
		permissionCodes[i] = perm.Code
	}

	return permissionCodes, nil
}

// checkRoleRequirements checks if user has required roles
func (m *EnhancedAuthMiddleware) checkRoleRequirements(ctx context.Context, authCtx *strategy.AuthContext, requiredRoles []string, requireAll bool) error {
	if requireAll {
		return m.hasAllRoles(authCtx.Roles, requiredRoles)
	}
	return m.hasAnyRole(authCtx.Roles, requiredRoles)
}

// checkPermissionRequirements checks if user has required permissions
func (m *EnhancedAuthMiddleware) checkPermissionRequirements(ctx context.Context, authCtx *strategy.AuthContext, requiredPermissions []string, requireAll bool) error {
	if requireAll {
		return m.hasAllPermissions(authCtx.Permissions, requiredPermissions)
	}
	return m.hasAnyPermission(authCtx.Permissions, requiredPermissions)
}

// hasAnyRole checks if user has any of the required roles
func (m *EnhancedAuthMiddleware) hasAnyRole(userRoles, requiredRoles []string) error {
	roleSet := make(map[string]bool)
	for _, role := range userRoles {
		roleSet[role] = true
	}

	for _, required := range requiredRoles {
		if roleSet[required] {
			return nil
		}
	}

	return fmt.Errorf("user lacks required roles")
}

// hasAllRoles checks if user has all required roles
func (m *EnhancedAuthMiddleware) hasAllRoles(userRoles, requiredRoles []string) error {
	roleSet := make(map[string]bool)
	for _, role := range userRoles {
		roleSet[role] = true
	}

	for _, required := range requiredRoles {
		if !roleSet[required] {
			return fmt.Errorf("user lacks required role: %s", required)
		}
	}

	return nil
}

// hasAnyPermission checks if user has any of the required permissions
func (m *EnhancedAuthMiddleware) hasAnyPermission(userPermissions, requiredPermissions []string) error {
	permSet := make(map[string]bool)
	for _, perm := range userPermissions {
		permSet[perm] = true
	}

	for _, required := range requiredPermissions {
		if permSet[required] || m.matchesWildcard(userPermissions, required) {
			return nil
		}
	}

	return fmt.Errorf("user lacks required permissions")
}

// hasAllPermissions checks if user has all required permissions
func (m *EnhancedAuthMiddleware) hasAllPermissions(userPermissions, requiredPermissions []string) error {
	permSet := make(map[string]bool)
	for _, perm := range userPermissions {
		permSet[perm] = true
	}

	for _, required := range requiredPermissions {
		if !permSet[required] && !m.matchesWildcard(userPermissions, required) {
			return fmt.Errorf("user lacks required permission: %s", required)
		}
	}

	return nil
}

// matchesWildcard checks if any user permission matches the required permission with wildcards
func (m *EnhancedAuthMiddleware) matchesWildcard(userPermissions []string, required string) bool {
	for _, userPerm := range userPermissions {
		if strings.HasSuffix(userPerm, "*") {
			prefix := userPerm[:len(userPerm)-1]
			if strings.HasPrefix(required, prefix) {
				return true
			}
		}
	}
	return false
}

// extractToken extracts authentication token from request
func (m *EnhancedAuthMiddleware) extractToken(c echo.Context) string {
	// Try Authorization header first
	authHeader := c.Request().Header.Get("Authorization")
	if authHeader != "" {
		if token := utils.ExtractTokenFromBearer(authHeader); token != "" {
			return token
		}
	}

	// Try cookie (for session mode)
	if cookie, err := c.Cookie("auth_token"); err == nil {
		return cookie.Value
	}

	// Try query parameter (less secure, for development/testing)
	if token := c.QueryParam("token"); token != "" {
		return token
	}

	return ""
}

// extractTenantID extracts tenant ID from request parameters
func (m *EnhancedAuthMiddleware) extractTenantID(c echo.Context, param string) *uuid.UUID {
	tenantIDStr := c.Param(param)
	if tenantIDStr == "" {
		tenantIDStr = c.QueryParam("tenant_id")
	}

	if tenantIDStr == "" {
		return nil
	}

	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		return nil
	}

	return &tenantID
}

// handleAuthError handles authentication errors
func (m *EnhancedAuthMiddleware) handleAuthError(c echo.Context, err error) error {
	m.logger.Warn("Authentication failed", "error", err, "path", c.Request().URL.Path)
	return echo.NewHTTPError(http.StatusUnauthorized, "Authentication required")
}

// InvalidateUserCache invalidates cached user data (roles, permissions)
func (m *EnhancedAuthMiddleware) InvalidateUserCache(ctx context.Context, userID, tenantID uuid.UUID) error {
	rolesCacheKey := fmt.Sprintf(UserRolesCacheKey, userID.String(), tenantID.String())
	permsCacheKey := fmt.Sprintf(UserPermissionsCacheKey, userID.String(), tenantID.String())

	return m.kvStore.Del(ctx, rolesCacheKey, permsCacheKey)
}

// InvalidateSessionCache invalidates cached session data
func (m *EnhancedAuthMiddleware) InvalidateSessionCache(ctx context.Context, token string) error {
	cacheKey := fmt.Sprintf(SessionDataCacheKey, token)
	return m.kvStore.Del(ctx, cacheKey)
}

// BlacklistJWT adds JWT to blacklist
func (m *EnhancedAuthMiddleware) BlacklistJWT(ctx context.Context, jti string, ttl time.Duration) error {
	blacklistKey := fmt.Sprintf(JWTBlacklistKey, jti)
	return m.kvStore.Set(ctx, blacklistKey, "revoked", ttl)
}

// StoreRefreshToken stores refresh token in KV store
func (m *EnhancedAuthMiddleware) StoreRefreshToken(ctx context.Context, refreshToken string, userID uuid.UUID, ttl time.Duration) error {
	refreshKey := fmt.Sprintf(RefreshTokenKey, refreshToken)
	return m.kvStore.Set(ctx, refreshKey, userID.String(), ttl)
}

// ValidateRefreshToken validates refresh token from KV store
func (m *EnhancedAuthMiddleware) ValidateRefreshToken(ctx context.Context, refreshToken string) (uuid.UUID, error) {
	refreshKey := fmt.Sprintf(RefreshTokenKey, refreshToken)
	userIDStr, err := m.kvStore.Get(ctx, refreshKey)
	if err != nil {
		return uuid.Nil, fmt.Errorf("refresh token not found or expired")
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return uuid.Nil, fmt.Errorf("invalid user ID in refresh token")
	}

	return userID, nil
}

// RevokeRefreshToken removes refresh token from KV store
func (m *EnhancedAuthMiddleware) RevokeRefreshToken(ctx context.Context, refreshToken string) error {
	refreshKey := fmt.Sprintf(RefreshTokenKey, refreshToken)
	return m.kvStore.Del(ctx, refreshKey)
}
