package middleware

import (
	"context"
	"fmt"

	"github.com/ducdt2000/azth/backend/internal/constants"
	"github.com/ducdt2000/azth/backend/internal/modules/auth/strategy"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

// AuthHelpers provides convenient helper functions for authentication and authorization
type AuthHelpers struct {
	enhancedAuth *EnhancedAuthMiddleware
}

// NewAuthHelpers creates a new auth helpers instance
func NewAuthHelpers(enhancedAuth *EnhancedAuthMiddleware) *AuthHelpers {
	return &AuthHelpers{
		enhancedAuth: enhancedAuth,
	}
}

// GetAuthContext extracts the authentication context from Echo context
func GetAuthContext(c echo.Context) (*strategy.AuthContext, error) {
	authCtx, ok := c.Get("auth_context").(*strategy.AuthContext)
	if !ok {
		return nil, fmt.Errorf("authentication context not found")
	}
	return authCtx, nil
}

// MustGetAuthContext extracts the authentication context or panics
func MustGetAuthContext(c echo.Context) *strategy.AuthContext {
	authCtx, err := GetAuthContext(c)
	if err != nil {
		panic(err)
	}
	return authCtx
}

// GetUserID extracts the user ID from Echo context
func GetUserID(c echo.Context) (uuid.UUID, error) {
	userIDStr, ok := c.Get("user_id").(string)
	if !ok {
		return uuid.Nil, fmt.Errorf("user ID not found in context")
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return uuid.Nil, fmt.Errorf("invalid user ID format: %w", err)
	}

	return userID, nil
}

// MustGetUserID extracts the user ID or panics
func MustGetUserID(c echo.Context) uuid.UUID {
	userID, err := GetUserID(c)
	if err != nil {
		panic(err)
	}
	return userID
}

// GetTenantID extracts the tenant ID from Echo context
func GetTenantID(c echo.Context) (uuid.UUID, error) {
	tenantIDStr, ok := c.Get("tenant_id").(string)
	if !ok {
		return uuid.Nil, fmt.Errorf("tenant ID not found in context")
	}

	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		return uuid.Nil, fmt.Errorf("invalid tenant ID format: %w", err)
	}

	return tenantID, nil
}

// MustGetTenantID extracts the tenant ID or panics
func MustGetTenantID(c echo.Context) uuid.UUID {
	tenantID, err := GetTenantID(c)
	if err != nil {
		panic(err)
	}
	return tenantID
}

// IsAuthenticatedContext checks if the request is authenticated (alternative to avoid redeclaration)
func IsAuthenticatedContext(c echo.Context) bool {
	_, err := GetAuthContext(c)
	return err == nil
}

// HasRole checks if the authenticated user has a specific role
func HasRole(c echo.Context, role string) bool {
	authCtx, err := GetAuthContext(c)
	if err != nil {
		return false
	}

	for _, userRole := range authCtx.Roles {
		if userRole == role {
			return true
		}
	}
	return false
}

// HasAnyRole checks if the authenticated user has any of the specified roles
func HasAnyRole(c echo.Context, roles ...string) bool {
	authCtx, err := GetAuthContext(c)
	if err != nil {
		return false
	}

	roleSet := make(map[string]bool)
	for _, userRole := range authCtx.Roles {
		roleSet[userRole] = true
	}

	for _, role := range roles {
		if roleSet[role] {
			return true
		}
	}
	return false
}

// HasAllRoles checks if the authenticated user has all of the specified roles
func HasAllRoles(c echo.Context, roles ...string) bool {
	authCtx, err := GetAuthContext(c)
	if err != nil {
		return false
	}

	roleSet := make(map[string]bool)
	for _, userRole := range authCtx.Roles {
		roleSet[userRole] = true
	}

	for _, role := range roles {
		if !roleSet[role] {
			return false
		}
	}
	return true
}

// HasPermission checks if the authenticated user has a specific permission
func HasPermission(c echo.Context, permission string) bool {
	authCtx, err := GetAuthContext(c)
	if err != nil {
		return false
	}

	for _, userPerm := range authCtx.Permissions {
		if userPerm == permission || matchesWildcardPermission(userPerm, permission) {
			return true
		}
	}
	return false
}

// HasAnyPermission checks if the authenticated user has any of the specified permissions
func HasAnyPermission(c echo.Context, permissions ...string) bool {
	authCtx, err := GetAuthContext(c)
	if err != nil {
		return false
	}

	permSet := make(map[string]bool)
	for _, userPerm := range authCtx.Permissions {
		permSet[userPerm] = true
	}

	for _, permission := range permissions {
		if permSet[permission] {
			return true
		}
		// Check wildcard permissions
		for userPerm := range permSet {
			if matchesWildcardPermission(userPerm, permission) {
				return true
			}
		}
	}
	return false
}

// HasAllPermissions checks if the authenticated user has all of the specified permissions
func HasAllPermissions(c echo.Context, permissions ...string) bool {
	authCtx, err := GetAuthContext(c)
	if err != nil {
		return false
	}

	permSet := make(map[string]bool)
	for _, userPerm := range authCtx.Permissions {
		permSet[userPerm] = true
	}

	for _, permission := range permissions {
		hasPermission := permSet[permission]
		if !hasPermission {
			// Check wildcard permissions
			for userPerm := range permSet {
				if matchesWildcardPermission(userPerm, permission) {
					hasPermission = true
					break
				}
			}
		}
		if !hasPermission {
			return false
		}
	}
	return true
}

// IsSuperAdmin checks if the authenticated user is a super admin
func IsSuperAdmin(c echo.Context) bool {
	return HasRole(c, "super_admin")
}

// IsAdmin checks if the authenticated user is an admin (super_admin or admin)
func IsAdmin(c echo.Context) bool {
	return HasAnyRole(c, "super_admin", "admin")
}

// IsTenantAdmin checks if the authenticated user is a tenant admin
func IsTenantAdmin(c echo.Context) bool {
	return HasAnyRole(c, "super_admin", "admin", "tenant_admin")
}

// CanAccessTenant checks if the authenticated user can access a specific tenant
func CanAccessTenant(c echo.Context, tenantID uuid.UUID) bool {
	authCtx, err := GetAuthContext(c)
	if err != nil {
		return false
	}

	// Super admins can access any tenant
	if IsSuperAdmin(c) {
		return true
	}

	// Users can access their own tenant
	return authCtx.TenantID == tenantID
}

// CanAccessUser checks if the authenticated user can access another user's data
func CanAccessUser(c echo.Context, targetUserID uuid.UUID) bool {
	authCtx, err := GetAuthContext(c)
	if err != nil {
		return false
	}

	// Users can access their own data
	if authCtx.UserID == targetUserID {
		return true
	}

	// Admins can access any user data
	if IsAdmin(c) {
		return true
	}

	// Check if user has user management permissions
	return HasAnyPermission(c, "user:read", "user:*")
}

// InvalidateUserCache invalidates cached user data for the authenticated user
func (h *AuthHelpers) InvalidateUserCache(c echo.Context) error {
	authCtx, err := GetAuthContext(c)
	if err != nil {
		return err
	}

	return h.enhancedAuth.InvalidateUserCache(c.Request().Context(), authCtx.UserID, authCtx.TenantID)
}

// InvalidateUserCacheByID invalidates cached user data for a specific user
func (h *AuthHelpers) InvalidateUserCacheByID(ctx context.Context, userID, tenantID uuid.UUID) error {
	return h.enhancedAuth.InvalidateUserCache(ctx, userID, tenantID)
}

// matchesWildcardPermission checks if a wildcard permission matches a specific permission
func matchesWildcardPermission(wildcardPerm, specificPerm string) bool {
	if len(wildcardPerm) == 0 || wildcardPerm[len(wildcardPerm)-1] != '*' {
		return false
	}

	prefix := wildcardPerm[:len(wildcardPerm)-1]
	return len(specificPerm) >= len(prefix) && specificPerm[:len(prefix)] == prefix
}

// Additional helper functions for enhanced auth context

// GetAuthMode returns the authentication mode (jwt or session)
func GetAuthMode(c echo.Context) string {
	authCtx, err := GetAuthContext(c)
	if err != nil {
		return ""
	}
	return authCtx.TokenType
}

// IsJWTAuth checks if the current authentication is JWT-based
func IsJWTAuth(c echo.Context) bool {
	return GetAuthMode(c) == "jwt"
}

// IsSessionAuth checks if the current authentication is session-based
func IsSessionAuth(c echo.Context) bool {
	return GetAuthMode(c) == "session"
}

// GetSessionID returns the session ID if using session authentication
func GetSessionID(c echo.Context) *uuid.UUID {
	authCtx, err := GetAuthContext(c)
	if err != nil {
		return nil
	}
	return authCtx.SessionID
}

// Legacy permission constants - DEPRECATED: Use constants.Perm* instead
// These are kept for backward compatibility and will be removed in a future version
const (
	// User permissions - use constants.PermUser* instead
	PermUserCreate         = constants.PermUserCreate
	PermUserRead           = constants.PermUserRead
	PermUserUpdate         = constants.PermUserUpdate
	PermUserDelete         = constants.PermUserDelete
	PermUserAll            = "user:*" // Special wildcard permission
	PermUserAssignRole     = constants.PermUserAssignRole
	PermUserRevokeRole     = constants.PermUserRevokeRole
	PermUserUpdatePassword = constants.PermUserUpdatePassword
	PermUserBulkUpdate     = constants.PermUserBulkUpdate
	PermUserStats          = constants.PermUserStats

	// Role permissions - use constants.PermRole* instead
	PermRoleCreate     = constants.PermRoleCreate
	PermRoleRead       = constants.PermRoleRead
	PermRoleUpdate     = constants.PermRoleUpdate
	PermRoleDelete     = constants.PermRoleDelete
	PermRoleAll        = "role:*" // Special wildcard permission
	PermRoleBulkCreate = constants.PermRoleBulkCreate
	PermRoleBulkDelete = constants.PermRoleBulkDelete
	PermRoleStats      = constants.PermRoleStats

	// Permission permissions - use constants.PermPermission* instead
	PermPermissionCreate     = constants.PermPermissionCreate
	PermPermissionRead       = constants.PermPermissionRead
	PermPermissionUpdate     = constants.PermPermissionUpdate
	PermPermissionDelete     = constants.PermPermissionDelete
	PermPermissionAll        = "permission:*" // Special wildcard permission
	PermPermissionAssign     = constants.PermPermissionAssign
	PermPermissionRevoke     = constants.PermPermissionRevoke
	PermPermissionBulkCreate = constants.PermPermissionBulkCreate
	PermPermissionBulkDelete = constants.PermPermissionBulkDelete
	PermPermissionValidate   = constants.PermPermissionValidate

	// Tenant permissions - use constants.PermTenant* instead
	PermTenantCreate     = constants.PermTenantCreate
	PermTenantRead       = constants.PermTenantRead
	PermTenantUpdate     = constants.PermTenantUpdate
	PermTenantDelete     = constants.PermTenantDelete
	PermTenantAll        = "tenant:*" // Special wildcard permission
	PermTenantActivate   = constants.PermTenantActivate
	PermTenantDeactivate = constants.PermTenantDeactivate
	PermTenantSuspend    = constants.PermTenantSuspend
)

// Note: Role constants are defined in authorization_middleware.go to avoid redeclaration
