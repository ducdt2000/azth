package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/ducdt2000/azth/backend/internal/constants"
	"github.com/ducdt2000/azth/backend/internal/modules/auth/strategy"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

// AuthorizationConfig holds configuration for authorization middleware
type AuthorizationConfig struct {
	RequiredRoles       []string `json:"required_roles"`
	RequiredPermissions []string `json:"required_permissions"`
	ResourceType        string   `json:"resource_type"`
	AllowOwnerAccess    bool     `json:"allow_owner_access"`
	RequireAll          bool     `json:"require_all"` // If true, require ALL permissions; if false, require ANY
}

// ResourceOwnership defines ownership validation interface
type ResourceOwnership interface {
	IsOwner(ctx context.Context, userID uuid.UUID, resourceID string) (bool, error)
}

// AuthorizationMiddleware provides role and permission-based authorization
type AuthorizationMiddleware struct {
	resourceOwnership ResourceOwnership
}

// NewAuthorizationMiddleware creates a new authorization middleware
func NewAuthorizationMiddleware(resourceOwnership ResourceOwnership) *AuthorizationMiddleware {
	return &AuthorizationMiddleware{
		resourceOwnership: resourceOwnership,
	}
}

// RequireRole creates middleware that requires specific roles
func (am *AuthorizationMiddleware) RequireRole(roles ...string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			authCtx := getAuthContextFromEcho(c)
			if authCtx == nil {
				return echo.NewHTTPError(http.StatusUnauthorized, "Authentication required")
			}

			if !am.hasAnyRole(authCtx.Roles, roles) {
				return echo.NewHTTPError(http.StatusForbidden,
					fmt.Sprintf("Required roles: %s", strings.Join(roles, ", ")))
			}

			return next(c)
		}
	}
}

// RequireAllRoles creates middleware that requires ALL specified roles
func (am *AuthorizationMiddleware) RequireAllRoles(roles ...string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			authCtx := getAuthContextFromEcho(c)
			if authCtx == nil {
				return echo.NewHTTPError(http.StatusUnauthorized, "Authentication required")
			}

			if !am.hasAllRoles(authCtx.Roles, roles) {
				return echo.NewHTTPError(http.StatusForbidden,
					fmt.Sprintf("Required roles: %s", strings.Join(roles, ", ")))
			}

			return next(c)
		}
	}
}

// RequirePermission creates middleware that requires specific permissions
func (am *AuthorizationMiddleware) RequirePermission(permissions ...string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			authCtx := getAuthContextFromEcho(c)
			if authCtx == nil {
				return echo.NewHTTPError(http.StatusUnauthorized, "Authentication required")
			}

			if !am.hasAnyPermission(authCtx.Permissions, permissions) {
				return echo.NewHTTPError(http.StatusForbidden,
					fmt.Sprintf("Required permissions: %s", strings.Join(permissions, ", ")))
			}

			return next(c)
		}
	}
}

// RequireAllPermissions creates middleware that requires ALL specified permissions
func (am *AuthorizationMiddleware) RequireAllPermissions(permissions ...string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			authCtx := getAuthContextFromEcho(c)
			if authCtx == nil {
				return echo.NewHTTPError(http.StatusUnauthorized, "Authentication required")
			}

			if !am.hasAllPermissions(authCtx.Permissions, permissions) {
				return echo.NewHTTPError(http.StatusForbidden,
					fmt.Sprintf("Required permissions: %s", strings.Join(permissions, ", ")))
			}

			return next(c)
		}
	}
}

// RequireOwnership creates middleware that requires resource ownership or specific permissions
func (am *AuthorizationMiddleware) RequireOwnership(resourceIDParam string, fallbackPermissions ...string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			authCtx := getAuthContextFromEcho(c)
			if authCtx == nil {
				return echo.NewHTTPError(http.StatusUnauthorized, "Authentication required")
			}

			resourceID := c.Param(resourceIDParam)
			if resourceID == "" {
				return echo.NewHTTPError(http.StatusBadRequest, "Resource ID not found")
			}

			// Check ownership first
			if am.resourceOwnership != nil {
				isOwner, err := am.resourceOwnership.IsOwner(c.Request().Context(), authCtx.UserID, resourceID)
				if err != nil {
					return echo.NewHTTPError(http.StatusInternalServerError, "Failed to verify ownership")
				}

				if isOwner {
					return next(c)
				}
			}

			// Check fallback permissions
			if len(fallbackPermissions) > 0 && am.hasAnyPermission(authCtx.Permissions, fallbackPermissions) {
				return next(c)
			}

			return echo.NewHTTPError(http.StatusForbidden, "Access denied: insufficient permissions or ownership")
		}
	}
}

// RequireRoleOrPermission creates middleware that requires either specific roles OR permissions
func (am *AuthorizationMiddleware) RequireRoleOrPermission(roles []string, permissions []string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			authCtx := getAuthContextFromEcho(c)
			if authCtx == nil {
				return echo.NewHTTPError(http.StatusUnauthorized, "Authentication required")
			}

			hasRole := len(roles) == 0 || am.hasAnyRole(authCtx.Roles, roles)
			hasPermission := len(permissions) == 0 || am.hasAnyPermission(authCtx.Permissions, permissions)

			if !hasRole && !hasPermission {
				return echo.NewHTTPError(http.StatusForbidden,
					fmt.Sprintf("Required roles: %s OR permissions: %s",
						strings.Join(roles, ", "), strings.Join(permissions, ", ")))
			}

			return next(c)
		}
	}
}

// RequireTenantAccess creates middleware that validates tenant access
func (am *AuthorizationMiddleware) RequireTenantAccess(tenantIDParam string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			authCtx := getAuthContextFromEcho(c)
			if authCtx == nil {
				return echo.NewHTTPError(http.StatusUnauthorized, "Authentication required")
			}

			requestedTenantID := c.Param(tenantIDParam)
			if requestedTenantID == "" {
				// Try to get from query parameter
				requestedTenantID = c.QueryParam("tenant_id")
			}

			if requestedTenantID == "" {
				return echo.NewHTTPError(http.StatusBadRequest, "Tenant ID required")
			}

			requestedTenantUUID, err := uuid.Parse(requestedTenantID)
			if err != nil {
				return echo.NewHTTPError(http.StatusBadRequest, "Invalid tenant ID format")
			}

			// Check if user belongs to the tenant or has global permissions
			if authCtx.TenantID != requestedTenantUUID {
				// Check for global admin permissions
				if !am.hasAnyPermission(authCtx.Permissions, []string{"global:admin", "tenant:access:any"}) {
					return echo.NewHTTPError(http.StatusForbidden, "Access denied: insufficient tenant permissions")
				}
			}

			return next(c)
		}
	}
}

// DynamicAuthorization creates middleware with dynamic authorization rules
func (am *AuthorizationMiddleware) DynamicAuthorization(config AuthorizationConfig) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			authCtx := getAuthContextFromEcho(c)
			if authCtx == nil {
				return echo.NewHTTPError(http.StatusUnauthorized, "Authentication required")
			}

			// Check roles
			if len(config.RequiredRoles) > 0 {
				if config.RequireAll {
					if !am.hasAllRoles(authCtx.Roles, config.RequiredRoles) {
						return echo.NewHTTPError(http.StatusForbidden, "Insufficient role permissions")
					}
				} else {
					if !am.hasAnyRole(authCtx.Roles, config.RequiredRoles) {
						return echo.NewHTTPError(http.StatusForbidden, "Insufficient role permissions")
					}
				}
			}

			// Check permissions
			if len(config.RequiredPermissions) > 0 {
				if config.RequireAll {
					if !am.hasAllPermissions(authCtx.Permissions, config.RequiredPermissions) {
						return echo.NewHTTPError(http.StatusForbidden, "Insufficient permissions")
					}
				} else {
					if !am.hasAnyPermission(authCtx.Permissions, config.RequiredPermissions) {
						return echo.NewHTTPError(http.StatusForbidden, "Insufficient permissions")
					}
				}
			}

			// Check ownership if required
			if config.AllowOwnerAccess && config.ResourceType != "" {
				resourceID := c.Param("id")
				if resourceID != "" && am.resourceOwnership != nil {
					isOwner, err := am.resourceOwnership.IsOwner(c.Request().Context(), authCtx.UserID, resourceID)
					if err == nil && isOwner {
						return next(c)
					}
				}
			}

			return next(c)
		}
	}
}

// Helper functions

func (am *AuthorizationMiddleware) hasAnyRole(userRoles []string, requiredRoles []string) bool {
	userRoleMap := make(map[string]bool)
	for _, role := range userRoles {
		userRoleMap[role] = true
	}

	for _, requiredRole := range requiredRoles {
		if userRoleMap[requiredRole] {
			return true
		}
	}

	return false
}

func (am *AuthorizationMiddleware) hasAllRoles(userRoles []string, requiredRoles []string) bool {
	userRoleMap := make(map[string]bool)
	for _, role := range userRoles {
		userRoleMap[role] = true
	}

	for _, requiredRole := range requiredRoles {
		if !userRoleMap[requiredRole] {
			return false
		}
	}

	return true
}

func (am *AuthorizationMiddleware) hasAnyPermission(userPermissions []string, requiredPermissions []string) bool {
	userPermMap := make(map[string]bool)
	for _, perm := range userPermissions {
		userPermMap[perm] = true
	}

	for _, requiredPerm := range requiredPermissions {
		if userPermMap[requiredPerm] {
			return true
		}

		// Check for wildcard permissions (e.g., "user:*" matches "user:read")
		if am.matchesWildcard(userPermissions, requiredPerm) {
			return true
		}
	}

	return false
}

func (am *AuthorizationMiddleware) hasAllPermissions(userPermissions []string, requiredPermissions []string) bool {
	userPermMap := make(map[string]bool)
	for _, perm := range userPermissions {
		userPermMap[perm] = true
	}

	for _, requiredPerm := range requiredPermissions {
		if !userPermMap[requiredPerm] && !am.matchesWildcard(userPermissions, requiredPerm) {
			return false
		}
	}

	return true
}

func (am *AuthorizationMiddleware) matchesWildcard(userPermissions []string, requiredPermission string) bool {
	parts := strings.Split(requiredPermission, ":")
	if len(parts) < 2 {
		return false
	}

	wildcardPerm := parts[0] + ":*"
	globalWildcard := "*"

	for _, userPerm := range userPermissions {
		if userPerm == wildcardPerm || userPerm == globalWildcard {
			return true
		}
	}

	return false
}

// getAuthContextFromEcho extracts the auth context from echo context
func getAuthContextFromEcho(c echo.Context) *strategy.AuthContext {
	// Try to get from different possible keys
	if authCtx, ok := c.Get("auth_context").(*strategy.AuthContext); ok {
		return authCtx
	}

	if authCtx, ok := c.Get("user").(*strategy.AuthContext); ok {
		return authCtx
	}

	return nil
}

// Legacy permission constants - DEPRECATED: Use constants.Perm* instead
// These are kept for backward compatibility and will be removed in a future version
const (
	// User permissions - use constants.PermUser* instead
	PermissionUserRead   = constants.PermUserRead
	PermissionUserWrite  = constants.PermUserUpdate // Note: mapped to Update for consistency
	PermissionUserDelete = constants.PermUserDelete
	PermissionUserAdmin  = "user:admin" // No direct mapping - consider using specific permissions

	// Tenant permissions - use constants.PermTenant* instead
	PermissionTenantRead   = constants.PermTenantRead
	PermissionTenantWrite  = constants.PermTenantUpdate // Note: mapped to Update for consistency
	PermissionTenantDelete = constants.PermTenantDelete
	PermissionTenantAdmin  = "tenant:admin" // No direct mapping - consider using specific permissions

	// Role permissions - use constants.PermRole* instead
	PermissionRoleRead   = constants.PermRoleRead
	PermissionRoleWrite  = constants.PermRoleUpdate // Note: mapped to Update for consistency
	PermissionRoleDelete = constants.PermRoleDelete
	PermissionRoleAdmin  = "role:admin" // No direct mapping - consider using specific permissions

	// Permission permissions - use constants.PermPermission* instead
	PermissionPermissionRead   = constants.PermPermissionRead
	PermissionPermissionWrite  = constants.PermPermissionUpdate // Note: mapped to Update for consistency
	PermissionPermissionDelete = constants.PermPermissionDelete
	PermissionPermissionAdmin  = "permission:admin" // No direct mapping - consider using specific permissions

	// Global permissions - use constants.Perm* instead
	PermissionGlobalAdmin = constants.PermGlobalAdmin
	PermissionSystemAdmin = constants.PermSystemAdmin
)

// Legacy role constants - DEPRECATED: Use constants.Role* instead
// These are kept for backward compatibility and will be removed in a future version
const (
	RoleAdmin      = constants.RoleAdmin
	RoleModerator  = constants.RoleModerator
	RoleUser       = constants.RoleUser
	RoleGuest      = constants.RoleGuest
	RoleOwner      = constants.RoleOwner
	RoleManager    = constants.RoleManager
	RoleDeveloper  = constants.RoleDeveloper
	RoleSupport    = constants.RoleSupport
	RoleAnalyst    = constants.RoleAnalyst
	RoleSuperAdmin = constants.RoleSuperAdmin
)
