package middleware

import (
	"context"
	"net/http"

	"github.com/ducdt2000/azth/backend/internal/modules/role/service"
	"github.com/ducdt2000/azth/backend/pkg/logger"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

// tracer for OpenTelemetry tracing
var tracer = otel.Tracer("rbac-middleware")

// RBACMiddleware provides role-based access control
type RBACMiddleware struct {
	roleService service.RoleService
	logger      *logger.Logger
}

// NewRBACMiddleware creates a new RBAC middleware
func NewRBACMiddleware(roleService service.RoleService, logger *logger.Logger) *RBACMiddleware {
	return &RBACMiddleware{
		roleService: roleService,
		logger:      logger,
	}
}

// RequirePermission creates middleware that requires a specific permission
func (m *RBACMiddleware) RequirePermission(permissionCode string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			ctx, span := tracer.Start(c.Request().Context(), "RBACMiddleware.RequirePermission")
			defer span.End()

			span.SetAttributes(attribute.String("permission.code", permissionCode))

			// Extract user and tenant from context (set by auth middleware)
			userID, tenantID, err := m.extractUserAndTenant(c)
			if err != nil {
				m.logger.Error("Failed to extract user and tenant", "error", err)
				return c.JSON(http.StatusUnauthorized, map[string]string{
					"error": "Authentication required",
				})
			}

			span.SetAttributes(
				attribute.String("user.id", userID.String()),
				attribute.String("tenant.id", tenantID.String()),
			)

			// Get user permissions
			permissions, err := m.roleService.GetUserPermissions(ctx, userID, tenantID)
			if err != nil {
				m.logger.Error("Failed to get user permissions", "error", err, "user_id", userID, "tenant_id", tenantID)
				return c.JSON(http.StatusInternalServerError, map[string]string{
					"error": "Failed to check permissions",
				})
			}

			// Check if user has the required permission
			hasPermission := false
			for _, permission := range permissions {
				if permission.Code == permissionCode {
					hasPermission = true
					break
				}
			}

			if !hasPermission {
				m.logger.Warn("User lacks required permission", "user_id", userID, "tenant_id", tenantID, "permission", permissionCode)
				return c.JSON(http.StatusForbidden, map[string]string{
					"error": "Insufficient permissions",
				})
			}

			m.logger.Debug("Permission check passed", "user_id", userID, "tenant_id", tenantID, "permission", permissionCode)
			return next(c)
		}
	}
}

// RequireAnyPermission creates middleware that requires any of the specified permissions
func (m *RBACMiddleware) RequireAnyPermission(permissionCodes ...string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			ctx, span := tracer.Start(c.Request().Context(), "RBACMiddleware.RequireAnyPermission")
			defer span.End()

			span.SetAttributes(attribute.StringSlice("permissions.codes", permissionCodes))

			// Extract user and tenant from context (set by auth middleware)
			userID, tenantID, err := m.extractUserAndTenant(c)
			if err != nil {
				m.logger.Error("Failed to extract user and tenant", "error", err)
				return c.JSON(http.StatusUnauthorized, map[string]string{
					"error": "Authentication required",
				})
			}

			span.SetAttributes(
				attribute.String("user.id", userID.String()),
				attribute.String("tenant.id", tenantID.String()),
			)

			// Get user permissions
			permissions, err := m.roleService.GetUserPermissions(ctx, userID, tenantID)
			if err != nil {
				m.logger.Error("Failed to get user permissions", "error", err, "user_id", userID, "tenant_id", tenantID)
				return c.JSON(http.StatusInternalServerError, map[string]string{
					"error": "Failed to check permissions",
				})
			}

			// Check if user has any of the required permissions
			hasPermission := false
			for _, permission := range permissions {
				for _, requiredCode := range permissionCodes {
					if permission.Code == requiredCode {
						hasPermission = true
						break
					}
				}
				if hasPermission {
					break
				}
			}

			if !hasPermission {
				m.logger.Warn("User lacks any required permission", "user_id", userID, "tenant_id", tenantID, "permissions", permissionCodes)
				return c.JSON(http.StatusForbidden, map[string]string{
					"error": "Insufficient permissions",
				})
			}

			m.logger.Debug("Permission check passed", "user_id", userID, "tenant_id", tenantID, "permissions", permissionCodes)
			return next(c)
		}
	}
}

// RequireRole creates middleware that requires a specific role
func (m *RBACMiddleware) RequireRole(roleSlug string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			ctx, span := tracer.Start(c.Request().Context(), "RBACMiddleware.RequireRole")
			defer span.End()

			span.SetAttributes(attribute.String("role.slug", roleSlug))

			// Extract user and tenant from context (set by auth middleware)
			userID, tenantID, err := m.extractUserAndTenant(c)
			if err != nil {
				m.logger.Error("Failed to extract user and tenant", "error", err)
				return c.JSON(http.StatusUnauthorized, map[string]string{
					"error": "Authentication required",
				})
			}

			span.SetAttributes(
				attribute.String("user.id", userID.String()),
				attribute.String("tenant.id", tenantID.String()),
			)

			// Get role by slug
			role, err := m.roleService.GetRoleBySlug(ctx, roleSlug, &tenantID)
			if err != nil {
				m.logger.Error("Failed to get role by slug", "error", err, "slug", roleSlug)
				return c.JSON(http.StatusInternalServerError, map[string]string{
					"error": "Failed to check role",
				})
			}

			// Check if user has the required role
			hasRole, err := m.roleService.HasRole(ctx, userID, role.ID, tenantID)
			if err != nil {
				m.logger.Error("Failed to check user role", "error", err, "user_id", userID, "role_id", role.ID)
				return c.JSON(http.StatusInternalServerError, map[string]string{
					"error": "Failed to check role",
				})
			}

			if !hasRole {
				m.logger.Warn("User lacks required role", "user_id", userID, "tenant_id", tenantID, "role", roleSlug)
				return c.JSON(http.StatusForbidden, map[string]string{
					"error": "Insufficient role",
				})
			}

			m.logger.Debug("Role check passed", "user_id", userID, "tenant_id", tenantID, "role", roleSlug)
			return next(c)
		}
	}
}

// RequireAnyRole creates middleware that requires any of the specified roles
func (m *RBACMiddleware) RequireAnyRole(roleSlugs ...string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			ctx, span := tracer.Start(c.Request().Context(), "RBACMiddleware.RequireAnyRole")
			defer span.End()

			span.SetAttributes(attribute.StringSlice("roles.slugs", roleSlugs))

			// Extract user and tenant from context (set by auth middleware)
			userID, tenantID, err := m.extractUserAndTenant(c)
			if err != nil {
				m.logger.Error("Failed to extract user and tenant", "error", err)
				return c.JSON(http.StatusUnauthorized, map[string]string{
					"error": "Authentication required",
				})
			}

			span.SetAttributes(
				attribute.String("user.id", userID.String()),
				attribute.String("tenant.id", tenantID.String()),
			)

			// Get role IDs for the slugs
			var roleIDs []uuid.UUID
			for _, slug := range roleSlugs {
				role, err := m.roleService.GetRoleBySlug(ctx, slug, &tenantID)
				if err != nil {
					m.logger.Error("Failed to get role by slug", "error", err, "slug", slug)
					continue
				}
				roleIDs = append(roleIDs, role.ID)
			}

			if len(roleIDs) == 0 {
				m.logger.Error("No valid roles found", "slugs", roleSlugs)
				return c.JSON(http.StatusInternalServerError, map[string]string{
					"error": "Failed to check roles",
				})
			}

			// Check if user has any of the required roles
			hasRole, err := m.roleService.HasAnyRole(ctx, userID, roleIDs, tenantID)
			if err != nil {
				m.logger.Error("Failed to check user roles", "error", err, "user_id", userID, "role_ids", roleIDs)
				return c.JSON(http.StatusInternalServerError, map[string]string{
					"error": "Failed to check roles",
				})
			}

			if !hasRole {
				m.logger.Warn("User lacks any required role", "user_id", userID, "tenant_id", tenantID, "roles", roleSlugs)
				return c.JSON(http.StatusForbidden, map[string]string{
					"error": "Insufficient role",
				})
			}

			m.logger.Debug("Role check passed", "user_id", userID, "tenant_id", tenantID, "roles", roleSlugs)
			return next(c)
		}
	}
}

// RequireAdmin creates middleware that requires admin role
func (m *RBACMiddleware) RequireAdmin() echo.MiddlewareFunc {
	return m.RequireAnyRole("super-admin", "admin")
}

// RequireSuperAdmin creates middleware that requires super admin role
func (m *RBACMiddleware) RequireSuperAdmin() echo.MiddlewareFunc {
	return m.RequireRole("super-admin")
}

// extractUserAndTenant extracts user ID and tenant ID from the request context
// This assumes that the authentication middleware has already set these values
func (m *RBACMiddleware) extractUserAndTenant(c echo.Context) (uuid.UUID, uuid.UUID, error) {
	// TODO: Extract from JWT token or session
	// For now, we'll try to get from headers as a placeholder

	userIDStr := c.Request().Header.Get("X-User-ID")
	tenantIDStr := c.Request().Header.Get("X-Tenant-ID")

	// If not in headers, try query params (for testing)
	if userIDStr == "" {
		userIDStr = c.QueryParam("user_id")
	}
	if tenantIDStr == "" {
		tenantIDStr = c.QueryParam("tenant_id")
	}

	if userIDStr == "" || tenantIDStr == "" {
		return uuid.Nil, uuid.Nil, echo.NewHTTPError(http.StatusUnauthorized, "Missing user or tenant information")
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return uuid.Nil, uuid.Nil, echo.NewHTTPError(http.StatusBadRequest, "Invalid user ID")
	}

	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		return uuid.Nil, uuid.Nil, echo.NewHTTPError(http.StatusBadRequest, "Invalid tenant ID")
	}

	return userID, tenantID, nil
}

// PermissionChecker provides utility functions for checking permissions in handlers
type PermissionChecker struct {
	roleService service.RoleService
	logger      *logger.Logger
}

// NewPermissionChecker creates a new permission checker
func NewPermissionChecker(roleService service.RoleService, logger *logger.Logger) *PermissionChecker {
	return &PermissionChecker{
		roleService: roleService,
		logger:      logger,
	}
}

// HasPermission checks if a user has a specific permission
func (pc *PermissionChecker) HasPermission(ctx context.Context, userID, tenantID uuid.UUID, permissionCode string) (bool, error) {
	permissions, err := pc.roleService.GetUserPermissions(ctx, userID, tenantID)
	if err != nil {
		return false, err
	}

	for _, permission := range permissions {
		if permission.Code == permissionCode {
			return true, nil
		}
	}

	return false, nil
}

// HasAnyPermission checks if a user has any of the specified permissions
func (pc *PermissionChecker) HasAnyPermission(ctx context.Context, userID, tenantID uuid.UUID, permissionCodes ...string) (bool, error) {
	permissions, err := pc.roleService.GetUserPermissions(ctx, userID, tenantID)
	if err != nil {
		return false, err
	}

	for _, permission := range permissions {
		for _, requiredCode := range permissionCodes {
			if permission.Code == requiredCode {
				return true, nil
			}
		}
	}

	return false, nil
}

// HasRole checks if a user has a specific role
func (pc *PermissionChecker) HasRole(ctx context.Context, userID, tenantID uuid.UUID, roleSlug string) (bool, error) {
	role, err := pc.roleService.GetRoleBySlug(ctx, roleSlug, &tenantID)
	if err != nil {
		return false, err
	}

	return pc.roleService.HasRole(ctx, userID, role.ID, tenantID)
}

// HasAnyRole checks if a user has any of the specified roles
func (pc *PermissionChecker) HasAnyRole(ctx context.Context, userID, tenantID uuid.UUID, roleSlugs ...string) (bool, error) {
	var roleIDs []uuid.UUID
	for _, slug := range roleSlugs {
		role, err := pc.roleService.GetRoleBySlug(ctx, slug, &tenantID)
		if err != nil {
			continue // Skip invalid roles
		}
		roleIDs = append(roleIDs, role.ID)
	}

	if len(roleIDs) == 0 {
		return false, nil
	}

	return pc.roleService.HasAnyRole(ctx, userID, roleIDs, tenantID)
}

// IsAdmin checks if a user has admin privileges
func (pc *PermissionChecker) IsAdmin(ctx context.Context, userID, tenantID uuid.UUID) (bool, error) {
	return pc.HasAnyRole(ctx, userID, tenantID, "super-admin", "admin")
}

// IsSuperAdmin checks if a user has super admin privileges
func (pc *PermissionChecker) IsSuperAdmin(ctx context.Context, userID, tenantID uuid.UUID) (bool, error) {
	return pc.HasRole(ctx, userID, tenantID, "super-admin")
}
