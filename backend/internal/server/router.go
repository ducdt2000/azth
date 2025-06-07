package server

import (
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"

	"github.com/ducdt2000/azth/backend/internal/constants"
	authHandlers "github.com/ducdt2000/azth/backend/internal/modules/auth/handlers"
	permissionHandlers "github.com/ducdt2000/azth/backend/internal/modules/permission/handlers"
	roleHandlers "github.com/ducdt2000/azth/backend/internal/modules/role/handlers"
	tenantHandlers "github.com/ducdt2000/azth/backend/internal/modules/tenant/handlers"
	userHandlers "github.com/ducdt2000/azth/backend/internal/modules/user/handlers"
	"github.com/ducdt2000/azth/backend/pkg/logger"
	pkgMiddleware "github.com/ducdt2000/azth/backend/pkg/middleware"
)

// Router handles HTTP routing with dependency-injected handlers
type Router struct {
	userHandler       *userHandlers.UserHandlerV2
	tenantHandler     *tenantHandlers.TenantHandler
	roleHandler       *roleHandlers.RoleHandler
	permissionHandler *permissionHandlers.PermissionHandler
	authHandler       *authHandlers.AuthHandler
	logger            *logger.Logger

	// Middleware
	enhancedAuth    *pkgMiddleware.EnhancedAuthMiddleware
	rbacMiddleware  *pkgMiddleware.RBACMiddleware
	authzMiddleware *pkgMiddleware.AuthorizationMiddleware
}

// NewRouter creates a new router with injected handlers and middleware
func NewRouter(
	userHandler *userHandlers.UserHandlerV2,
	tenantHandler *tenantHandlers.TenantHandler,
	roleHandler *roleHandlers.RoleHandler,
	permissionHandler *permissionHandlers.PermissionHandler,
	authHandler *authHandlers.AuthHandler,
	logger *logger.Logger,
	enhancedAuth *pkgMiddleware.EnhancedAuthMiddleware,
	rbacMiddleware *pkgMiddleware.RBACMiddleware,
	authzMiddleware *pkgMiddleware.AuthorizationMiddleware,
) *Router {
	return &Router{
		userHandler:       userHandler,
		tenantHandler:     tenantHandler,
		roleHandler:       roleHandler,
		permissionHandler: permissionHandler,
		authHandler:       authHandler,
		logger:            logger,
		enhancedAuth:      enhancedAuth,
		rbacMiddleware:    rbacMiddleware,
		authzMiddleware:   authzMiddleware,
	}
}

// SetupRoutes configures all routes with proper handlers and middleware
func (r *Router) SetupRoutes(e *echo.Echo) {
	// Health check
	e.GET("/health", r.healthHandler)

	// API v1 routes
	v1 := e.Group("/api/v1")

	// Add request logging middleware for API routes
	v1.Use(middleware.RequestLoggerWithConfig(middleware.RequestLoggerConfig{
		LogStatus:   true,
		LogURI:      true,
		LogError:    true,
		HandleError: true,
		LogValuesFunc: func(c echo.Context, v middleware.RequestLoggerValues) error {
			if v.Error == nil {
				r.logger.Info("HTTP request",
					"uri", v.URI,
					"status", v.Status,
					"method", c.Request().Method,
				)
			} else {
				r.logger.Error("HTTP request error",
					"uri", v.URI,
					"status", v.Status,
					"method", c.Request().Method,
					"error", v.Error,
				)
			}
			return nil
		},
	}))

	// Auth routes (public)
	auth := v1.Group("/auth")
	auth.POST("/login", r.authHandler.Login)
	auth.POST("/register", r.placeholderHandler("register")) // TODO: Implement user registration
	auth.POST("/refresh", r.authHandler.RefreshToken)
	auth.GET("/me", r.placeholderHandler("get-profile"), r.enhancedAuth.RequireAuth()) // TODO: Implement get profile
	auth.POST("/logout", r.authHandler.Logout, r.enhancedAuth.RequireAuth())
	auth.PUT("/password", r.placeholderHandler("change-password"), r.enhancedAuth.RequireAuth()) // TODO: Implement change password

	// Session management
	auth.GET("/sessions", r.authHandler.GetSessions, r.enhancedAuth.RequireAuth())
	auth.DELETE("/sessions/:id", r.authHandler.RevokeSession, r.enhancedAuth.RequireAuth())
	auth.DELETE("/sessions", r.authHandler.LogoutAll, r.enhancedAuth.RequireAuth())

	// MFA routes
	auth.POST("/mfa/enable", r.authHandler.EnableMFA, r.enhancedAuth.RequireAuth())
	auth.DELETE("/mfa/disable", r.authHandler.DisableMFA, r.enhancedAuth.RequireAuth())
	auth.POST("/mfa/validate", r.authHandler.ValidateMFA, r.enhancedAuth.RequireAuth())
	auth.POST("/mfa/backup-codes", r.authHandler.GenerateBackupCodes, r.enhancedAuth.RequireAuth())

	// User routes with role-based access control
	users := v1.Group("/users")
	users.Use(r.enhancedAuth.RequireAuth()) // All user routes require authentication

	// User management - requires admin or user management permissions
	users.POST("", r.userHandler.CreateUser, r.enhancedAuth.RequirePermission(constants.PermUserCreate))
	users.GET("", r.userHandler.ListUsers, r.enhancedAuth.RequirePermission(constants.PermUserRead))
	// TODO: Implement GetUserStats and BulkUpdateUsers in UserHandlerV2
	// users.GET("/stats", r.userHandler.GetUserStats, r.enhancedAuth.RequirePermission(constants.PermUserStats))
	// users.POST("/bulk", r.userHandler.BulkUpdateUsers, r.enhancedAuth.RequirePermission(constants.PermUserBulkUpdate))

	// Individual user operations
	users.GET("/:id", r.userHandler.GetUser, r.enhancedAuth.RequirePermission(constants.PermUserRead))
	users.PUT("/:id", r.userHandler.UpdateUser, r.enhancedAuth.RequirePermission(constants.PermUserUpdate))
	users.DELETE("/:id", r.userHandler.DeleteUser, r.enhancedAuth.RequirePermission(constants.PermUserDelete))
	// TODO: Implement ChangePassword in UserHandlerV2
	// users.PUT("/:id/password", r.userHandler.ChangePassword, r.enhancedAuth.RequirePermission(constants.PermUserUpdatePassword))

	// User role and permission routes - requires role management permissions
	users.GET("/:user_id/roles", r.roleHandler.GetUserRoles, r.enhancedAuth.RequirePermission(constants.PermRoleRead))
	users.GET("/:user_id/permissions", r.roleHandler.GetUserPermissions, r.enhancedAuth.RequirePermission(constants.PermPermissionRead))

	// Tenant routes with tenant-specific access control
	tenants := v1.Group("/tenants")
	tenants.Use(r.enhancedAuth.RequireAuth()) // All tenant routes require authentication

	// Tenant management - requires tenant admin permissions
	tenants.POST("", r.tenantHandler.CreateTenant, r.enhancedAuth.RequirePermission(constants.PermTenantCreate))
	tenants.GET("", r.tenantHandler.ListTenants, r.enhancedAuth.RequirePermission(constants.PermTenantRead))
	tenants.GET("/:id", r.tenantHandler.GetTenant, r.enhancedAuth.RequirePermission(constants.PermTenantRead))
	tenants.PUT("/:id", r.tenantHandler.UpdateTenant, r.enhancedAuth.RequirePermission(constants.PermTenantUpdate))
	tenants.DELETE("/:id", r.tenantHandler.DeleteTenant, r.enhancedAuth.RequirePermission(constants.PermTenantDelete))

	// Tenant status management - requires tenant admin permissions
	tenants.PUT("/:id/activate", r.tenantHandler.ActivateTenant, r.enhancedAuth.RequirePermission(constants.PermTenantActivate))
	tenants.PUT("/:id/deactivate", r.tenantHandler.DeactivateTenant, r.enhancedAuth.RequirePermission(constants.PermTenantDeactivate))
	tenants.PUT("/:id/suspend", r.tenantHandler.SuspendTenant, r.enhancedAuth.RequirePermission(constants.PermTenantSuspend))

	// Public tenant lookup
	tenants.GET("/slug/:slug", r.tenantHandler.GetTenantBySlug) // Public endpoint

	// Bulk operations - requires super admin
	tenants.POST("/bulk", r.tenantHandler.BulkUpdateTenants, r.enhancedAuth.RequireRole(constants.RoleSuperAdmin))

	// Tenant role routes
	tenants.GET("/:tenant_id/roles", r.roleHandler.GetRolesByTenant,
		r.enhancedAuth.RequirePermission(constants.PermRoleRead),
		r.enhancedAuth.RequireTenantAccess("tenant_id"))

	// Role routes with permission-based access control
	roles := v1.Group("/roles")
	roles.Use(r.enhancedAuth.RequireAuth()) // All role routes require authentication

	// Role management - requires role management permissions
	roles.POST("", r.roleHandler.CreateRole, r.enhancedAuth.RequirePermission(constants.PermRoleCreate))
	roles.GET("", r.roleHandler.ListRoles, r.enhancedAuth.RequirePermission(constants.PermRoleRead))
	roles.GET("/stats", r.roleHandler.GetRoleStats, r.enhancedAuth.RequirePermission(constants.PermRoleStats))
	roles.GET("/global", r.roleHandler.GetGlobalRoles, r.enhancedAuth.RequirePermission(constants.PermRoleRead))
	roles.GET("/system", r.roleHandler.GetSystemRoles, r.enhancedAuth.RequireRole(constants.RoleSuperAdmin))
	roles.GET("/default", r.roleHandler.GetDefaultRoles, r.enhancedAuth.RequirePermission(constants.PermRoleRead))

	// Bulk operations - requires admin permissions
	roles.POST("/bulk", r.roleHandler.BulkCreateRoles, r.enhancedAuth.RequirePermission(constants.PermRoleBulkCreate))
	roles.DELETE("/bulk", r.roleHandler.BulkDeleteRoles, r.enhancedAuth.RequirePermission(constants.PermRoleBulkDelete))
	roles.POST("/initialize", r.roleHandler.InitializeDefaultRoles, r.enhancedAuth.RequireRole(constants.RoleSuperAdmin))

	// Individual role operations
	roles.GET("/slug/:slug", r.roleHandler.GetRoleBySlug, r.enhancedAuth.RequirePermission(constants.PermRoleRead))
	roles.GET("/:id", r.roleHandler.GetRole, r.enhancedAuth.RequirePermission(constants.PermRoleRead))
	roles.PUT("/:id", r.roleHandler.UpdateRole, r.enhancedAuth.RequirePermission(constants.PermRoleUpdate))
	roles.DELETE("/:id", r.roleHandler.DeleteRole, r.enhancedAuth.RequirePermission(constants.PermRoleDelete))

	// Role permission management - requires permission management
	roles.GET("/:id/permissions", r.roleHandler.GetRolePermissions, r.enhancedAuth.RequirePermission(constants.PermPermissionRead))
	roles.POST("/:id/permissions", r.roleHandler.AssignPermissions, r.enhancedAuth.RequirePermission(constants.PermPermissionAssign))
	roles.PUT("/:id/permissions", r.roleHandler.ReplacePermissions, r.enhancedAuth.RequirePermission(constants.PermPermissionAssign))
	roles.DELETE("/:id/permissions", r.roleHandler.RevokePermissions, r.enhancedAuth.RequirePermission(constants.PermPermissionRevoke))

	// Role user management - requires user role management
	roles.POST("/:id/users", r.roleHandler.AssignRoleToUser, r.enhancedAuth.RequirePermission(constants.PermUserAssignRole))
	roles.DELETE("/:id/users", r.roleHandler.RevokeRoleFromUser, r.enhancedAuth.RequirePermission(constants.PermUserRevokeRole))

	// Permission routes with strict access control
	permissions := v1.Group("/permissions")
	permissions.Use(r.enhancedAuth.RequireAuth()) // All permission routes require authentication

	// Permission management - requires permission management permissions
	permissions.POST("", r.permissionHandler.CreatePermission, r.enhancedAuth.RequirePermission(constants.PermPermissionCreate))
	permissions.GET("", r.permissionHandler.ListPermissions, r.enhancedAuth.RequirePermission(constants.PermPermissionRead))
	permissions.GET("/default", r.permissionHandler.GetDefaultPermissions, r.enhancedAuth.RequirePermission(constants.PermPermissionRead))
	permissions.GET("/system", r.permissionHandler.GetSystemPermissions, r.enhancedAuth.RequireRole(constants.RoleSuperAdmin))
	permissions.GET("/modules", r.permissionHandler.GetPermissionModules, r.enhancedAuth.RequirePermission(constants.PermPermissionRead))
	permissions.GET("/grouped", r.permissionHandler.GetPermissionsGrouped, r.enhancedAuth.RequirePermission(constants.PermPermissionRead))

	// Bulk operations - requires admin permissions
	permissions.POST("/bulk", r.permissionHandler.BulkCreatePermissions, r.enhancedAuth.RequirePermission(constants.PermPermissionBulkCreate))
	permissions.DELETE("/bulk", r.permissionHandler.BulkDeletePermissions, r.enhancedAuth.RequirePermission(constants.PermPermissionBulkDelete))
	permissions.POST("/initialize", r.permissionHandler.InitializeDefaultPermissions, r.enhancedAuth.RequireRole(constants.RoleSuperAdmin))

	// Validation endpoints
	permissions.POST("/validate/code", r.permissionHandler.ValidatePermissionCode, r.enhancedAuth.RequirePermission(constants.PermPermissionValidate))
	permissions.POST("/validate/action", r.permissionHandler.ValidateModuleResourceAction, r.enhancedAuth.RequirePermission(constants.PermPermissionValidate))

	// Individual permission operations
	permissions.GET("/code/:code", r.permissionHandler.GetPermissionByCode, r.enhancedAuth.RequirePermission(constants.PermPermissionRead))
	permissions.GET("/module/:module", r.permissionHandler.GetPermissionsByModule, r.enhancedAuth.RequirePermission(constants.PermPermissionRead))
	permissions.GET("/module/:module/resource/:resource", r.permissionHandler.GetPermissionsByResource, r.enhancedAuth.RequirePermission(constants.PermPermissionRead))
	permissions.GET("/module/:module/resource/:resource/action/:action", r.permissionHandler.GetPermissionByAction, r.enhancedAuth.RequirePermission(constants.PermPermissionRead))
	permissions.GET("/:id", r.permissionHandler.GetPermission, r.enhancedAuth.RequirePermission(constants.PermPermissionRead))
	permissions.PUT("/:id", r.permissionHandler.UpdatePermission, r.enhancedAuth.RequirePermission(constants.PermPermissionUpdate))
	permissions.DELETE("/:id", r.permissionHandler.DeletePermission, r.enhancedAuth.RequirePermission(constants.PermPermissionDelete))

	// OIDC routes (placeholder) - public endpoints
	oidc := v1.Group("/oidc")
	oidc.GET("/.well-known/openid_configuration", r.placeholderHandler("oidc-discovery"))
	oidc.GET("/authorize", r.placeholderHandler("oidc-authorize"))
	oidc.POST("/token", r.placeholderHandler("oidc-token"))
	oidc.GET("/userinfo", r.placeholderHandler("oidc-userinfo"), r.enhancedAuth.RequireAuth())
	oidc.GET("/jwks", r.placeholderHandler("oidc-jwks"))

	// Admin routes - requires super admin role
	admin := v1.Group("/admin")
	admin.Use(r.enhancedAuth.RequireRole(constants.RoleSuperAdmin))
	admin.GET("/audit", r.placeholderHandler("audit-logs"))
	admin.GET("/health", r.placeholderHandler("admin-health"))
	admin.GET("/metrics", r.placeholderHandler("admin-metrics"))
	admin.POST("/cache/clear", r.placeholderHandler("clear-cache"))
}

// healthHandler provides health check endpoint
func (r *Router) healthHandler(c echo.Context) error {
	return c.JSON(200, map[string]interface{}{
		"status":  "ok",
		"service": "azth-sso",
		"version": "1.0.0",
	})
}

// placeholderHandler returns a placeholder response
func (r *Router) placeholderHandler(endpoint string) echo.HandlerFunc {
	return func(c echo.Context) error {
		return c.JSON(501, map[string]string{
			"message":  "Not implemented",
			"endpoint": endpoint,
		})
	}
}
