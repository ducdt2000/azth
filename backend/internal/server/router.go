package server

import (
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"

	permissionHandlers "github.com/ducdt2000/azth/backend/internal/modules/permission/handlers"
	roleHandlers "github.com/ducdt2000/azth/backend/internal/modules/role/handlers"
	tenantHandlers "github.com/ducdt2000/azth/backend/internal/modules/tenant/handlers"
	userHandlers "github.com/ducdt2000/azth/backend/internal/modules/user/handlers"
	"github.com/ducdt2000/azth/backend/pkg/logger"
)

// Router handles HTTP routing with dependency-injected handlers
type Router struct {
	userHandler       *userHandlers.UserHandler
	tenantHandler     *tenantHandlers.TenantHandler
	roleHandler       *roleHandlers.RoleHandler
	permissionHandler *permissionHandlers.PermissionHandler
	logger            *logger.Logger
}

// NewRouter creates a new router with injected handlers
func NewRouter(
	userHandler *userHandlers.UserHandler,
	tenantHandler *tenantHandlers.TenantHandler,
	roleHandler *roleHandlers.RoleHandler,
	permissionHandler *permissionHandlers.PermissionHandler,
	logger *logger.Logger,
) *Router {
	return &Router{
		userHandler:       userHandler,
		tenantHandler:     tenantHandler,
		roleHandler:       roleHandler,
		permissionHandler: permissionHandler,
		logger:            logger,
	}
}

// SetupRoutes configures all routes with proper handlers
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

	// User routes
	users := v1.Group("/users")
	users.POST("", r.userHandler.CreateUser)
	users.GET("", r.userHandler.ListUsers)
	users.GET("/stats", r.userHandler.GetUserStats)
	users.POST("/bulk", r.userHandler.BulkUpdateUsers)
	users.GET("/:id", r.userHandler.GetUser)
	users.PUT("/:id", r.userHandler.UpdateUser)
	users.DELETE("/:id", r.userHandler.DeleteUser)
	users.PUT("/:id/password", r.userHandler.ChangePassword)
	// User role and permission routes
	users.GET("/:user_id/roles", r.roleHandler.GetUserRoles)
	users.GET("/:user_id/permissions", r.roleHandler.GetUserPermissions)

	// Tenant routes
	tenants := v1.Group("/tenants")
	tenants.POST("", r.tenantHandler.CreateTenant)
	tenants.GET("", r.tenantHandler.ListTenants)
	tenants.GET("/:id", r.tenantHandler.GetTenant)
	tenants.PUT("/:id", r.tenantHandler.UpdateTenant)
	tenants.DELETE("/:id", r.tenantHandler.DeleteTenant)
	tenants.PUT("/:id/activate", r.tenantHandler.ActivateTenant)
	tenants.PUT("/:id/deactivate", r.tenantHandler.DeactivateTenant)
	tenants.PUT("/:id/suspend", r.tenantHandler.SuspendTenant)
	tenants.GET("/slug/:slug", r.tenantHandler.GetTenantBySlug)
	tenants.POST("/bulk", r.tenantHandler.BulkUpdateTenants)
	// Tenant role routes
	tenants.GET("/:tenant_id/roles", r.roleHandler.GetRolesByTenant)

	// Role routes
	roles := v1.Group("/roles")
	roles.POST("", r.roleHandler.CreateRole)
	roles.GET("", r.roleHandler.ListRoles)
	roles.GET("/stats", r.roleHandler.GetRoleStats)
	roles.GET("/global", r.roleHandler.GetGlobalRoles)
	roles.GET("/system", r.roleHandler.GetSystemRoles)
	roles.GET("/default", r.roleHandler.GetDefaultRoles)
	roles.POST("/bulk", r.roleHandler.BulkCreateRoles)
	roles.DELETE("/bulk", r.roleHandler.BulkDeleteRoles)
	roles.POST("/initialize", r.roleHandler.InitializeDefaultRoles)
	roles.GET("/slug/:slug", r.roleHandler.GetRoleBySlug)
	roles.GET("/:id", r.roleHandler.GetRole)
	roles.PUT("/:id", r.roleHandler.UpdateRole)
	roles.DELETE("/:id", r.roleHandler.DeleteRole)
	// Role permission management
	roles.GET("/:id/permissions", r.roleHandler.GetRolePermissions)
	roles.POST("/:id/permissions", r.roleHandler.AssignPermissions)
	roles.PUT("/:id/permissions", r.roleHandler.ReplacePermissions)
	roles.DELETE("/:id/permissions", r.roleHandler.RevokePermissions)
	// Role user management
	roles.POST("/:id/users", r.roleHandler.AssignRoleToUser)
	roles.DELETE("/:id/users", r.roleHandler.RevokeRoleFromUser)

	// Permission routes
	permissions := v1.Group("/permissions")
	permissions.POST("", r.permissionHandler.CreatePermission)
	permissions.GET("", r.permissionHandler.ListPermissions)
	permissions.GET("/default", r.permissionHandler.GetDefaultPermissions)
	permissions.GET("/system", r.permissionHandler.GetSystemPermissions)
	permissions.GET("/modules", r.permissionHandler.GetPermissionModules)
	permissions.GET("/grouped", r.permissionHandler.GetPermissionsGrouped)
	permissions.POST("/bulk", r.permissionHandler.BulkCreatePermissions)
	permissions.DELETE("/bulk", r.permissionHandler.BulkDeletePermissions)
	permissions.POST("/initialize", r.permissionHandler.InitializeDefaultPermissions)
	permissions.POST("/validate/code", r.permissionHandler.ValidatePermissionCode)
	permissions.POST("/validate/action", r.permissionHandler.ValidateModuleResourceAction)
	permissions.GET("/code/:code", r.permissionHandler.GetPermissionByCode)
	permissions.GET("/module/:module", r.permissionHandler.GetPermissionsByModule)
	permissions.GET("/module/:module/resource/:resource", r.permissionHandler.GetPermissionsByResource)
	permissions.GET("/module/:module/resource/:resource/action/:action", r.permissionHandler.GetPermissionByAction)
	permissions.GET("/:id", r.permissionHandler.GetPermission)
	permissions.PUT("/:id", r.permissionHandler.UpdatePermission)
	permissions.DELETE("/:id", r.permissionHandler.DeletePermission)

	// Auth routes (placeholder)
	auth := v1.Group("/auth")
	auth.POST("/login", r.placeholderHandler("login"))
	auth.POST("/register", r.placeholderHandler("register"))
	auth.POST("/logout", r.placeholderHandler("logout"))
	auth.GET("/me", r.placeholderHandler("me"))
	auth.POST("/refresh", r.placeholderHandler("refresh"))

	// OIDC routes (placeholder)
	oidc := v1.Group("/oidc")
	oidc.GET("/.well-known/openid_configuration", r.placeholderHandler("oidc-discovery"))
	oidc.GET("/authorize", r.placeholderHandler("oidc-authorize"))
	oidc.POST("/token", r.placeholderHandler("oidc-token"))
	oidc.GET("/userinfo", r.placeholderHandler("oidc-userinfo"))
	oidc.GET("/jwks", r.placeholderHandler("oidc-jwks"))

	// Admin routes (placeholder)
	admin := v1.Group("/admin")
	admin.Use(r.authMiddleware) // Add authentication middleware
	admin.GET("/audit", r.placeholderHandler("audit-logs"))
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

// authMiddleware is a placeholder authentication middleware
func (r *Router) authMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		// TODO: Implement JWT authentication
		// For now, just pass through
		return next(c)
	}
}
