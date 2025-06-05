package server

import (
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"

	userHandlers "github.com/ducdt2000/azth/backend/internal/modules/user/handlers"
	"github.com/ducdt2000/azth/backend/pkg/logger"
)

// Router handles HTTP routing with dependency-injected handlers
type Router struct {
	userHandler *userHandlers.UserHandler
	logger      *logger.Logger
}

// NewRouter creates a new router with injected handlers
func NewRouter(
	userHandler *userHandlers.UserHandler,
	logger *logger.Logger,
) *Router {
	return &Router{
		userHandler: userHandler,
		logger:      logger,
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

	// TODO: Add tenant routes
	// tenants := v1.Group("/tenants")
	// tenants.POST("", r.tenantHandler.CreateTenant)
	// tenants.GET("", r.tenantHandler.ListTenants)
	// tenants.GET("/:id", r.tenantHandler.GetTenant)
	// tenants.PUT("/:id", r.tenantHandler.UpdateTenant)
	// tenants.DELETE("/:id", r.tenantHandler.DeleteTenant)

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
