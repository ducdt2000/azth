package server

import (
	"context"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"

	"github.com/ducdt2000/azth/backend/internal/config"
	"github.com/ducdt2000/azth/backend/internal/db"
	"github.com/ducdt2000/azth/backend/internal/redis"
	"github.com/ducdt2000/azth/backend/pkg/logger"
)

// Server represents the HTTP server
type Server struct {
	echo   *echo.Echo
	db     *db.DB
	redis  *redis.Client
	logger *logger.Logger
	config config.ServerConfig
}

// New creates a new HTTP server
func New(cfg config.ServerConfig, database *db.DB, redisClient *redis.Client, logger *logger.Logger) *Server {
	e := echo.New()

	// Configure Echo
	e.HideBanner = true
	e.HidePort = true

	// Add middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.RequestID())

	// CORS middleware
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins:     cfg.CORS.AllowedOrigins,
		AllowMethods:     cfg.CORS.AllowedMethods,
		AllowHeaders:     cfg.CORS.AllowedHeaders,
		ExposeHeaders:    cfg.CORS.ExposedHeaders,
		AllowCredentials: cfg.CORS.AllowCredentials,
		MaxAge:           cfg.CORS.MaxAge,
	}))

	// Timeout middleware
	e.Use(middleware.TimeoutWithConfig(middleware.TimeoutConfig{
		Timeout: 30 * time.Second,
	}))

	// Create server instance
	server := &Server{
		echo:   e,
		db:     database,
		redis:  redisClient,
		logger: logger,
		config: cfg,
	}

	// Setup routes
	server.setupRoutes()

	return server
}

// Start starts the HTTP server
func (s *Server) Start(address string) error {
	s.logger.Info("Starting HTTP server", "address", address)

	// Configure timeouts
	s.echo.Server.ReadTimeout = s.config.ReadTimeout
	s.echo.Server.WriteTimeout = s.config.WriteTimeout
	s.echo.Server.IdleTimeout = s.config.IdleTimeout

	// Start server
	if s.config.TLS.Enabled {
		return s.echo.StartTLS(address, s.config.TLS.CertFile, s.config.TLS.KeyFile)
	}
	return s.echo.Start(address)
}

// Shutdown gracefully shuts down the server
func (s *Server) Shutdown(ctx context.Context) error {
	s.logger.Info("Shutting down HTTP server")
	return s.echo.Shutdown(ctx)
}

// setupRoutes configures all routes
func (s *Server) setupRoutes() {
	// Health check
	s.echo.GET("/health", s.healthHandler)

	// API v1 routes
	v1 := s.echo.Group("/api/v1")

	// Auth routes
	auth := v1.Group("/auth")
	auth.POST("/login", s.loginHandler)
	auth.POST("/register", s.registerHandler)
	auth.POST("/logout", s.logoutHandler)
	auth.GET("/me", s.meHandler)
	auth.POST("/refresh", s.refreshHandler)

	// OIDC routes
	oidc := v1.Group("/oidc")
	oidc.GET("/.well-known/openid_configuration", s.oidcDiscoveryHandler)
	oidc.GET("/authorize", s.oidcAuthorizeHandler)
	oidc.POST("/token", s.oidcTokenHandler)
	oidc.GET("/userinfo", s.oidcUserInfoHandler)
	oidc.GET("/jwks", s.oidcJWKSHandler)

	// Admin routes (protected)
	admin := v1.Group("/admin")
	admin.Use(s.authMiddleware) // Add authentication middleware
	admin.GET("/users", s.listUsersHandler)
	admin.GET("/tenants", s.listTenantsHandler)
	admin.GET("/audit", s.listAuditLogsHandler)
}

// Health check handler
func (s *Server) healthHandler(c echo.Context) error {
	return c.JSON(200, map[string]interface{}{
		"status":    "ok",
		"timestamp": time.Now().Unix(),
		"version":   "1.0.0",
	})
}

// Placeholder handlers - these will be implemented later
func (s *Server) loginHandler(c echo.Context) error {
	return c.JSON(501, map[string]string{"message": "Not implemented"})
}

func (s *Server) registerHandler(c echo.Context) error {
	return c.JSON(501, map[string]string{"message": "Not implemented"})
}

func (s *Server) logoutHandler(c echo.Context) error {
	return c.JSON(501, map[string]string{"message": "Not implemented"})
}

func (s *Server) meHandler(c echo.Context) error {
	return c.JSON(501, map[string]string{"message": "Not implemented"})
}

func (s *Server) refreshHandler(c echo.Context) error {
	return c.JSON(501, map[string]string{"message": "Not implemented"})
}

func (s *Server) oidcDiscoveryHandler(c echo.Context) error {
	return c.JSON(501, map[string]string{"message": "Not implemented"})
}

func (s *Server) oidcAuthorizeHandler(c echo.Context) error {
	return c.JSON(501, map[string]string{"message": "Not implemented"})
}

func (s *Server) oidcTokenHandler(c echo.Context) error {
	return c.JSON(501, map[string]string{"message": "Not implemented"})
}

func (s *Server) oidcUserInfoHandler(c echo.Context) error {
	return c.JSON(501, map[string]string{"message": "Not implemented"})
}

func (s *Server) oidcJWKSHandler(c echo.Context) error {
	return c.JSON(501, map[string]string{"message": "Not implemented"})
}

func (s *Server) listUsersHandler(c echo.Context) error {
	return c.JSON(501, map[string]string{"message": "Not implemented"})
}

func (s *Server) listTenantsHandler(c echo.Context) error {
	return c.JSON(501, map[string]string{"message": "Not implemented"})
}

func (s *Server) listAuditLogsHandler(c echo.Context) error {
	return c.JSON(501, map[string]string{"message": "Not implemented"})
}

// Auth middleware - placeholder
func (s *Server) authMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		// TODO: Implement JWT authentication
		return next(c)
	}
}
