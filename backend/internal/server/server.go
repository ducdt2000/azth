package server

import (
	"context"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"

	"github.com/ducdt2000/azth/backend/internal/config"
	"github.com/ducdt2000/azth/backend/pkg/logger"
	"github.com/ducdt2000/azth/backend/pkg/validator"
)

// Server represents the HTTP server
type Server struct {
	echo   *echo.Echo
	router *Router
	logger *logger.Logger
	config config.ServerConfig
}

// New creates a new HTTP server
func New(cfg config.ServerConfig, router *Router, logger *logger.Logger) *Server {
	e := echo.New()

	// Configure Echo
	e.HideBanner = true
	e.HidePort = true

	// Add middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.RequestID())

	// Setup custom validator
	validator.SetupEchoValidator(e)

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
		router: router,
		logger: logger,
		config: cfg,
	}

	// Setup routes using the injected router
	router.SetupRoutes(e)

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
