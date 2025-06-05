package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ducdt2000/azth/backend/internal/config"
	"github.com/ducdt2000/azth/backend/internal/db"
	"github.com/ducdt2000/azth/backend/internal/redis"
	"github.com/ducdt2000/azth/backend/internal/server"
	"github.com/ducdt2000/azth/backend/pkg/logger"
	"github.com/ducdt2000/azth/backend/pkg/telemetry"
)

// @title AZTH SSO & OIDC Server API
// @version 1.0
// @description Multi-tenant SSO and OIDC server with user management
// @termsOfService http://azth.ducdt.dev/terms/
// @contact.name API Support
// @contact.url http://azth.ducdt.dev/support
// @contact.email support@ducdt.dev
// @license.name MIT
// @license.url https://opensource.org/licenses/MIT
// @host localhost:8080
// @BasePath /api/v1
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description Type "Bearer" followed by a space and JWT token.
func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize logger
	logger := logger.New(cfg.Logger.Level, cfg.Logger.Format)
	defer logger.Sync()

	// Initialize OpenTelemetry
	otelShutdown, err := telemetry.Setup(cfg.Telemetry, logger)
	if err != nil {
		logger.Fatal("Failed to setup OpenTelemetry", "error", err)
	}
	defer otelShutdown()

	// Initialize database
	database, err := db.New(cfg.Database, logger)
	if err != nil {
		logger.Fatal("Failed to initialize database", "error", err)
	}
	defer database.Close()

	// Run database migrations
	if err := database.Migrate(); err != nil {
		logger.Fatal("Failed to run database migrations", "error", err)
	}

	// Initialize Redis
	redisClient, err := redis.New(cfg.Redis, logger)
	if err != nil {
		logger.Fatal("Failed to initialize Redis", "error", err)
	}
	defer redisClient.Close()

	// Initialize server with dependencies
	srv := server.New(cfg.Server, database, redisClient, logger)

	// Start server in a goroutine
	go func() {
		logger.Info("Starting server", "address", cfg.Server.Address, "port", cfg.Server.Port)
		if err := srv.Start(fmt.Sprintf("%s:%d", cfg.Server.Address, cfg.Server.Port)); err != nil && err != http.ErrServerClosed {
			logger.Fatal("Failed to start server", "error", err)
		}
	}()

	// Setup graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("Shutting down server...")

	// Give outstanding requests 30 seconds to complete
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logger.Fatal("Server forced to shutdown", "error", err)
	}

	logger.Info("Server shutdown complete")
}
