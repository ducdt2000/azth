package fx

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"go.uber.org/fx"

	"github.com/ducdt2000/azth/backend/internal/config"
	"github.com/ducdt2000/azth/backend/internal/server"
	"github.com/ducdt2000/azth/backend/pkg/logger"
)

// NewApp creates a new FX application with all modules wired together
func NewApp() *fx.App {
	return fx.New(
		// Core infrastructure modules
		ConfigModule,
		LoggerModule,
		TelemetryModule,
		DatabaseModule,
		RedisModule,

		// Business logic modules
		ServiceModule,
		RepositoryModule,

		// Server and handlers
		ServerModule,
		HandlerModule,

		// Application lifecycle
		fx.Invoke(runApplication),
	)
}

// runApplication starts the application and handles graceful shutdown
func runApplication(
	lifecycle fx.Lifecycle,
	server *server.Server,
	cfg *config.Config,
	logger *logger.Logger,
) {
	lifecycle.Append(fx.Hook{
		OnStart: func(ctx context.Context) error {
			logger.Info("Starting application...")

			// Start the server in a goroutine
			go func() {
				addr := fmt.Sprintf("%s:%d", cfg.Server.Address, cfg.Server.Port)
				logger.Info("Starting HTTP server", "address", addr)
				if err := server.Start(addr); err != nil && !errors.Is(err, http.ErrServerClosed) {
					logger.Error("Failed to start server", "error", err)
				}
			}()

			return nil
		},
		OnStop: func(ctx context.Context) error {
			logger.Info("Shutting down application...")
			return server.Shutdown(ctx)
		},
	})
}
