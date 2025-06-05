package fx

import (
	"context"

	"go.uber.org/fx"

	"github.com/ducdt2000/azth/backend/internal/config"
	"github.com/ducdt2000/azth/backend/pkg/logger"
	"github.com/ducdt2000/azth/backend/pkg/telemetry"
)

// TelemetryModule provides telemetry dependencies
var TelemetryModule = fx.Module("telemetry",
	fx.Invoke(setupTelemetry),
)

// TelemetryShutdown holds the telemetry shutdown function
type TelemetryShutdown func()

// setupTelemetry initializes OpenTelemetry and registers shutdown hook
func setupTelemetry(lc fx.Lifecycle, cfg *config.Config, logger *logger.Logger) error {
	var shutdownFn func()

	lc.Append(fx.Hook{
		OnStart: func(ctx context.Context) error {
			logger.Info("Initializing OpenTelemetry...")

			shutdown, err := telemetry.Setup(cfg.Telemetry, logger)
			if err != nil {
				return err
			}
			shutdownFn = shutdown

			logger.Info("OpenTelemetry initialized successfully")
			return nil
		},
		OnStop: func(ctx context.Context) error {
			if shutdownFn != nil {
				logger.Info("Shutting down OpenTelemetry...")
				shutdownFn()
			}
			return nil
		},
	})

	return nil
}
