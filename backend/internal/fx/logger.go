package fx

import (
	"context"

	"go.uber.org/fx"

	"github.com/ducdt2000/azth/backend/internal/config"
	"github.com/ducdt2000/azth/backend/pkg/logger"
)

// LoggerModule provides logger dependency
var LoggerModule = fx.Module("logger",
	fx.Provide(NewLogger),
	fx.Invoke(registerLoggerLifecycle),
)

// NewLogger creates a new logger instance
func NewLogger(cfg *config.Config) *logger.Logger {
	return logger.New(cfg.Logger.Level, cfg.Logger.Format)
}

// registerLoggerLifecycle registers the logger shutdown hook
func registerLoggerLifecycle(lc fx.Lifecycle, logger *logger.Logger) {
	lc.Append(fx.Hook{
		OnStop: func(ctx context.Context) error {
			return logger.Sync()
		},
	})
}
