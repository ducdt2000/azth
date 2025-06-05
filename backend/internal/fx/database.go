package fx

import (
	"context"

	"go.uber.org/fx"

	"github.com/ducdt2000/azth/backend/internal/config"
	"github.com/ducdt2000/azth/backend/internal/db"
	"github.com/ducdt2000/azth/backend/pkg/logger"
)

// DatabaseModule provides database dependencies
var DatabaseModule = fx.Module("database",
	fx.Provide(NewDatabase),
	fx.Invoke(registerDatabaseLifecycle),
)

// NewDatabase creates a new database connection
func NewDatabase(cfg *config.Config, logger *logger.Logger) (*db.DB, error) {
	database, err := db.New(cfg.Database, logger)
	if err != nil {
		return nil, err
	}

	// Run database migrations
	if err := database.Migrate(); err != nil {
		database.Close()
		return nil, err
	}

	return database, nil
}

// registerDatabaseLifecycle registers the database shutdown hook
func registerDatabaseLifecycle(lc fx.Lifecycle, database *db.DB, logger *logger.Logger) {
	lc.Append(fx.Hook{
		OnStop: func(ctx context.Context) error {
			logger.Info("Closing database connection...")
			return database.Close()
		},
	})
}
