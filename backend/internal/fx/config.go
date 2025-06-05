package fx

import (
	"go.uber.org/fx"

	"github.com/ducdt2000/azth/backend/internal/config"
)

// ConfigModule provides configuration dependency
var ConfigModule = fx.Module("config",
	fx.Provide(NewConfig),
)

// NewConfig loads and provides application configuration
func NewConfig() (*config.Config, error) {
	return config.Load()
}
