package fx

import (
	"context"

	"go.uber.org/fx"

	"github.com/ducdt2000/azth/backend/internal/config"
	"github.com/ducdt2000/azth/backend/internal/redis"
	"github.com/ducdt2000/azth/backend/pkg/logger"
)

// RedisModule provides Redis dependencies
var RedisModule = fx.Module("redis",
	fx.Provide(NewRedis),
	fx.Invoke(registerRedisLifecycle),
)

// NewRedis creates a new Redis client
func NewRedis(cfg *config.Config, logger *logger.Logger) (*redis.Client, error) {
	return redis.New(cfg.Redis, logger)
}

// registerRedisLifecycle registers the Redis shutdown hook
func registerRedisLifecycle(lc fx.Lifecycle, redisClient *redis.Client, logger *logger.Logger) {
	lc.Append(fx.Hook{
		OnStop: func(ctx context.Context) error {
			logger.Info("Closing Redis connection...")
			return redisClient.Close()
		},
	})
}
