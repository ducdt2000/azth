package redis

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/ducdt2000/azth/backend/internal/config"
	"github.com/ducdt2000/azth/backend/pkg/logger"
)

// Client wraps Redis client with additional methods
type Client struct {
	*redis.Client
	logger *logger.Logger
	config config.RedisConfig
}

// New creates a new Redis client
func New(cfg config.RedisConfig, logger *logger.Logger) (*Client, error) {
	// Build Redis options
	opts := &redis.Options{
		DB:           cfg.DB,
		PoolSize:     cfg.PoolSize,
		MinIdleConns: cfg.MinIdleConn,
		DialTimeout:  cfg.DialTimeout,
		ReadTimeout:  cfg.ReadTimeout,
	}

	// Set address
	if cfg.URL != "" {
		parsedOpts, err := redis.ParseURL(cfg.URL)
		if err != nil {
			return nil, fmt.Errorf("failed to parse Redis URL: %w", err)
		}
		opts = parsedOpts
	} else {
		opts.Addr = fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
		opts.Password = cfg.Password
	}

	// Create Redis client
	rdb := redis.NewClient(opts)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := rdb.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to ping Redis: %w", err)
	}

	logger.Info("Redis connected",
		"addr", opts.Addr,
		"db", opts.DB,
		"pool_size", opts.PoolSize,
		"min_idle_conns", opts.MinIdleConns,
	)

	return &Client{
		Client: rdb,
		logger: logger,
		config: cfg,
	}, nil
}

// Close closes the Redis connection
func (c *Client) Close() error {
	c.logger.Info("Closing Redis connection")
	return c.Client.Close()
}

// Health checks Redis health
func (c *Client) Health() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return c.Ping(ctx).Err()
}

// Stats returns Redis connection statistics
func (c *Client) Stats() map[string]interface{} {
	stats := c.PoolStats()
	return map[string]interface{}{
		"hits":        stats.Hits,
		"misses":      stats.Misses,
		"timeouts":    stats.Timeouts,
		"total_conns": stats.TotalConns,
		"idle_conns":  stats.IdleConns,
		"stale_conns": stats.StaleConns,
	}
}

// SetWithExpiration sets a key-value pair with expiration
func (c *Client) SetWithExpiration(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	return c.Set(ctx, key, value, expiration).Err()
}

// GetString gets a string value by key
func (c *Client) GetString(ctx context.Context, key string) (string, error) {
	return c.Get(ctx, key).Result()
}

// DeleteKeys deletes multiple keys
func (c *Client) DeleteKeys(ctx context.Context, keys ...string) error {
	if len(keys) == 0 {
		return nil
	}
	return c.Del(ctx, keys...).Err()
}

// Exists checks if a key exists
func (c *Client) Exists(ctx context.Context, key string) (bool, error) {
	result, err := c.Client.Exists(ctx, key).Result()
	return result > 0, err
}

// SetNX sets a key only if it doesn't exist (for distributed locks)
func (c *Client) SetNX(ctx context.Context, key string, value interface{}, expiration time.Duration) (bool, error) {
	return c.Client.SetNX(ctx, key, value, expiration).Result()
}
