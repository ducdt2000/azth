package kv

import (
	"fmt"

	"github.com/ducdt2000/azth/backend/internal/config"
	"github.com/ducdt2000/azth/backend/pkg/logger"
)

// NewKVStore creates a new KVStore implementation based on configuration
// If Redis is enabled and configured, it returns a RedisKV instance
// Otherwise, it returns a LocalKV instance as fallback
func NewKVStore(cfg config.RedisConfig, logger *logger.Logger) (KVStore, error) {
	if cfg.Enabled {
		// Try to create Redis connection first
		if redisStore, err := NewRedisKV(cfg, logger); err == nil {
			logger.Info("Using Redis KV store")
			return redisStore, nil
		} else {
			logger.Warn("Failed to connect to Redis, falling back to local KV store", "error", err)
		}
	} else {
		logger.Info("Redis disabled, using local KV store")
	}

	// Fallback to local KV store
	localStore, err := NewLocalKV(cfg.LocalStore, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create local KV store: %w", err)
	}

	return localStore, nil
}

// MustNewKVStore creates a new KVStore and panics on error
// Should only be used during application initialization
func MustNewKVStore(cfg config.RedisConfig, logger *logger.Logger) KVStore {
	store, err := NewKVStore(cfg, logger)
	if err != nil {
		panic(fmt.Sprintf("failed to create KV store: %v", err))
	}
	return store
}
