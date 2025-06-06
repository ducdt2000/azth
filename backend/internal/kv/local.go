package kv

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/ducdt2000/azth/backend/internal/config"
	"github.com/ducdt2000/azth/backend/pkg/logger"
)

// LocalKV implements the KVStore interface using local storage
type LocalKV struct {
	mu          sync.RWMutex
	data        map[string]*entry
	config      config.LocalKVConfig
	logger      *logger.Logger
	stopCleanup chan struct{}
}

// entry represents a stored value with expiration and type information
type entry struct {
	Value     interface{} `json:"value"`
	ExpiresAt time.Time   `json:"expires_at"`
	Type      string      `json:"type"` // string, hash, list, set
}

// NewLocalKV creates a new local KV store
func NewLocalKV(cfg config.LocalKVConfig, logger *logger.Logger) (*LocalKV, error) {
	kv := &LocalKV{
		data:        make(map[string]*entry),
		config:      cfg,
		logger:      logger,
		stopCleanup: make(chan struct{}),
	}

	// Load from file if file-based storage is configured
	if cfg.Type == "file" && cfg.FilePath != "" {
		if err := kv.loadFromFile(); err != nil {
			logger.Warn("Failed to load data from file", "error", err, "file", cfg.FilePath)
		}
	}

	// Start cleanup goroutine
	go kv.cleanupExpired()

	logger.Info("Local KV store initialized",
		"type", cfg.Type,
		"file_path", cfg.FilePath,
		"max_size", cfg.MaxSize,
		"cleanup_interval", cfg.CleanupInterval,
		"default_ttl", cfg.DefaultTTL,
	)

	return kv, nil
}

// Set stores a key-value pair with optional expiration
func (kv *LocalKV) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	kv.mu.Lock()
	defer kv.mu.Unlock()

	var expiresAt time.Time
	if expiration > 0 {
		expiresAt = time.Now().Add(expiration)
	} else if kv.config.DefaultTTL > 0 {
		expiresAt = time.Now().Add(kv.config.DefaultTTL)
	}

	kv.data[key] = &entry{
		Value:     value,
		ExpiresAt: expiresAt,
		Type:      "string",
	}

	return kv.persistIfNeeded()
}

// Get retrieves a value by key
func (kv *LocalKV) Get(ctx context.Context, key string) (string, error) {
	kv.mu.RLock()
	defer kv.mu.RUnlock()

	entry, exists := kv.data[key]
	if !exists {
		return "", fmt.Errorf("key not found")
	}

	if !entry.ExpiresAt.IsZero() && time.Now().After(entry.ExpiresAt) {
		return "", fmt.Errorf("key expired")
	}

	return fmt.Sprintf("%v", entry.Value), nil
}

// Del deletes one or more keys
func (kv *LocalKV) Del(ctx context.Context, keys ...string) error {
	kv.mu.Lock()
	defer kv.mu.Unlock()

	for _, key := range keys {
		delete(kv.data, key)
	}

	return kv.persistIfNeeded()
}

// Exists checks if a key exists and is not expired
func (kv *LocalKV) Exists(ctx context.Context, key string) (bool, error) {
	kv.mu.RLock()
	defer kv.mu.RUnlock()

	entry, exists := kv.data[key]
	if !exists {
		return false, nil
	}

	if !entry.ExpiresAt.IsZero() && time.Now().After(entry.ExpiresAt) {
		return false, nil
	}

	return true, nil
}

// SetNX sets a key only if it doesn't exist
func (kv *LocalKV) SetNX(ctx context.Context, key string, value interface{}, expiration time.Duration) (bool, error) {
	kv.mu.Lock()
	defer kv.mu.Unlock()

	// Check if key exists and is not expired
	if entry, exists := kv.data[key]; exists {
		if entry.ExpiresAt.IsZero() || time.Now().Before(entry.ExpiresAt) {
			return false, nil // Key already exists
		}
	}

	var expiresAt time.Time
	if expiration > 0 {
		expiresAt = time.Now().Add(expiration)
	} else if kv.config.DefaultTTL > 0 {
		expiresAt = time.Now().Add(kv.config.DefaultTTL)
	}

	kv.data[key] = &entry{
		Value:     value,
		ExpiresAt: expiresAt,
		Type:      "string",
	}

	if err := kv.persistIfNeeded(); err != nil {
		return false, err
	}

	return true, nil
}

// Incr increments a numeric value
func (kv *LocalKV) Incr(ctx context.Context, key string) (int64, error) {
	kv.mu.Lock()
	defer kv.mu.Unlock()

	existingEntry, exists := kv.data[key]
	var current int64 = 0

	if exists && (existingEntry.ExpiresAt.IsZero() || time.Now().Before(existingEntry.ExpiresAt)) {
		if val, err := strconv.ParseInt(fmt.Sprintf("%v", existingEntry.Value), 10, 64); err == nil {
			current = val
		}
	}

	current++
	var expiresAt time.Time
	if exists {
		expiresAt = existingEntry.ExpiresAt
	} else if kv.config.DefaultTTL > 0 {
		expiresAt = time.Now().Add(kv.config.DefaultTTL)
	}

	kv.data[key] = &entry{
		Value:     current,
		ExpiresAt: expiresAt,
		Type:      "string",
	}

	if err := kv.persistIfNeeded(); err != nil {
		return 0, err
	}

	return current, nil
}

// Decr decrements a numeric value
func (kv *LocalKV) Decr(ctx context.Context, key string) (int64, error) {
	kv.mu.Lock()
	defer kv.mu.Unlock()

	existingEntry, exists := kv.data[key]
	var current int64 = 0

	if exists && (existingEntry.ExpiresAt.IsZero() || time.Now().Before(existingEntry.ExpiresAt)) {
		if val, err := strconv.ParseInt(fmt.Sprintf("%v", existingEntry.Value), 10, 64); err == nil {
			current = val
		}
	}

	current--
	var expiresAt time.Time
	if exists {
		expiresAt = existingEntry.ExpiresAt
	} else if kv.config.DefaultTTL > 0 {
		expiresAt = time.Now().Add(kv.config.DefaultTTL)
	}

	kv.data[key] = &entry{
		Value:     current,
		ExpiresAt: expiresAt,
		Type:      "string",
	}

	if err := kv.persistIfNeeded(); err != nil {
		return 0, err
	}

	return current, nil
}

// Expire sets expiration for a key
func (kv *LocalKV) Expire(ctx context.Context, key string, expiration time.Duration) error {
	kv.mu.Lock()
	defer kv.mu.Unlock()

	entry, exists := kv.data[key]
	if !exists {
		return fmt.Errorf("key not found")
	}

	entry.ExpiresAt = time.Now().Add(expiration)
	return kv.persistIfNeeded()
}

// TTL returns the time to live for a key
func (kv *LocalKV) TTL(ctx context.Context, key string) (time.Duration, error) {
	kv.mu.RLock()
	defer kv.mu.RUnlock()

	entry, exists := kv.data[key]
	if !exists {
		return -2 * time.Second, nil // Key doesn't exist
	}

	if entry.ExpiresAt.IsZero() {
		return -1 * time.Second, nil // No expiration
	}

	ttl := time.Until(entry.ExpiresAt)
	if ttl <= 0 {
		return -2 * time.Second, nil // Key expired
	}

	return ttl, nil
}

// Simplified hash, list, and set operations for basic compatibility
func (kv *LocalKV) HSet(ctx context.Context, key, field string, value interface{}) error {
	return kv.Set(ctx, key+":"+field, value, 0)
}

func (kv *LocalKV) HGet(ctx context.Context, key, field string) (string, error) {
	return kv.Get(ctx, key+":"+field)
}

func (kv *LocalKV) HGetAll(ctx context.Context, key string) (map[string]string, error) {
	// Simplified implementation - just return empty map for compatibility
	return make(map[string]string), nil
}

func (kv *LocalKV) HDel(ctx context.Context, key string, fields ...string) error {
	keys := make([]string, len(fields))
	for i, field := range fields {
		keys[i] = key + ":" + field
	}
	return kv.Del(ctx, keys...)
}

// List operations - simplified implementation
func (kv *LocalKV) LPush(ctx context.Context, key string, values ...interface{}) error {
	return kv.Set(ctx, key+":list", values, 0)
}

func (kv *LocalKV) RPush(ctx context.Context, key string, values ...interface{}) error {
	return kv.Set(ctx, key+":list", values, 0)
}

func (kv *LocalKV) LPop(ctx context.Context, key string) (string, error) {
	return "", fmt.Errorf("not implemented")
}

func (kv *LocalKV) RPop(ctx context.Context, key string) (string, error) {
	return "", fmt.Errorf("not implemented")
}

func (kv *LocalKV) LLen(ctx context.Context, key string) (int64, error) {
	return 0, nil
}

// Set operations - simplified implementation
func (kv *LocalKV) SAdd(ctx context.Context, key string, members ...interface{}) error {
	return kv.Set(ctx, key+":set", members, 0)
}

func (kv *LocalKV) SRem(ctx context.Context, key string, members ...interface{}) error {
	return kv.Del(ctx, key+":set")
}

func (kv *LocalKV) SMembers(ctx context.Context, key string) ([]string, error) {
	return []string{}, nil
}

func (kv *LocalKV) SIsMember(ctx context.Context, key string, member interface{}) (bool, error) {
	return false, nil
}

// Administrative operations
func (kv *LocalKV) Health() error {
	return nil // Local storage is always healthy
}

func (kv *LocalKV) Close() error {
	close(kv.stopCleanup)

	if kv.config.Type == "file" {
		return kv.persistToFile()
	}

	return nil
}

func (kv *LocalKV) Stats() map[string]interface{} {
	kv.mu.RLock()
	defer kv.mu.RUnlock()

	return map[string]interface{}{
		"keys":         len(kv.data),
		"type":         kv.config.Type,
		"file_path":    kv.config.FilePath,
		"max_size":     kv.config.MaxSize,
		"memory_usage": kv.estimateMemoryUsage(),
	}
}

func (kv *LocalKV) FlushAll(ctx context.Context) error {
	kv.mu.Lock()
	defer kv.mu.Unlock()

	kv.data = make(map[string]*entry)
	return kv.persistIfNeeded()
}

// Helper methods
func (kv *LocalKV) cleanupExpired() {
	ticker := time.NewTicker(kv.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			kv.mu.Lock()
			now := time.Now()
			for key, entry := range kv.data {
				if !entry.ExpiresAt.IsZero() && now.After(entry.ExpiresAt) {
					delete(kv.data, key)
				}
			}
			kv.persistIfNeeded()
			kv.mu.Unlock()

		case <-kv.stopCleanup:
			return
		}
	}
}

func (kv *LocalKV) persistIfNeeded() error {
	if kv.config.Type == "file" {
		return kv.persistToFile()
	}
	return nil
}

func (kv *LocalKV) persistToFile() error {
	if kv.config.FilePath == "" {
		return nil
	}

	// Create directory if it doesn't exist
	if err := os.MkdirAll(filepath.Dir(kv.config.FilePath), 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	file, err := os.Create(kv.config.FilePath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	return encoder.Encode(kv.data)
}

func (kv *LocalKV) loadFromFile() error {
	if kv.config.FilePath == "" {
		return nil
	}

	file, err := os.Open(kv.config.FilePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // File doesn't exist yet, that's OK
		}
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	return decoder.Decode(&kv.data)
}

func (kv *LocalKV) estimateMemoryUsage() int64 {
	// Rough estimate of memory usage
	var size int64
	for key, entry := range kv.data {
		size += int64(len(key))
		size += int64(len(fmt.Sprintf("%v", entry.Value)))
		size += 64 // rough estimate for metadata
	}
	return size
}
