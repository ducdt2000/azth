package db

import (
	"context"
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"

	"github.com/ducdt2000/azth/backend/internal/config"
	"github.com/ducdt2000/azth/backend/pkg/logger"
)

// DB wraps the database connection and provides additional methods
type DB struct {
	*sqlx.DB
	logger *logger.Logger
	config config.DatabaseConfig
}

// New creates a new database connection
func New(cfg config.DatabaseConfig, logger *logger.Logger) (*DB, error) {
	// Build connection string
	var connStr string
	if cfg.URL != "" {
		connStr = cfg.URL
	} else {
		connStr = fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
			cfg.Host, cfg.Port, cfg.User, cfg.Password, cfg.Name, cfg.SSLMode)
	}

	// Open database connection
	db, err := sqlx.Connect("postgres", connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Configure connection pool
	db.SetMaxOpenConns(cfg.MaxOpenConnections)
	db.SetMaxIdleConns(cfg.MaxIdleConnections)
	db.SetConnMaxLifetime(cfg.ConnMaxLifetime)

	// Test connection
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	logger.Info("Database connected",
		"host", cfg.Host,
		"port", cfg.Port,
		"database", cfg.Name,
		"max_open_conns", cfg.MaxOpenConnections,
		"max_idle_conns", cfg.MaxIdleConnections,
	)

	return &DB{
		DB:     db,
		logger: logger,
		config: cfg,
	}, nil
}

// Close closes the database connection
func (d *DB) Close() error {
	d.logger.Info("Closing database connection")
	return d.DB.Close()
}

// Migrate runs database migrations
func (d *DB) Migrate() error {
	d.logger.Info("Running database migrations", "path", d.config.MigrationsPath)

	// TODO: Implement actual migration logic using golang-migrate
	// For now, just log that we would run migrations
	d.logger.Info("Migration setup complete")

	return nil
}

// Health checks database health
func (d *DB) Health() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return d.PingContext(ctx)
}

// Stats returns database connection statistics
func (d *DB) Stats() map[string]interface{} {
	stats := d.DB.Stats()
	return map[string]interface{}{
		"max_open_connections": stats.MaxOpenConnections,
		"open_connections":     stats.OpenConnections,
		"in_use":               stats.InUse,
		"idle":                 stats.Idle,
		"wait_count":           stats.WaitCount,
		"wait_duration":        stats.WaitDuration.String(),
		"max_idle_closed":      stats.MaxIdleClosed,
		"max_idle_time_closed": stats.MaxIdleTimeClosed,
		"max_lifetime_closed":  stats.MaxLifetimeClosed,
	}
}
