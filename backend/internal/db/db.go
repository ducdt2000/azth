package db

import (
	"context"
	"embed"
	"fmt"
	"time"

	_ "github.com/go-sql-driver/mysql" // MySQL driver
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"               // PostgreSQL driver
	_ "github.com/mattn/go-sqlite3"     // SQLite driver
	_ "github.com/microsoft/go-mssqldb" // SQL Server driver
	"github.com/pressly/goose/v3"

	"github.com/ducdt2000/azth/backend/internal/config"
	"github.com/ducdt2000/azth/backend/pkg/logger"
)

//go:embed migrations/*.sql
var embedMigrations embed.FS

// DB wraps the database connection and provides additional methods
type DB struct {
	*sqlx.DB
	logger *logger.Logger
	config config.DatabaseConfig
}

// New creates a new database connection with support for multiple database drivers
func New(cfg config.DatabaseConfig, logger *logger.Logger) (*DB, error) {
	// Determine the driver
	driver := cfg.Driver
	if driver == "" {
		driver = "postgres" // default
	}

	// Build connection string
	var connStr string
	if cfg.URL != "" {
		connStr = cfg.URL
	} else {
		switch driver {
		case "postgres":
			connStr = fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
				cfg.Host, cfg.Port, cfg.User, cfg.Password, cfg.Name, cfg.SSLMode)
		case "mysql":
			charset := cfg.MySQLCharset
			if charset == "" {
				charset = "utf8mb4"
			}
			connStr = fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=%s&parseTime=true&loc=UTC",
				cfg.User, cfg.Password, cfg.Host, cfg.Port, cfg.Name, charset)
		case "sqlite3":
			file := cfg.SQLiteFile
			if file == "" {
				file = "./data/azth.db"
			}
			mode := cfg.SQLiteMode
			if mode == "" {
				mode = "rwc"
			}
			connStr = fmt.Sprintf("file:%s?mode=%s&cache=shared&_fk=1&_journal_mode=WAL", file, mode)
		case "sqlserver":
			encrypt := cfg.SQLServerEncrypt
			if encrypt == "" {
				encrypt = "false"
			}
			trustCert := "false"
			if cfg.SQLServerTrustCert {
				trustCert = "true"
			}
			connStr = fmt.Sprintf("sqlserver://%s:%s@%s:%d?database=%s&encrypt=%s&trustservercertificate=%s",
				cfg.User, cfg.Password, cfg.Host, cfg.Port, cfg.Name, encrypt, trustCert)
		default:
			return nil, fmt.Errorf("unsupported database driver: %s", driver)
		}
	}

	logger.Info("Connecting to database",
		"driver", driver,
		"host", cfg.Host,
		"port", cfg.Port,
		"database", cfg.Name,
	)

	// Open database connection
	db, err := sqlx.Connect(driver, connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Configure connection pool
	if cfg.MaxOpenConnections > 0 {
		db.SetMaxOpenConns(cfg.MaxOpenConnections)
	}
	if cfg.MaxIdleConnections > 0 {
		db.SetMaxIdleConns(cfg.MaxIdleConnections)
	}
	if cfg.ConnMaxLifetime > 0 {
		db.SetConnMaxLifetime(cfg.ConnMaxLifetime)
	}
	if cfg.ConnMaxIdleTime > 0 {
		db.SetConnMaxIdleTime(cfg.ConnMaxIdleTime)
	}

	// Test connection
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	logger.Info("Database connected successfully",
		"driver", driver,
		"host", cfg.Host,
		"port", cfg.Port,
		"database", cfg.Name,
		"max_open_conns", cfg.MaxOpenConnections,
		"max_idle_conns", cfg.MaxIdleConnections,
	)

	dbInstance := &DB{
		DB:     db,
		logger: logger,
		config: cfg,
	}

	// Run migrations if auto-migrate is enabled
	if cfg.AutoMigrate {
		if err := dbInstance.Migrate(); err != nil {
			logger.Warn("Failed to run database migrations", "error", err)
		}
	}

	return dbInstance, nil
}

// Close closes the database connection
func (d *DB) Close() error {
	d.logger.Info("Closing database connection")
	return d.DB.Close()
}

// Migrate runs database migrations
func (d *DB) Migrate() error {
	d.logger.Info("Running database migrations")

	// Set up goose with embedded migrations
	goose.SetBaseFS(embedMigrations)

	// Determine the dialect based on the driver
	dialect := d.config.Driver
	if dialect == "" {
		dialect = "postgres"
	}

	// Map driver names to goose dialect names
	var gooseDialect string
	switch dialect {
	case "postgres":
		gooseDialect = "postgres"
	case "mysql":
		gooseDialect = "mysql"
	case "sqlite3":
		gooseDialect = "sqlite3"
	case "sqlserver":
		gooseDialect = "mssql"
	default:
		gooseDialect = "postgres" // fallback
	}

	// Run migrations
	if err := goose.SetDialect(gooseDialect); err != nil {
		return fmt.Errorf("failed to set dialect '%s': %w", gooseDialect, err)
	}

	// Get current database version
	version, err := goose.GetDBVersion(d.DB.DB)
	if err != nil {
		d.logger.Warn("Could not get database version, creating goose schema", "error", err)
		// Create goose_db_version table if it doesn't exist
		if err := goose.UpTo(d.DB.DB, "migrations", 0); err != nil {
			return fmt.Errorf("failed to initialize goose: %w", err)
		}
	}

	d.logger.Info("Current database version", "version", version, "dialect", gooseDialect)

	// Run all migrations
	if err := goose.Up(d.DB.DB, "migrations"); err != nil {
		return fmt.Errorf("failed to run migrations: %w", err)
	}

	// Get new version
	newVersion, err := goose.GetDBVersion(d.DB.DB)
	if err != nil {
		return fmt.Errorf("failed to get new database version: %w", err)
	}

	d.logger.Info("Database migrations completed", "version", newVersion, "dialect", gooseDialect)
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
