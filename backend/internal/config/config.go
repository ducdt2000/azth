package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config holds all configuration for the application
type Config struct {
	Server    ServerConfig    `mapstructure:"server"`
	Database  DatabaseConfig  `mapstructure:"database"`
	Redis     RedisConfig     `mapstructure:"redis"`
	JWT       JWTConfig       `mapstructure:"jwt"`
	OIDC      OIDCConfig      `mapstructure:"oidc"`
	Logger    LoggerConfig    `mapstructure:"logger"`
	Telemetry TelemetryConfig `mapstructure:"telemetry"`
	Security  SecurityConfig  `mapstructure:"security"`
}

// ServerConfig holds server-related configuration
type ServerConfig struct {
	Address         string        `mapstructure:"address"`
	Port            int           `mapstructure:"port"`
	ReadTimeout     time.Duration `mapstructure:"read_timeout"`
	WriteTimeout    time.Duration `mapstructure:"write_timeout"`
	IdleTimeout     time.Duration `mapstructure:"idle_timeout"`
	ShutdownTimeout time.Duration `mapstructure:"shutdown_timeout"`
	TLS             TLSConfig     `mapstructure:"tls"`
	CORS            CORSConfig    `mapstructure:"cors"`
}

// TLSConfig holds TLS configuration
type TLSConfig struct {
	Enabled  bool   `mapstructure:"enabled"`
	CertFile string `mapstructure:"cert_file"`
	KeyFile  string `mapstructure:"key_file"`
}

// CORSConfig holds CORS configuration
type CORSConfig struct {
	AllowedOrigins     []string `mapstructure:"allowed_origins"`
	AllowedMethods     []string `mapstructure:"allowed_methods"`
	AllowedHeaders     []string `mapstructure:"allowed_headers"`
	ExposedHeaders     []string `mapstructure:"exposed_headers"`
	AllowCredentials   bool     `mapstructure:"allow_credentials"`
	MaxAge             int      `mapstructure:"max_age"`
	OptionsPassthrough bool     `mapstructure:"options_passthrough"`
}

// DatabaseConfig holds database configuration
type DatabaseConfig struct {
	// Connection configuration
	URL      string `mapstructure:"url"`
	Driver   string `mapstructure:"driver"` // postgres, mysql, sqlite3, sqlserver
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	User     string `mapstructure:"user"`
	Password string `mapstructure:"password"`
	Name     string `mapstructure:"name"`
	SSLMode  string `mapstructure:"ssl_mode"` // for postgres: disable, require, verify-ca, verify-full

	// Connection pooling
	MaxOpenConnections int           `mapstructure:"max_open_connections"`
	MaxIdleConnections int           `mapstructure:"max_idle_connections"`
	ConnMaxLifetime    time.Duration `mapstructure:"conn_max_lifetime"`
	ConnMaxIdleTime    time.Duration `mapstructure:"conn_max_idle_time"`

	// SQLite specific
	SQLiteFile string `mapstructure:"sqlite_file"` // for sqlite3: file path
	SQLiteMode string `mapstructure:"sqlite_mode"` // rwc, rw, ro, memory

	// MySQL specific
	MySQLCharset      string        `mapstructure:"mysql_charset"`       // utf8mb4, utf8, etc.
	MySQLCollation    string        `mapstructure:"mysql_collation"`     // utf8mb4_unicode_ci, etc.
	MySQLTimeout      time.Duration `mapstructure:"mysql_timeout"`       // connection timeout
	MySQLReadTimeout  time.Duration `mapstructure:"mysql_read_timeout"`  // read timeout
	MySQLWriteTimeout time.Duration `mapstructure:"mysql_write_timeout"` // write timeout

	// SQL Server specific
	SQLServerEncrypt   string `mapstructure:"sqlserver_encrypt"` // disable, false, true
	SQLServerTrustCert bool   `mapstructure:"sqlserver_trust_cert"`

	// Migration settings
	MigrationsPath string `mapstructure:"migrations_path"`
	AutoMigrate    bool   `mapstructure:"auto_migrate"`
}

// RedisConfig holds Redis configuration
type RedisConfig struct {
	// Connection configuration
	URL      string `mapstructure:"url"`
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	Password string `mapstructure:"password"`
	DB       int    `mapstructure:"db"`

	// Connection pooling
	PoolSize     int           `mapstructure:"pool_size"`
	MinIdleConn  int           `mapstructure:"min_idle_conn"`
	DialTimeout  time.Duration `mapstructure:"dial_timeout"`
	ReadTimeout  time.Duration `mapstructure:"read_timeout"`
	WriteTimeout time.Duration `mapstructure:"write_timeout"`

	// Cluster configuration
	ClusterMode  bool     `mapstructure:"cluster_mode"`
	ClusterAddrs []string `mapstructure:"cluster_addrs"`

	// Local KV store fallback
	Enabled    bool          `mapstructure:"enabled"` // if false, use local KV store
	LocalStore LocalKVConfig `mapstructure:"local_store"`

	// Advanced settings
	MaxRetries      int           `mapstructure:"max_retries"`
	MinRetryBackoff time.Duration `mapstructure:"min_retry_backoff"`
	MaxRetryBackoff time.Duration `mapstructure:"max_retry_backoff"`
}

// LocalKVConfig holds local key-value store configuration
type LocalKVConfig struct {
	Type            string        `mapstructure:"type"`             // memory, file
	FilePath        string        `mapstructure:"file_path"`        // for file-based storage
	MaxSize         int64         `mapstructure:"max_size"`         // maximum size in bytes
	CleanupInterval time.Duration `mapstructure:"cleanup_interval"` // cleanup expired keys interval
	DefaultTTL      time.Duration `mapstructure:"default_ttl"`      // default TTL for keys
}

// JWTConfig holds JWT configuration
type JWTConfig struct {
	Secret            string        `mapstructure:"secret"`
	PrivateKeyPath    string        `mapstructure:"private_key_path"`
	PublicKeyPath     string        `mapstructure:"public_key_path"`
	AccessTokenTTL    time.Duration `mapstructure:"access_token_ttl"`
	RefreshTokenTTL   time.Duration `mapstructure:"refresh_token_ttl"`
	Algorithm         string        `mapstructure:"algorithm"`
	Issuer            string        `mapstructure:"issuer"`
	Audience          []string      `mapstructure:"audience"`
	RefreshTokenStore string        `mapstructure:"refresh_token_store"`
}

// OIDCConfig holds OIDC server configuration
type OIDCConfig struct {
	Issuer                 string   `mapstructure:"issuer"`
	AuthorizationURL       string   `mapstructure:"authorization_url"`
	TokenURL               string   `mapstructure:"token_url"`
	UserinfoURL            string   `mapstructure:"userinfo_url"`
	JWKsURL                string   `mapstructure:"jwks_url"`
	SupportedScopes        []string `mapstructure:"supported_scopes"`
	SupportedGrantTypes    []string `mapstructure:"supported_grant_types"`
	SupportedResponseTypes []string `mapstructure:"supported_response_types"`
	SubjectTypes           []string `mapstructure:"subject_types"`
	IDTokenSigningAlg      []string `mapstructure:"id_token_signing_alg"`
}

// LoggerConfig holds logging configuration
type LoggerConfig struct {
	Level  string `mapstructure:"level"`
	Format string `mapstructure:"format"`
	Output string `mapstructure:"output"`
}

// TelemetryConfig holds telemetry configuration
type TelemetryConfig struct {
	ServiceName    string            `mapstructure:"service_name"`
	ServiceVersion string            `mapstructure:"service_version"`
	Environment    string            `mapstructure:"environment"`
	Tracing        TracingConfig     `mapstructure:"tracing"`
	Metrics        MetricsConfig     `mapstructure:"metrics"`
	Logging        LoggingConfig     `mapstructure:"logging"`
	Attributes     map[string]string `mapstructure:"attributes"`
}

// TracingConfig holds tracing configuration
type TracingConfig struct {
	Enabled        bool              `mapstructure:"enabled"`
	Endpoint       string            `mapstructure:"endpoint"`
	SamplingRate   float64           `mapstructure:"sampling_rate"`
	MaxExportBatch int               `mapstructure:"max_export_batch"`
	ExportTimeout  time.Duration     `mapstructure:"export_timeout"`
	Headers        map[string]string `mapstructure:"headers"`
}

// MetricsConfig holds metrics configuration
type MetricsConfig struct {
	Enabled  bool          `mapstructure:"enabled"`
	Endpoint string        `mapstructure:"endpoint"`
	Interval time.Duration `mapstructure:"interval"`
}

// LoggingConfig holds logging telemetry configuration
type LoggingConfig struct {
	Enabled  bool   `mapstructure:"enabled"`
	Endpoint string `mapstructure:"endpoint"`
}

// SecurityConfig holds security-related configuration
type SecurityConfig struct {
	PasswordMinLength     int           `mapstructure:"password_min_length"`
	PasswordRequireUpper  bool          `mapstructure:"password_require_upper"`
	PasswordRequireLower  bool          `mapstructure:"password_require_lower"`
	PasswordRequireDigit  bool          `mapstructure:"password_require_digit"`
	PasswordRequireSymbol bool          `mapstructure:"password_require_symbol"`
	MaxLoginAttempts      int           `mapstructure:"max_login_attempts"`
	LockoutDuration       time.Duration `mapstructure:"lockout_duration"`
	SessionTimeout        time.Duration `mapstructure:"session_timeout"`
	MFAEnabled            bool          `mapstructure:"mfa_enabled"`
	MFAIssuer             string        `mapstructure:"mfa_issuer"`
}

// Load loads configuration from environment variables and config files
func Load() (*Config, error) {
	v := viper.New()

	// Set defaults
	setDefaults(v)

	// Read from environment variables
	v.SetEnvPrefix("AZTH")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	// Read from config file if it exists
	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath("./configs")
	v.AddConfigPath(".")

	if err := v.ReadInConfig(); err != nil {
		// Config file is optional, so only return error if it's not a file not found error
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &cfg, nil
}

// setDefaults sets default configuration values
func setDefaults(v *viper.Viper) {
	// Server defaults
	v.SetDefault("server.address", "0.0.0.0")
	v.SetDefault("server.port", 8080)
	v.SetDefault("server.read_timeout", "10s")
	v.SetDefault("server.write_timeout", "10s")
	v.SetDefault("server.idle_timeout", "60s")
	v.SetDefault("server.shutdown_timeout", "30s")

	// CORS defaults
	v.SetDefault("server.cors.allowed_origins", []string{"*"})
	v.SetDefault("server.cors.allowed_methods", []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"})
	v.SetDefault("server.cors.allowed_headers", []string{"*"})
	v.SetDefault("server.cors.allow_credentials", true)
	v.SetDefault("server.cors.max_age", 3600)

	// Database defaults
	v.SetDefault("database.driver", "postgres")
	v.SetDefault("database.host", "localhost")
	v.SetDefault("database.port", 5432)
	v.SetDefault("database.user", "azth")
	v.SetDefault("database.password", "azth")
	v.SetDefault("database.name", "azth")
	v.SetDefault("database.ssl_mode", "disable")
	v.SetDefault("database.max_open_connections", 25)
	v.SetDefault("database.max_idle_connections", 25)
	v.SetDefault("database.conn_max_lifetime", "5m")
	v.SetDefault("database.conn_max_idle_time", "30m")
	v.SetDefault("database.auto_migrate", true)
	v.SetDefault("database.migrations_path", "file://migrations")

	// SQLite defaults
	v.SetDefault("database.sqlite_file", "./data/azth.db")
	v.SetDefault("database.sqlite_mode", "rwc")

	// MySQL defaults
	v.SetDefault("database.mysql_charset", "utf8mb4")
	v.SetDefault("database.mysql_collation", "utf8mb4_unicode_ci")
	v.SetDefault("database.mysql_timeout", "10s")
	v.SetDefault("database.mysql_read_timeout", "30s")
	v.SetDefault("database.mysql_write_timeout", "30s")

	// SQL Server defaults
	v.SetDefault("database.sqlserver_encrypt", "false")
	v.SetDefault("database.sqlserver_trust_cert", false)

	// Redis defaults
	v.SetDefault("redis.enabled", true)
	v.SetDefault("redis.host", "localhost")
	v.SetDefault("redis.port", 6379)
	v.SetDefault("redis.db", 0)
	v.SetDefault("redis.pool_size", 10)
	v.SetDefault("redis.min_idle_conn", 5)
	v.SetDefault("redis.dial_timeout", "5s")
	v.SetDefault("redis.read_timeout", "3s")
	v.SetDefault("redis.write_timeout", "3s")
	v.SetDefault("redis.cluster_mode", false)
	v.SetDefault("redis.max_retries", 3)
	v.SetDefault("redis.min_retry_backoff", "8ms")
	v.SetDefault("redis.max_retry_backoff", "512ms")

	// Local KV store defaults (fallback when Redis is disabled)
	v.SetDefault("redis.local_store.type", "memory")
	v.SetDefault("redis.local_store.file_path", "./data/local_kv.db")
	v.SetDefault("redis.local_store.max_size", 104857600) // 100MB
	v.SetDefault("redis.local_store.cleanup_interval", "5m")
	v.SetDefault("redis.local_store.default_ttl", "24h")

	// JWT defaults
	v.SetDefault("jwt.algorithm", "RS256")
	v.SetDefault("jwt.access_token_ttl", "15m")
	v.SetDefault("jwt.refresh_token_ttl", "168h") // 7 days
	v.SetDefault("jwt.issuer", "azth")
	v.SetDefault("jwt.audience", []string{"azth"})
	v.SetDefault("jwt.refresh_token_store", "redis")

	// OIDC defaults
	v.SetDefault("oidc.issuer", "http://localhost:8080")
	v.SetDefault("oidc.supported_scopes", []string{"openid", "profile", "email"})
	v.SetDefault("oidc.supported_grant_types", []string{"authorization_code", "refresh_token"})
	v.SetDefault("oidc.supported_response_types", []string{"code"})
	v.SetDefault("oidc.subject_types", []string{"public"})
	v.SetDefault("oidc.id_token_signing_alg", []string{"RS256"})

	// Logger defaults
	v.SetDefault("logger.level", "info")
	v.SetDefault("logger.format", "json")
	v.SetDefault("logger.output", "stdout")

	// Telemetry defaults
	v.SetDefault("telemetry.service_name", "azth-server")
	v.SetDefault("telemetry.service_version", "1.0.0")
	v.SetDefault("telemetry.environment", "development")
	v.SetDefault("telemetry.tracing.enabled", false)
	v.SetDefault("telemetry.tracing.sampling_rate", 0.1)
	v.SetDefault("telemetry.tracing.max_export_batch", 512)
	v.SetDefault("telemetry.tracing.export_timeout", "30s")
	v.SetDefault("telemetry.metrics.enabled", false)
	v.SetDefault("telemetry.metrics.interval", "30s")
	v.SetDefault("telemetry.logging.enabled", false)

	// Security defaults
	v.SetDefault("security.password_min_length", 8)
	v.SetDefault("security.password_require_upper", true)
	v.SetDefault("security.password_require_lower", true)
	v.SetDefault("security.password_require_digit", true)
	v.SetDefault("security.password_require_symbol", false)
	v.SetDefault("security.max_login_attempts", 5)
	v.SetDefault("security.lockout_duration", "15m")
	v.SetDefault("security.session_timeout", "24h")
	v.SetDefault("security.mfa_enabled", false)
	v.SetDefault("security.mfa_issuer", "AZTH")
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.Server.Port <= 0 || c.Server.Port > 65535 {
		return fmt.Errorf("invalid server port: %d", c.Server.Port)
	}

	if c.Database.URL == "" {
		if c.Database.Host == "" || c.Database.Name == "" {
			return fmt.Errorf("database configuration is incomplete")
		}
	}

	if c.JWT.Secret == "" && c.JWT.PrivateKeyPath == "" {
		return fmt.Errorf("JWT secret or private key path must be provided")
	}

	if c.OIDC.Issuer == "" {
		return fmt.Errorf("OIDC issuer must be provided")
	}

	return nil
}

// GetDatabaseURL returns the complete database URL based on the driver
func (c *Config) GetDatabaseURL() string {
	if c.Database.URL != "" {
		return c.Database.URL
	}

	switch c.Database.Driver {
	case "postgres":
		return fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
			c.Database.User,
			c.Database.Password,
			c.Database.Host,
			c.Database.Port,
			c.Database.Name,
			c.Database.SSLMode,
		)
	case "mysql":
		charset := c.Database.MySQLCharset
		if charset == "" {
			charset = "utf8mb4"
		}
		collation := c.Database.MySQLCollation
		if collation == "" {
			collation = "utf8mb4_unicode_ci"
		}
		timeout := c.Database.MySQLTimeout
		if timeout == 0 {
			timeout = 10 * time.Second
		}
		readTimeout := c.Database.MySQLReadTimeout
		if readTimeout == 0 {
			readTimeout = 30 * time.Second
		}
		writeTimeout := c.Database.MySQLWriteTimeout
		if writeTimeout == 0 {
			writeTimeout = 30 * time.Second
		}

		return fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=%s&collation=%s&timeout=%s&readTimeout=%s&writeTimeout=%s&parseTime=true&loc=UTC",
			c.Database.User,
			c.Database.Password,
			c.Database.Host,
			c.Database.Port,
			c.Database.Name,
			charset,
			collation,
			timeout,
			readTimeout,
			writeTimeout,
		)
	case "sqlite3":
		file := c.Database.SQLiteFile
		if file == "" {
			file = "./data/azth.db"
		}
		mode := c.Database.SQLiteMode
		if mode == "" {
			mode = "rwc"
		}
		return fmt.Sprintf("file:%s?mode=%s&cache=shared&_fk=1&_journal_mode=WAL",
			file,
			mode,
		)
	case "sqlserver":
		encrypt := c.Database.SQLServerEncrypt
		if encrypt == "" {
			encrypt = "false"
		}
		trustCert := "false"
		if c.Database.SQLServerTrustCert {
			trustCert = "true"
		}
		return fmt.Sprintf("sqlserver://%s:%s@%s:%d?database=%s&encrypt=%s&trustservercertificate=%s",
			c.Database.User,
			c.Database.Password,
			c.Database.Host,
			c.Database.Port,
			c.Database.Name,
			encrypt,
			trustCert,
		)
	default:
		// Default to PostgreSQL
		return fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
			c.Database.User,
			c.Database.Password,
			c.Database.Host,
			c.Database.Port,
			c.Database.Name,
			c.Database.SSLMode,
		)
	}
}

// GetRedisURL returns the complete Redis URL
func (c *Config) GetRedisURL() string {
	if c.Redis.URL != "" {
		return c.Redis.URL
	}

	if c.Redis.Password != "" {
		return fmt.Sprintf("redis://:%s@%s:%d/%d",
			c.Redis.Password,
			c.Redis.Host,
			c.Redis.Port,
			c.Redis.DB,
		)
	}

	return fmt.Sprintf("redis://%s:%d/%d",
		c.Redis.Host,
		c.Redis.Port,
		c.Redis.DB,
	)
}
