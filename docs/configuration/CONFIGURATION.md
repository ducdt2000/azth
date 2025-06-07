# Configuration Guide

## Overview

AZTH Backend uses a hierarchical configuration system that supports multiple formats (YAML, JSON, Environment Variables) and environment-specific overrides. Configuration is managed through Viper with validation and hot-reloading capabilities.

## Configuration Hierarchy

The configuration system loads settings in the following order (later sources override earlier ones):

1. **Default values** (hardcoded in application)
2. **Configuration files** (`config.yaml`, `config.json`)
3. **Environment-specific files** (`config.development.yaml`, `config.production.yaml`)
4. **Environment variables** (prefixed with `AZTH_`)
5. **Command-line flags** (highest priority)

## Configuration Structure

### Application Settings

```yaml
app:
  name: "AZTH Backend"
  version: "1.0.0"
  environment: "development" # development, staging, production
  port: 8080
  host: "0.0.0.0"
  debug: true
  read_timeout: "30s"
  write_timeout: "30s"
  idle_timeout: "120s"
  shutdown_timeout: "30s"
  base_url: "http://localhost:8080"
  frontend_url: "http://localhost:3000"
  cors:
    allowed_origins:
      - "http://localhost:3000"
      - "https://app.azth.com"
    allowed_methods:
      - "GET"
      - "POST"
      - "PUT"
      - "DELETE"
      - "OPTIONS"
    allowed_headers:
      - "Content-Type"
      - "Authorization"
      - "X-Tenant-ID"
      - "X-Request-ID"
    allow_credentials: true
    max_age: 86400
```

### Database Configuration

```yaml
database:
  # Connection settings
  host: "localhost"
  port: 5432
  user: "azth_user"
  password: "secure_password"
  name: "azth_db"
  ssl_mode: "disable" # disable, require, verify-ca, verify-full

  # Connection pool
  max_open_conns: 25
  max_idle_conns: 5
  conn_max_lifetime: "5m"
  conn_max_idle_time: "1m"

  # Timeouts
  connect_timeout: "10s"
  query_timeout: "30s"

  # Features
  auto_migrate: true
  debug: false

  # Backup
  backup_enabled: true
  backup_schedule: "0 2 * * *" # Daily at 2 AM
  backup_retention: "30d"

  # Read replicas (optional)
  read_replicas:
    - host: "replica1.db.azth.com"
      port: 5432
      weight: 1
    - host: "replica2.db.azth.com"
      port: 5432
      weight: 1
```

### Redis Configuration

```yaml
redis:
  # Connection
  addr: "localhost:6379"
  password: ""
  db: 0

  # Pool settings
  pool_size: 10
  min_idle_conns: 1
  max_retries: 3
  retry_delay: "1s"

  # Timeouts
  dial_timeout: "5s"
  read_timeout: "3s"
  write_timeout: "3s"
  pool_timeout: "4s"
  idle_timeout: "5m"

  # Features
  enable_tracing: true
  key_prefix: "azth:"

  # Cluster configuration (for Redis Cluster)
  cluster:
    enabled: false
    addrs:
      - "redis-cluster-1:6379"
      - "redis-cluster-2:6379"
      - "redis-cluster-3:6379"
```

### Authentication Configuration

```yaml
auth:
  # Mode: "stateful" (session) or "stateless" (JWT)
  mode: "stateful"

  # JWT settings (for stateless mode)
  jwt:
    secret: "your-jwt-secret-change-in-production"
    issuer: "azth-backend"
    audience: "azth-users"
    access_token_ttl: "15m"
    refresh_token_ttl: "168h" # 7 days
    algorithm: "HS256"

  # Session settings (for stateful mode)
  session:
    secret: "your-session-secret-change-in-production"
    name: "azth_session"
    ttl: "24h"
    secure: false # Set to true in production with HTTPS
    http_only: true
    same_site: "lax" # strict, lax, none
    domain: "" # Leave empty for current domain
    path: "/"

  # Security settings
  password:
    min_length: 8
    require_uppercase: true
    require_lowercase: true
    require_numbers: true
    require_symbols: false
    bcrypt_cost: 12

  # Account security
  max_login_attempts: 5
  lockout_duration: "15m"
  session_timeout: "30m"
  max_sessions_per_user: 5

  # Multi-factor authentication
  mfa:
    enabled: true
    issuer: "AZTH"
    backup_codes_count: 10
    totp_period: 30
    totp_skew: 1

  # Password reset
  password_reset:
    token_ttl: "1h"
    max_attempts: 3
    cooldown: "5m"
```

### Email Configuration

```yaml
email:
  # Provider: smtp, sendgrid, ses, mailgun
  provider: "smtp"

  # SMTP settings
  smtp:
    host: "localhost"
    port: 587
    username: "noreply@azth.com"
    password: "smtp_password"
    use_tls: true
    use_ssl: false

  # SendGrid settings
  sendgrid:
    api_key: "your-sendgrid-api-key"

  # AWS SES settings
  ses:
    region: "us-east-1"
    access_key_id: "your-access-key"
    secret_access_key: "your-secret-key"

  # Default settings
  from_email: "noreply@azth.com"
  from_name: "AZTH Platform"
  reply_to: "support@azth.com"

  # Templates
  templates:
    welcome: "welcome.html"
    password_reset: "password-reset.html"
    email_verification: "email-verification.html"
    otp_code: "otp-code.html"

  # Rate limiting
  rate_limit:
    per_user: 10
    per_hour: 1000
```

### SMS Configuration

```yaml
sms:
  # Provider: twilio, aws_sns
  provider: "twilio"

  # Twilio settings
  twilio:
    account_sid: "your-account-sid"
    auth_token: "your-auth-token"
    from_number: "+1234567890"

  # AWS SNS settings
  sns:
    region: "us-east-1"
    access_key_id: "your-access-key"
    secret_access_key: "your-secret-key"

  # Rate limiting
  rate_limit:
    per_user: 5
    per_hour: 100
```

### Logging Configuration

```yaml
logging:
  # Level: debug, info, warn, error
  level: "info"

  # Format: json, text
  format: "json"

  # Output: stdout, stderr, file
  output: "stdout"

  # File output settings
  file:
    path: "/var/log/azth/app.log"
    max_size: 100 # MB
    max_age: 28 # days
    max_backups: 3
    compress: true

  # Structured logging
  structured: true
  caller: true
  stack_trace: true

  # Log sampling (for high-volume logs)
  sampling:
    enabled: false
    initial: 100
    thereafter: 100
```

### Cache Configuration

```yaml
cache:
  # Provider: memory, redis
  provider: "redis"

  # Default TTL
  default_ttl: "1h"

  # Memory cache settings
  memory:
    max_size: 100 # MB
    cleanup_interval: "10m"

  # Cache layers
  layers:
    l1: # In-memory cache
      enabled: true
      provider: "memory"
      ttl: "5m"
      max_size: 50 # MB

    l2: # Distributed cache
      enabled: true
      provider: "redis"
      ttl: "1h"

  # Cache keys
  key_patterns:
    user: "user:%s"
    session: "session:%s"
    role: "role:%s"
    permission: "permission:%s"
```

### Rate Limiting Configuration

```yaml
rate_limit:
  # Global settings
  enabled: true
  store: "redis" # memory, redis

  # Default limits
  default:
    requests: 1000
    window: "1h"

  # Endpoint-specific limits
  endpoints:
    "/auth/login":
      requests: 10
      window: "1m"

    "/auth/password/reset":
      requests: 5
      window: "1h"

    "/otp/send":
      requests: 10
      window: "1h"

  # IP-based limits
  ip_whitelist:
    - "127.0.0.1"
    - "10.0.0.0/8"

  # User-based limits
  user_limits:
    free:
      requests: 1000
      window: "1h"
    premium:
      requests: 10000
      window: "1h"
```

### Monitoring Configuration

```yaml
monitoring:
  # Health checks
  health:
    enabled: true
    endpoint: "/health"

  # Metrics
  metrics:
    enabled: true
    endpoint: "/metrics"
    namespace: "azth"

  # Tracing
  tracing:
    enabled: true
    provider: "jaeger" # jaeger, zipkin
    endpoint: "http://jaeger:14268/api/traces"
    sample_rate: 0.1

  # Profiling
  profiling:
    enabled: false # Only enable in development
    endpoint: "/debug/pprof"
```

## Environment-Specific Configuration

### Development Configuration

```yaml
# config.development.yaml
app:
  environment: "development"
  debug: true
  port: 8080

database:
  name: "azth_dev"
  debug: true
  auto_migrate: true

auth:
  session:
    secure: false

logging:
  level: "debug"
  format: "text"

cache:
  provider: "memory"

rate_limit:
  enabled: false
```

### Production Configuration

```yaml
# config.production.yaml
app:
  environment: "production"
  debug: false
  port: 8080
  host: "0.0.0.0"

database:
  ssl_mode: "require"
  max_open_conns: 100
  debug: false
  auto_migrate: false

auth:
  session:
    secure: true
    domain: ".azth.com"

logging:
  level: "info"
  format: "json"
  file:
    path: "/var/log/azth/app.log"

monitoring:
  health:
    enabled: true
  metrics:
    enabled: true
  tracing:
    enabled: true
    sample_rate: 0.01

rate_limit:
  enabled: true
```

## Environment Variables

### Database Variables

```bash
# Primary database
DATABASE_URL="postgres://user:pass@host:port/dbname?sslmode=require"
DATABASE_HOST="localhost"
DATABASE_PORT="5432"
DATABASE_USER="azth_user"
DATABASE_PASSWORD="secure_password"
DATABASE_NAME="azth_db"
DATABASE_SSL_MODE="require"

# Connection pool
DATABASE_MAX_OPEN_CONNS="100"
DATABASE_MAX_IDLE_CONNS="10"
DATABASE_CONN_MAX_LIFETIME="5m"
```

### Redis Variables

```bash
REDIS_URL="redis://:password@host:port/db"
REDIS_ADDR="localhost:6379"
REDIS_PASSWORD="redis_password"
REDIS_DB="0"
REDIS_POOL_SIZE="10"
```

### Authentication Variables

```bash
# JWT
JWT_SECRET="your-jwt-secret-here"
JWT_ISSUER="azth-backend"
JWT_ACCESS_TOKEN_TTL="15m"
JWT_REFRESH_TOKEN_TTL="168h"

# Session
SESSION_SECRET="your-session-secret-here"
SESSION_TTL="24h"

# Security
AUTH_MAX_LOGIN_ATTEMPTS="5"
AUTH_LOCKOUT_DURATION="15m"
```

### Email Variables

```bash
# SMTP
EMAIL_PROVIDER="smtp"
SMTP_HOST="smtp.gmail.com"
SMTP_PORT="587"
SMTP_USERNAME="noreply@azth.com"
SMTP_PASSWORD="smtp_password"
SMTP_USE_TLS="true"

# SendGrid
SENDGRID_API_KEY="your-sendgrid-api-key"

# Default settings
EMAIL_FROM="noreply@azth.com"
EMAIL_FROM_NAME="AZTH Platform"
```

### Application Variables

```bash
# Application
APP_ENV="production"
APP_PORT="8080"
APP_DEBUG="false"
APP_BASE_URL="https://api.azth.com"
APP_FRONTEND_URL="https://app.azth.com"

# Logging
LOG_LEVEL="info"
LOG_FORMAT="json"
LOG_OUTPUT="stdout"

# Features
FEATURE_MFA_ENABLED="true"
FEATURE_EMAIL_VERIFICATION="true"
FEATURE_PASSWORD_RESET="true"
```

## Configuration Validation

### Schema Validation

```go
// Configuration struct with validation tags
type Config struct {
    App      AppConfig      `mapstructure:"app" validate:"required"`
    Database DatabaseConfig `mapstructure:"database" validate:"required"`
    Redis    RedisConfig    `mapstructure:"redis" validate:"required"`
    Auth     AuthConfig     `mapstructure:"auth" validate:"required"`
    Email    EmailConfig    `mapstructure:"email" validate:"required"`
    Logging  LoggingConfig  `mapstructure:"logging" validate:"required"`
}

type AppConfig struct {
    Name        string        `mapstructure:"name" validate:"required"`
    Version     string        `mapstructure:"version" validate:"required"`
    Environment string        `mapstructure:"environment" validate:"required,oneof=development staging production"`
    Port        int           `mapstructure:"port" validate:"required,min=1,max=65535"`
    Host        string        `mapstructure:"host" validate:"required"`
    Debug       bool          `mapstructure:"debug"`
    ReadTimeout time.Duration `mapstructure:"read_timeout" validate:"required"`
}
```

### Runtime Validation

```go
func (c *Config) Validate() error {
    validator := validator.New()

    if err := validator.Struct(c); err != nil {
        return fmt.Errorf("configuration validation failed: %w", err)
    }

    // Custom validations
    if c.App.Environment == "production" && c.App.Debug {
        return errors.New("debug mode cannot be enabled in production")
    }

    if c.Auth.Mode == "stateless" && c.Auth.JWT.Secret == "" {
        return errors.New("JWT secret is required for stateless auth mode")
    }

    return nil
}
```

## Dynamic Configuration

### Hot Reloading

```go
// Watch for configuration changes
func (c *Config) WatchForChanges() {
    viper.WatchConfig()
    viper.OnConfigChange(func(e fsnotify.Event) {
        log.Printf("Config file changed: %s", e.Name)

        // Reload configuration
        if err := c.Reload(); err != nil {
            log.Printf("Failed to reload config: %v", err)
            return
        }

        // Notify services of config changes
        c.notifyServices()
    })
}
```

### Feature Flags

```yaml
features:
  email_verification:
    enabled: true
    rollout_percentage: 100

  mfa_enforcement:
    enabled: false
    rollout_percentage: 10
    target_tenants:
      - "tenant-1"
      - "tenant-2"

  new_ui:
    enabled: true
    rollout_percentage: 50
    user_whitelist:
      - "user@example.com"
```

## Security Considerations

### Secrets Management

```bash
# Use external secret management
# AWS Secrets Manager
aws secretsmanager get-secret-value --secret-id prod/azth/database --query SecretString

# HashiCorp Vault
vault kv get -field=password secret/azth/database

# Kubernetes Secrets
kubectl get secret azth-secrets -o jsonpath='{.data.database-password}' | base64 -d
```

### Environment-Specific Secrets

```yaml
# Use different secrets per environment
database:
  password: "${DATABASE_PASSWORD}" # From environment

auth:
  jwt:
    secret: "${JWT_SECRET}" # From environment
```

## Configuration Examples

### Docker Compose

```yaml
version: "3.8"
services:
  azth-backend:
    image: azth/backend:latest
    environment:
      - APP_ENV=production
      - DATABASE_URL=postgres://user:pass@db:5432/azth
      - REDIS_URL=redis://redis:6379
      - JWT_SECRET=${JWT_SECRET}
      - SESSION_SECRET=${SESSION_SECRET}
    depends_on:
      - db
      - redis
```

### Kubernetes ConfigMap

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: azth-config
data:
  config.yaml: |
    app:
      environment: "production"
      port: 8080
    database:
      host: "postgres-service"
      port: 5432
      ssl_mode: "require"
    redis:
      addr: "redis-service:6379"
```

### Terraform Configuration

```hcl
resource "aws_ssm_parameter" "database_url" {
  name  = "/azth/production/database-url"
  type  = "SecureString"
  value = "postgres://user:pass@${aws_db_instance.main.endpoint}/azth"
}

resource "aws_ssm_parameter" "jwt_secret" {
  name  = "/azth/production/jwt-secret"
  type  = "SecureString"
  value = random_password.jwt_secret.result
}
```

## Troubleshooting

### Common Configuration Issues

1. **Database Connection Failed**

   ```bash
   # Check connection string
   echo $DATABASE_URL

   # Test connection
   psql $DATABASE_URL -c "SELECT version();"
   ```

2. **Redis Connection Failed**

   ```bash
   # Check Redis connection
   redis-cli -u $REDIS_URL ping
   ```

3. **Configuration Not Loading**

   ```bash
   # Check file permissions
   ls -la config.yaml

   # Validate YAML syntax
   yamllint config.yaml
   ```

4. **Environment Variables Not Set**

   ```bash
   # List environment variables
   env | grep AZTH

   # Check specific variable
   echo $JWT_SECRET
   ```

### Debug Configuration

```go
// Add debug logging for configuration
func (c *Config) Debug() {
    log.Printf("App Environment: %s", c.App.Environment)
    log.Printf("Database Host: %s", c.Database.Host)
    log.Printf("Redis Address: %s", c.Redis.Addr)
    log.Printf("Auth Mode: %s", c.Auth.Mode)

    // Don't log sensitive values
    if c.Database.Password != "" {
        log.Printf("Database Password: [REDACTED]")
    }
}
```

---

For more information, see the [Development Guide](DEVELOPMENT.md) and [Deployment Guide](DEPLOYMENT.md).
