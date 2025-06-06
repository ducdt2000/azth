# Environment Variables Documentation

This document describes all environment variables that can be used to configure the AZTH backend application. All environment variables are prefixed with `AZTH_` and correspond to configuration keys in the configuration files.

## Table of Contents

- [Server Configuration](#server-configuration)
- [Database Configuration](#database-configuration)
- [Redis/KV Store Configuration](#rediskv-store-configuration)
- [JWT Configuration](#jwt-configuration)
- [OIDC Configuration](#oidc-configuration)
- [Logging Configuration](#logging-configuration)
- [Telemetry Configuration](#telemetry-configuration)
- [Security Configuration](#security-configuration)
- [Example Configuration Files](#example-configuration-files)

## Server Configuration

### Basic Server Settings

| Variable                       | Type     | Default   | Description               |
| ------------------------------ | -------- | --------- | ------------------------- |
| `AZTH_SERVER_ADDRESS`          | string   | `0.0.0.0` | Server bind address       |
| `AZTH_SERVER_PORT`             | int      | `8080`    | Server port               |
| `AZTH_SERVER_READ_TIMEOUT`     | duration | `10s`     | HTTP read timeout         |
| `AZTH_SERVER_WRITE_TIMEOUT`    | duration | `10s`     | HTTP write timeout        |
| `AZTH_SERVER_IDLE_TIMEOUT`     | duration | `60s`     | HTTP idle timeout         |
| `AZTH_SERVER_SHUTDOWN_TIMEOUT` | duration | `30s`     | Graceful shutdown timeout |

### TLS Configuration

| Variable                    | Type   | Default | Description                  |
| --------------------------- | ------ | ------- | ---------------------------- |
| `AZTH_SERVER_TLS_ENABLED`   | bool   | `false` | Enable TLS/HTTPS             |
| `AZTH_SERVER_TLS_CERT_FILE` | string | `""`    | Path to TLS certificate file |
| `AZTH_SERVER_TLS_KEY_FILE`  | string | `""`    | Path to TLS private key file |

### CORS Configuration

| Variable                             | Type     | Default                                   | Description                             |
| ------------------------------------ | -------- | ----------------------------------------- | --------------------------------------- |
| `AZTH_SERVER_CORS_ALLOWED_ORIGINS`   | []string | `["*"]`                                   | Allowed CORS origins (comma-separated)  |
| `AZTH_SERVER_CORS_ALLOWED_METHODS`   | []string | `["GET","POST","PUT","DELETE","OPTIONS"]` | Allowed HTTP methods                    |
| `AZTH_SERVER_CORS_ALLOWED_HEADERS`   | []string | `["*"]`                                   | Allowed headers                         |
| `AZTH_SERVER_CORS_ALLOW_CREDENTIALS` | bool     | `true`                                    | Allow credentials in CORS requests      |
| `AZTH_SERVER_CORS_MAX_AGE`           | int      | `3600`                                    | CORS preflight cache duration (seconds) |

## Database Configuration

### Universal Database Settings

| Variable                        | Type   | Default             | Description                                                  |
| ------------------------------- | ------ | ------------------- | ------------------------------------------------------------ |
| `AZTH_DATABASE_URL`             | string | `""`                | Complete database connection URL (overrides other settings)  |
| `AZTH_DATABASE_DRIVER`          | string | `postgres`          | Database driver: `postgres`, `mysql`, `sqlite3`, `sqlserver` |
| `AZTH_DATABASE_HOST`            | string | `localhost`         | Database host                                                |
| `AZTH_DATABASE_PORT`            | int    | `5432`              | Database port                                                |
| `AZTH_DATABASE_USER`            | string | `azth`              | Database username                                            |
| `AZTH_DATABASE_PASSWORD`        | string | `azth`              | Database password                                            |
| `AZTH_DATABASE_NAME`            | string | `azth`              | Database name                                                |
| `AZTH_DATABASE_AUTO_MIGRATE`    | bool   | `true`              | Automatically run migrations on startup                      |
| `AZTH_DATABASE_MIGRATIONS_PATH` | string | `file://migrations` | Path to migration files                                      |

### Connection Pool Settings

| Variable                             | Type     | Default | Description                       |
| ------------------------------------ | -------- | ------- | --------------------------------- |
| `AZTH_DATABASE_MAX_OPEN_CONNECTIONS` | int      | `25`    | Maximum open database connections |
| `AZTH_DATABASE_MAX_IDLE_CONNECTIONS` | int      | `25`    | Maximum idle database connections |
| `AZTH_DATABASE_CONN_MAX_LIFETIME`    | duration | `5m`    | Maximum connection lifetime       |
| `AZTH_DATABASE_CONN_MAX_IDLE_TIME`   | duration | `30m`   | Maximum connection idle time      |

### PostgreSQL Specific

| Variable                 | Type   | Default   | Description                                                |
| ------------------------ | ------ | --------- | ---------------------------------------------------------- |
| `AZTH_DATABASE_SSL_MODE` | string | `disable` | SSL mode: `disable`, `require`, `verify-ca`, `verify-full` |

### MySQL Specific

| Variable                            | Type     | Default              | Description              |
| ----------------------------------- | -------- | -------------------- | ------------------------ |
| `AZTH_DATABASE_MYSQL_CHARSET`       | string   | `utf8mb4`            | MySQL character set      |
| `AZTH_DATABASE_MYSQL_COLLATION`     | string   | `utf8mb4_unicode_ci` | MySQL collation          |
| `AZTH_DATABASE_MYSQL_TIMEOUT`       | duration | `10s`                | MySQL connection timeout |
| `AZTH_DATABASE_MYSQL_READ_TIMEOUT`  | duration | `30s`                | MySQL read timeout       |
| `AZTH_DATABASE_MYSQL_WRITE_TIMEOUT` | duration | `30s`                | MySQL write timeout      |

### SQLite Specific

| Variable                    | Type   | Default          | Description                              |
| --------------------------- | ------ | ---------------- | ---------------------------------------- |
| `AZTH_DATABASE_SQLITE_FILE` | string | `./data/azth.db` | SQLite database file path                |
| `AZTH_DATABASE_SQLITE_MODE` | string | `rwc`            | SQLite mode: `rwc`, `rw`, `ro`, `memory` |

### SQL Server Specific

| Variable                             | Type   | Default | Description                                       |
| ------------------------------------ | ------ | ------- | ------------------------------------------------- |
| `AZTH_DATABASE_SQLSERVER_ENCRYPT`    | string | `false` | SQL Server encryption: `disable`, `false`, `true` |
| `AZTH_DATABASE_SQLSERVER_TRUST_CERT` | bool   | `false` | Trust server certificate                          |

## Redis/KV Store Configuration

### Redis Settings

| Variable              | Type   | Default     | Description                                              |
| --------------------- | ------ | ----------- | -------------------------------------------------------- |
| `AZTH_REDIS_ENABLED`  | bool   | `true`      | Enable Redis (if false, uses local KV store)             |
| `AZTH_REDIS_URL`      | string | `""`        | Complete Redis connection URL (overrides other settings) |
| `AZTH_REDIS_HOST`     | string | `localhost` | Redis host                                               |
| `AZTH_REDIS_PORT`     | int    | `6379`      | Redis port                                               |
| `AZTH_REDIS_PASSWORD` | string | `""`        | Redis password                                           |
| `AZTH_REDIS_DB`       | int    | `0`         | Redis database number                                    |

### Redis Connection Pool

| Variable                   | Type     | Default | Description                |
| -------------------------- | -------- | ------- | -------------------------- |
| `AZTH_REDIS_POOL_SIZE`     | int      | `10`    | Redis connection pool size |
| `AZTH_REDIS_MIN_IDLE_CONN` | int      | `5`     | Minimum idle connections   |
| `AZTH_REDIS_DIAL_TIMEOUT`  | duration | `5s`    | Connection dial timeout    |
| `AZTH_REDIS_READ_TIMEOUT`  | duration | `3s`    | Read timeout               |
| `AZTH_REDIS_WRITE_TIMEOUT` | duration | `3s`    | Write timeout              |

### Redis Cluster

| Variable                   | Type     | Default | Description                               |
| -------------------------- | -------- | ------- | ----------------------------------------- |
| `AZTH_REDIS_CLUSTER_MODE`  | bool     | `false` | Enable Redis cluster mode                 |
| `AZTH_REDIS_CLUSTER_ADDRS` | []string | `[]`    | Redis cluster addresses (comma-separated) |

### Redis Advanced

| Variable                       | Type     | Default | Description            |
| ------------------------------ | -------- | ------- | ---------------------- |
| `AZTH_REDIS_MAX_RETRIES`       | int      | `3`     | Maximum retry attempts |
| `AZTH_REDIS_MIN_RETRY_BACKOFF` | duration | `8ms`   | Minimum retry backoff  |
| `AZTH_REDIS_MAX_RETRY_BACKOFF` | duration | `512ms` | Maximum retry backoff  |

### Local KV Store (Fallback)

| Variable                                  | Type     | Default              | Description                        |
| ----------------------------------------- | -------- | -------------------- | ---------------------------------- |
| `AZTH_REDIS_LOCAL_STORE_TYPE`             | string   | `memory`             | Local store type: `memory`, `file` |
| `AZTH_REDIS_LOCAL_STORE_FILE_PATH`        | string   | `./data/local_kv.db` | File path for file-based storage   |
| `AZTH_REDIS_LOCAL_STORE_MAX_SIZE`         | int64    | `104857600`          | Maximum size in bytes (100MB)      |
| `AZTH_REDIS_LOCAL_STORE_CLEANUP_INTERVAL` | duration | `5m`                 | Expired keys cleanup interval      |
| `AZTH_REDIS_LOCAL_STORE_DEFAULT_TTL`      | duration | `24h`                | Default TTL for keys               |

## JWT Configuration

| Variable                       | Type     | Default    | Description                                |
| ------------------------------ | -------- | ---------- | ------------------------------------------ |
| `AZTH_JWT_SECRET`              | string   | `""`       | JWT signing secret (required for HS256)    |
| `AZTH_JWT_PRIVATE_KEY_PATH`    | string   | `""`       | Path to private key file (for RS256)       |
| `AZTH_JWT_PUBLIC_KEY_PATH`     | string   | `""`       | Path to public key file (for RS256)        |
| `AZTH_JWT_ALGORITHM`           | string   | `RS256`    | JWT algorithm: `HS256`, `RS256`            |
| `AZTH_JWT_ACCESS_TOKEN_TTL`    | duration | `15m`      | Access token lifetime                      |
| `AZTH_JWT_REFRESH_TOKEN_TTL`   | duration | `168h`     | Refresh token lifetime (7 days)            |
| `AZTH_JWT_ISSUER`              | string   | `azth`     | JWT issuer                                 |
| `AZTH_JWT_AUDIENCE`            | []string | `["azth"]` | JWT audience (comma-separated)             |
| `AZTH_JWT_REFRESH_TOKEN_STORE` | string   | `redis`    | Refresh token storage: `redis`, `database` |

## OIDC Configuration

| Variable                             | Type     | Default                                  | Description                 |
| ------------------------------------ | -------- | ---------------------------------------- | --------------------------- |
| `AZTH_OIDC_ISSUER`                   | string   | `http://localhost:8080`                  | OIDC issuer URL             |
| `AZTH_OIDC_AUTHORIZATION_URL`        | string   | `""`                                     | Custom authorization URL    |
| `AZTH_OIDC_TOKEN_URL`                | string   | `""`                                     | Custom token URL            |
| `AZTH_OIDC_USERINFO_URL`             | string   | `""`                                     | Custom userinfo URL         |
| `AZTH_OIDC_JWKS_URL`                 | string   | `""`                                     | Custom JWKS URL             |
| `AZTH_OIDC_SUPPORTED_SCOPES`         | []string | `["openid","profile","email"]`           | Supported scopes            |
| `AZTH_OIDC_SUPPORTED_GRANT_TYPES`    | []string | `["authorization_code","refresh_token"]` | Supported grant types       |
| `AZTH_OIDC_SUPPORTED_RESPONSE_TYPES` | []string | `["code"]`                               | Supported response types    |
| `AZTH_OIDC_SUBJECT_TYPES`            | []string | `["public"]`                             | Subject types               |
| `AZTH_OIDC_ID_TOKEN_SIGNING_ALG`     | []string | `["RS256"]`                              | ID token signing algorithms |

## Logging Configuration

| Variable             | Type   | Default  | Description                                 |
| -------------------- | ------ | -------- | ------------------------------------------- |
| `AZTH_LOGGER_LEVEL`  | string | `info`   | Log level: `debug`, `info`, `warn`, `error` |
| `AZTH_LOGGER_FORMAT` | string | `json`   | Log format: `json`, `text`                  |
| `AZTH_LOGGER_OUTPUT` | string | `stdout` | Log output: `stdout`, `stderr`, file path   |

## Telemetry Configuration

### Service Information

| Variable                         | Type   | Default       | Description                |
| -------------------------------- | ------ | ------------- | -------------------------- |
| `AZTH_TELEMETRY_SERVICE_NAME`    | string | `azth-server` | Service name for telemetry |
| `AZTH_TELEMETRY_SERVICE_VERSION` | string | `1.0.0`       | Service version            |
| `AZTH_TELEMETRY_ENVIRONMENT`     | string | `development` | Environment name           |

### Tracing

| Variable                                  | Type     | Default | Description                         |
| ----------------------------------------- | -------- | ------- | ----------------------------------- |
| `AZTH_TELEMETRY_TRACING_ENABLED`          | bool     | `false` | Enable distributed tracing          |
| `AZTH_TELEMETRY_TRACING_ENDPOINT`         | string   | `""`    | Tracing endpoint URL (e.g., Jaeger) |
| `AZTH_TELEMETRY_TRACING_SAMPLING_RATE`    | float64  | `0.1`   | Trace sampling rate (0.0-1.0)       |
| `AZTH_TELEMETRY_TRACING_MAX_EXPORT_BATCH` | int      | `512`   | Maximum traces per batch            |
| `AZTH_TELEMETRY_TRACING_EXPORT_TIMEOUT`   | duration | `30s`   | Trace export timeout                |

### Metrics

| Variable                          | Type     | Default | Description                             |
| --------------------------------- | -------- | ------- | --------------------------------------- |
| `AZTH_TELEMETRY_METRICS_ENABLED`  | bool     | `false` | Enable metrics collection               |
| `AZTH_TELEMETRY_METRICS_ENDPOINT` | string   | `""`    | Metrics endpoint URL (e.g., Prometheus) |
| `AZTH_TELEMETRY_METRICS_INTERVAL` | duration | `30s`   | Metrics collection interval             |

### Logging Telemetry

| Variable                          | Type   | Default | Description            |
| --------------------------------- | ------ | ------- | ---------------------- |
| `AZTH_TELEMETRY_LOGGING_ENABLED`  | bool   | `false` | Enable log telemetry   |
| `AZTH_TELEMETRY_LOGGING_ENDPOINT` | string | `""`    | Log telemetry endpoint |

## Security Configuration

| Variable                                | Type     | Default | Description                            |
| --------------------------------------- | -------- | ------- | -------------------------------------- |
| `AZTH_SECURITY_PASSWORD_MIN_LENGTH`     | int      | `8`     | Minimum password length                |
| `AZTH_SECURITY_PASSWORD_REQUIRE_UPPER`  | bool     | `true`  | Require uppercase letters in passwords |
| `AZTH_SECURITY_PASSWORD_REQUIRE_LOWER`  | bool     | `true`  | Require lowercase letters in passwords |
| `AZTH_SECURITY_PASSWORD_REQUIRE_DIGIT`  | bool     | `true`  | Require digits in passwords            |
| `AZTH_SECURITY_PASSWORD_REQUIRE_SYMBOL` | bool     | `false` | Require symbols in passwords           |
| `AZTH_SECURITY_MAX_LOGIN_ATTEMPTS`      | int      | `5`     | Maximum failed login attempts          |
| `AZTH_SECURITY_LOCKOUT_DURATION`        | duration | `15m`   | Account lockout duration               |
| `AZTH_SECURITY_SESSION_TIMEOUT`         | duration | `24h`   | Session timeout                        |
| `AZTH_SECURITY_MFA_ENABLED`             | bool     | `false` | Enable multi-factor authentication     |
| `AZTH_SECURITY_MFA_ISSUER`              | string   | `AZTH`  | MFA issuer name                        |

## Example Configuration Files

### Development Environment (.env.development)

```bash
# Server
AZTH_SERVER_ADDRESS=0.0.0.0
AZTH_SERVER_PORT=8080
AZTH_LOGGER_LEVEL=debug

# Database - PostgreSQL
AZTH_DATABASE_DRIVER=postgres
AZTH_DATABASE_HOST=localhost
AZTH_DATABASE_PORT=5432
AZTH_DATABASE_USER=azth
AZTH_DATABASE_PASSWORD=azth
AZTH_DATABASE_NAME=azth
AZTH_DATABASE_SSL_MODE=disable

# Redis
AZTH_REDIS_ENABLED=true
AZTH_REDIS_HOST=localhost
AZTH_REDIS_PORT=6379

# JWT
AZTH_JWT_SECRET=your-super-secret-jwt-key-change-in-production
AZTH_JWT_ALGORITHM=HS256

# OIDC
AZTH_OIDC_ISSUER=http://localhost:8080

# Telemetry
AZTH_TELEMETRY_TRACING_ENABLED=false
```

### Production Environment (.env.production)

```bash
# Server
AZTH_SERVER_ADDRESS=0.0.0.0
AZTH_SERVER_PORT=8080
AZTH_LOGGER_LEVEL=info
AZTH_LOGGER_FORMAT=json

# TLS
AZTH_SERVER_TLS_ENABLED=true
AZTH_SERVER_TLS_CERT_FILE=/etc/ssl/certs/azth.crt
AZTH_SERVER_TLS_KEY_FILE=/etc/ssl/private/azth.key

# Database - PostgreSQL with SSL
AZTH_DATABASE_DRIVER=postgres
AZTH_DATABASE_HOST=prod-db.example.com
AZTH_DATABASE_PORT=5432
AZTH_DATABASE_USER=azth_prod
AZTH_DATABASE_PASSWORD=${DB_PASSWORD}
AZTH_DATABASE_NAME=azth_prod
AZTH_DATABASE_SSL_MODE=require
AZTH_DATABASE_MAX_OPEN_CONNECTIONS=50
AZTH_DATABASE_MAX_IDLE_CONNECTIONS=25

# Redis
AZTH_REDIS_ENABLED=true
AZTH_REDIS_HOST=prod-redis.example.com
AZTH_REDIS_PORT=6379
AZTH_REDIS_PASSWORD=${REDIS_PASSWORD}
AZTH_REDIS_POOL_SIZE=20

# JWT
AZTH_JWT_PRIVATE_KEY_PATH=/etc/azth/keys/jwt_private.pem
AZTH_JWT_PUBLIC_KEY_PATH=/etc/azth/keys/jwt_public.pem
AZTH_JWT_ALGORITHM=RS256

# OIDC
AZTH_OIDC_ISSUER=https://auth.example.com

# Security
AZTH_SECURITY_PASSWORD_MIN_LENGTH=12
AZTH_SECURITY_PASSWORD_REQUIRE_SYMBOL=true
AZTH_SECURITY_MFA_ENABLED=true

# Telemetry
AZTH_TELEMETRY_TRACING_ENABLED=true
AZTH_TELEMETRY_TRACING_ENDPOINT=https://jaeger.example.com/api/traces
AZTH_TELEMETRY_METRICS_ENABLED=true
AZTH_TELEMETRY_METRICS_ENDPOINT=https://prometheus.example.com/api/v1/write
```

### MySQL Example (.env.mysql)

```bash
# Database - MySQL
AZTH_DATABASE_DRIVER=mysql
AZTH_DATABASE_HOST=localhost
AZTH_DATABASE_PORT=3306
AZTH_DATABASE_USER=azth
AZTH_DATABASE_PASSWORD=azth
AZTH_DATABASE_NAME=azth
AZTH_DATABASE_MYSQL_CHARSET=utf8mb4
AZTH_DATABASE_MYSQL_COLLATION=utf8mb4_unicode_ci
```

### SQLite Example (.env.sqlite)

```bash
# Database - SQLite
AZTH_DATABASE_DRIVER=sqlite3
AZTH_DATABASE_SQLITE_FILE=./data/azth.db
AZTH_DATABASE_SQLITE_MODE=rwc

# Disable Redis, use local KV store
AZTH_REDIS_ENABLED=false
AZTH_REDIS_LOCAL_STORE_TYPE=file
AZTH_REDIS_LOCAL_STORE_FILE_PATH=./data/kv_store.db
```

### SQL Server Example (.env.sqlserver)

```bash
# Database - SQL Server
AZTH_DATABASE_DRIVER=sqlserver
AZTH_DATABASE_HOST=localhost
AZTH_DATABASE_PORT=1433
AZTH_DATABASE_USER=azth
AZTH_DATABASE_PASSWORD=azth
AZTH_DATABASE_NAME=azth
AZTH_DATABASE_SQLSERVER_ENCRYPT=false
AZTH_DATABASE_SQLSERVER_TRUST_CERT=true
```

## Notes

- Duration values accept Go duration format: `1s`, `5m`, `2h`, `24h`, etc.
- Boolean values accept: `true`, `false`, `1`, `0`
- Array values (like CORS origins) should be comma-separated
- Environment variables take precedence over configuration files
- Missing environment variables will use default values
- Sensitive values like passwords should be set via environment variables, not configuration files
