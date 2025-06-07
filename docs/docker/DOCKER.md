# Docker Setup and Deployment Guide

This guide explains how to build and deploy the AZTH application using Docker and Docker Compose with support for multiple databases and configurable services.

## Quick Start

1. **Copy the environment file:**

   ```bash
   cp env.example .env
   ```

2. **Start with PostgreSQL (default):**

   ```bash
   docker-compose --profile all up -d
   ```

3. **Access the application:**
   - Backend: http://localhost:8080
   - Frontend: http://localhost:3000
   - Grafana: http://localhost:3001 (admin/admin)
   - Jaeger UI: http://localhost:16686

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Supported Databases](#supported-databases)
- [Service Profiles](#service-profiles)
- [Environment Configuration](#environment-configuration)
- [Database-Specific Setup](#database-specific-setup)
- [Storage Options](#storage-options)
- [Observability Stack](#observability-stack)
- [Production Deployment](#production-deployment)
- [Troubleshooting](#troubleshooting)

## Architecture Overview

The application consists of the following services:

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│    Frontend     │────│     Backend     │────│    Database     │
│   (Nuxt 3)      │    │   (Go Server)   │    │ (Configurable)  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                              │
                              │
                    ┌─────────────────┐
                    │   Redis/KV      │
                    │ (Optional/Local)│
                    └─────────────────┘
```

## Supported Databases

The application supports multiple SQL databases:

| Database   | Image                                        | Default Port | Profile     |
| ---------- | -------------------------------------------- | ------------ | ----------- |
| PostgreSQL | `postgres:15-alpine`                         | 5432         | `postgres`  |
| MySQL      | `mysql:8.0`                                  | 3306         | `mysql`     |
| SQLite     | Built into Go binary                         | N/A          | N/A         |
| SQL Server | `mcr.microsoft.com/mssql/server:2022-latest` | 1433         | `sqlserver` |

## Service Profiles

Services are organized into profiles for flexible deployment:

### Core Profiles

- **`backend`** - Backend service with PostgreSQL and Redis
- **`frontend`** - Frontend service
- **`all`** - Backend + Frontend + PostgreSQL + Redis

### Database Profiles

- **`postgres`** - PostgreSQL database (default)
- **`mysql`** - MySQL database
- **`sqlserver`** - SQL Server database

### Optional Service Profiles

- **`redis`** - Redis cache (included in `backend` and `all`)
- **`observability`** - Jaeger + Prometheus + Grafana
- **`tracing`** - Jaeger only
- **`metrics`** - Prometheus only
- **`dashboards`** - Grafana only
- **`development`** - MailHog for email testing
- **`storage`** - MinIO for object storage

## Environment Configuration

### Using Environment Files

Create different environment files for different scenarios:

```bash
# Development with PostgreSQL
cp env.example .env.postgres

# Development with MySQL
cp env.example .env.mysql
# Edit .env.mysql and set AZTH_DATABASE_DRIVER=mysql

# Development with SQLite (no external database)
cp env.example .env.sqlite
# Edit .env.sqlite and set AZTH_DATABASE_DRIVER=sqlite3
```

### Loading Environment Files

```bash
# Use specific environment file
docker-compose --env-file .env.mysql --profile mysql --profile backend up -d

# Override specific variables
AZTH_DATABASE_DRIVER=mysql docker-compose --profile mysql --profile backend up -d
```

## Database-Specific Setup

### PostgreSQL (Default)

```bash
# Start PostgreSQL with backend
docker-compose --profile backend up -d

# Or with full stack
docker-compose --profile all up -d
```

**Environment variables:**

```bash
AZTH_DATABASE_DRIVER=postgres
AZTH_DATABASE_HOST=postgres
AZTH_DATABASE_PORT=5432
AZTH_DATABASE_USER=azth
AZTH_DATABASE_PASSWORD=azth
AZTH_DATABASE_NAME=azth
AZTH_DATABASE_SSL_MODE=disable
```

### MySQL

```bash
# Start MySQL with backend
docker-compose --profile mysql --profile backend up -d
```

**Environment variables:**

```bash
AZTH_DATABASE_DRIVER=mysql
AZTH_DATABASE_HOST=mysql
AZTH_DATABASE_PORT=3306
AZTH_DATABASE_USER=azth
AZTH_DATABASE_PASSWORD=azth
AZTH_DATABASE_NAME=azth
AZTH_DATABASE_MYSQL_CHARSET=utf8mb4
AZTH_DATABASE_MYSQL_COLLATION=utf8mb4_unicode_ci
```

### SQL Server

```bash
# Start SQL Server with backend
docker-compose --profile sqlserver --profile backend up -d
```

**Environment variables:**

```bash
AZTH_DATABASE_DRIVER=sqlserver
AZTH_DATABASE_HOST=sqlserver
AZTH_DATABASE_PORT=1433
AZTH_DATABASE_USER=sa
AZTH_DATABASE_PASSWORD=Azth123!
AZTH_DATABASE_NAME=azth
AZTH_DATABASE_SQLSERVER_ENCRYPT=false
AZTH_DATABASE_SQLSERVER_TRUST_CERT=true
```

### SQLite (Embedded)

SQLite doesn't require a separate database container:

```bash
# Start only backend with SQLite
docker-compose --profile backend up backend
```

**Environment variables:**

```bash
AZTH_DATABASE_DRIVER=sqlite3
AZTH_DATABASE_SQLITE_FILE=./data/azth.db
AZTH_DATABASE_SQLITE_MODE=rwc
AZTH_REDIS_ENABLED=false  # Use local KV store
AZTH_REDIS_LOCAL_STORE_TYPE=file
AZTH_REDIS_LOCAL_STORE_FILE_PATH=./data/kv_store.db
```

## Storage Options

### Redis (Default)

```bash
# Redis with password
AZTH_REDIS_PASSWORD=mypassword docker-compose --profile redis up -d
```

### Local KV Store (Fallback)

When Redis is disabled or unavailable, the application automatically falls back to a local KV store:

```bash
# Disable Redis, use local memory store
AZTH_REDIS_ENABLED=false docker-compose --profile backend up backend

# Disable Redis, use local file store
AZTH_REDIS_ENABLED=false \
AZTH_REDIS_LOCAL_STORE_TYPE=file \
AZTH_REDIS_LOCAL_STORE_FILE_PATH=./data/kv_store.db \
docker-compose --profile backend up backend
```

## Observability Stack

### Full Observability

```bash
# Start with full observability stack
docker-compose --profile all --profile observability up -d
```

This includes:

- **Jaeger** (http://localhost:16686) - Distributed tracing
- **Prometheus** (http://localhost:9090) - Metrics collection
- **Grafana** (http://localhost:3001) - Dashboards and visualization

### Individual Components

```bash
# Only tracing
docker-compose --profile backend --profile tracing up -d

# Only metrics
docker-compose --profile backend --profile metrics up -d

# Only dashboards
docker-compose --profile backend --profile dashboards up -d
```

### Enable Telemetry in Backend

```bash
# Enable tracing and metrics
AZTH_TELEMETRY_TRACING_ENABLED=true \
AZTH_TELEMETRY_METRICS_ENABLED=true \
docker-compose --profile all --profile observability up -d
```

## Production Deployment

### Production Configuration

1. **Create production environment file:**

   ```bash
   cp env.example .env.production
   ```

2. **Update security settings:**

   ```bash
   # Strong JWT secret
   AZTH_JWT_SECRET=$(openssl rand -base64 32)

   # Use RS256 with key files
   AZTH_JWT_ALGORITHM=RS256
   AZTH_JWT_PRIVATE_KEY_PATH=/etc/azth/keys/jwt_private.pem
   AZTH_JWT_PUBLIC_KEY_PATH=/etc/azth/keys/jwt_public.pem

   # Enable TLS
   AZTH_SERVER_TLS_ENABLED=true
   AZTH_SERVER_TLS_CERT_FILE=/etc/ssl/certs/azth.crt
   AZTH_SERVER_TLS_KEY_FILE=/etc/ssl/private/azth.key

   # Database with SSL
   AZTH_DATABASE_SSL_MODE=require
   AZTH_DATABASE_PASSWORD=${SECURE_DB_PASSWORD}

   # Redis with password
   AZTH_REDIS_PASSWORD=${SECURE_REDIS_PASSWORD}

   # Enhanced security
   AZTH_SECURITY_PASSWORD_MIN_LENGTH=12
   AZTH_SECURITY_PASSWORD_REQUIRE_SYMBOL=true
   AZTH_SECURITY_MFA_ENABLED=true

   # Production logging
   AZTH_LOGGER_LEVEL=info
   AZTH_LOGGER_FORMAT=json

   # Enable telemetry
   AZTH_TELEMETRY_TRACING_ENABLED=true
   AZTH_TELEMETRY_METRICS_ENABLED=true
   ```

3. **Deploy with production profile:**
   ```bash
   docker-compose --env-file .env.production --profile all up -d
   ```

### Production Build

For production, use the optimized Dockerfile:

```bash
# Build production image
docker build -t azth-backend:latest ./backend

# Deploy with production image
docker-compose --env-file .env.production up -d
```

## Common Commands

### Development

```bash
# Start development stack with hot reload
docker-compose --profile all up

# Start only backend for testing
docker-compose --profile backend up

# Start with specific database
docker-compose --profile mysql --profile backend up

# Start with observability
docker-compose --profile all --profile observability up
```

### Database Management

```bash
# Reset PostgreSQL data
docker-compose down -v postgres
docker volume rm azth-postgres-data

# Reset MySQL data
docker-compose down -v mysql
docker volume rm azth-mysql-data

# Reset all data
docker-compose down -v
docker volume prune
```

### Logs and Debugging

```bash
# View backend logs
docker-compose logs -f backend

# View database logs
docker-compose logs -f postgres  # or mysql, sqlserver

# View all logs
docker-compose logs -f

# Debug container
docker-compose exec backend sh
```

## Troubleshooting

### Common Issues

1. **Database Connection Failed**

   ```bash
   # Check database health
   docker-compose ps

   # Check database logs
   docker-compose logs postgres

   # Verify environment variables
   docker-compose config
   ```

2. **Redis Connection Failed**

   ```bash
   # Check Redis health
   docker-compose exec redis redis-cli ping

   # Disable Redis and use local store
   AZTH_REDIS_ENABLED=false docker-compose up backend
   ```

3. **Port Conflicts**

   ```bash
   # Change ports in environment
   AZTH_SERVER_PORT=8081 \
   AZTH_DATABASE_PORT=5433 \
   docker-compose up
   ```

4. **Permissions Issues**
   ```bash
   # Fix volume permissions
   sudo chown -R $(id -u):$(id -g) ./backend/data
   ```

### Health Checks

All services include health checks:

```bash
# Check service health
docker-compose ps

# Wait for healthy services
docker-compose up --wait

# Force health check
docker-compose exec backend curl -f http://localhost:8080/health
```

### Performance Monitoring

```bash
# Monitor resource usage
docker stats

# View service metrics in Grafana
open http://localhost:3001

# View traces in Jaeger
open http://localhost:16686
```

## Security Considerations

### Development vs Production

| Setting       | Development | Production        |
| ------------- | ----------- | ----------------- |
| JWT Algorithm | HS256       | RS256             |
| Database SSL  | disabled    | required          |
| TLS/HTTPS     | disabled    | enabled           |
| Log Level     | debug       | info              |
| Secrets       | hardcoded   | environment/vault |
| MFA           | disabled    | enabled           |

### Secure Deployment Checklist

- [ ] Use strong, unique passwords
- [ ] Enable TLS/HTTPS
- [ ] Use RS256 JWT with key files
- [ ] Enable database SSL
- [ ] Set up proper firewall rules
- [ ] Use secret management
- [ ] Enable audit logging
- [ ] Set up monitoring and alerts
- [ ] Regular security updates
- [ ] Backup strategy

## Backup and Recovery

### Database Backups

```bash
# PostgreSQL backup
docker-compose exec postgres pg_dump -U azth azth > backup.sql

# MySQL backup
docker-compose exec mysql mysqldump -u azth -p azth > backup.sql

# SQLite backup (copy file)
docker-compose exec backend cp /app/data/azth.db /app/data/backup.db
```

### Volume Backups

```bash
# Backup all volumes
docker run --rm -v azth-postgres-data:/data -v $(pwd):/backup alpine tar czf /backup/postgres-backup.tar.gz -C /data .

# Restore volume
docker run --rm -v azth-postgres-data:/data -v $(pwd):/backup alpine tar xzf /backup/postgres-backup.tar.gz -C /data
```
