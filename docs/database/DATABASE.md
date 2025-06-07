# Database Documentation

## Overview

AZTH Backend uses PostgreSQL as the primary database with Redis for caching and session storage. The database design follows multi-tenant architecture with row-level security and comprehensive audit trails.

## Database Architecture

### Multi-Tenant Design

The system implements **tenant-aware** architecture where all data is isolated by tenant:

```sql
-- Every tenant-aware table includes tenant_id
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    -- other fields...
    UNIQUE(tenant_id, email)
);
```

### Key Design Principles

1. **Soft Deletes**: Use `deleted_at` timestamp instead of hard deletes
2. **Audit Trails**: Track `created_at`, `updated_at`, and `created_by`/`updated_by`
3. **UUID Primary Keys**: For better security and distributed systems
4. **Tenant Isolation**: Row-level security policies
5. **Optimized Indexes**: For performance and uniqueness constraints

## Schema Design

### Core Tables

#### tenants

```sql
CREATE TABLE tenants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(100) NOT NULL UNIQUE,
    domain VARCHAR(255),
    status VARCHAR(20) DEFAULT 'active',
    plan VARCHAR(50) DEFAULT 'free',
    settings JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

-- Indexes
CREATE INDEX idx_tenants_slug ON tenants(slug);
CREATE INDEX idx_tenants_domain ON tenants(domain);
CREATE INDEX idx_tenants_status ON tenants(status);
```

#### users

```sql
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    email VARCHAR(255) NOT NULL,
    username VARCHAR(100) NOT NULL,
    password_hash TEXT NOT NULL,
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    avatar TEXT,
    email_verified BOOLEAN DEFAULT FALSE,
    email_verification_token TEXT,
    email_verification_expires_at TIMESTAMPTZ,
    mfa_enabled BOOLEAN DEFAULT FALSE,
    mfa_secret TEXT,
    backup_codes TEXT[],
    status VARCHAR(20) DEFAULT 'active',
    last_login_at TIMESTAMPTZ,
    login_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMPTZ,
    password_reset_token TEXT,
    password_reset_expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

-- Unique constraints
CREATE UNIQUE INDEX idx_users_tenant_email
    ON users(tenant_id, email)
    WHERE deleted_at IS NULL;

CREATE UNIQUE INDEX idx_users_tenant_username
    ON users(tenant_id, username)
    WHERE deleted_at IS NULL;

-- Performance indexes
CREATE INDEX idx_users_status ON users(status);
CREATE INDEX idx_users_email_verification_token ON users(email_verification_token);
CREATE INDEX idx_users_password_reset_token ON users(password_reset_token);
CREATE INDEX idx_users_created_at ON users(created_at);
CREATE INDEX idx_users_last_login ON users(last_login_at);
```

#### roles

```sql
CREATE TABLE roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    name VARCHAR(100) NOT NULL,
    description TEXT,
    is_system BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

-- Unique constraint
CREATE UNIQUE INDEX idx_roles_tenant_name
    ON roles(tenant_id, name)
    WHERE deleted_at IS NULL;
```

#### permissions

```sql
CREATE TABLE permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) NOT NULL UNIQUE,
    resource VARCHAR(50) NOT NULL,
    action VARCHAR(50) NOT NULL,
    scope VARCHAR(20) DEFAULT 'tenant',
    description TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes
CREATE INDEX idx_permissions_resource ON permissions(resource);
CREATE INDEX idx_permissions_action ON permissions(action);
CREATE UNIQUE INDEX idx_permissions_resource_action ON permissions(resource, action);
```

#### user_roles

```sql
CREATE TABLE user_roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    assigned_by UUID REFERENCES users(id),
    assigned_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Unique constraint
CREATE UNIQUE INDEX idx_user_roles_user_role
    ON user_roles(user_id, role_id);

-- Performance indexes
CREATE INDEX idx_user_roles_user_id ON user_roles(user_id);
CREATE INDEX idx_user_roles_role_id ON user_roles(role_id);
CREATE INDEX idx_user_roles_expires_at ON user_roles(expires_at);
```

#### role_permissions

```sql
CREATE TABLE role_permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Unique constraint
CREATE UNIQUE INDEX idx_role_permissions_role_permission
    ON role_permissions(role_id, permission_id);
```

#### sessions

```sql
CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    refresh_token_hash TEXT UNIQUE,
    ip_address INET,
    user_agent TEXT,
    last_activity TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes
CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_token_hash ON sessions(token_hash);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX idx_sessions_last_activity ON sessions(last_activity);
```

#### otp_codes

```sql
CREATE TABLE otp_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,
    type VARCHAR(20) NOT NULL, -- email, sms, totp
    purpose VARCHAR(50) NOT NULL, -- login, verification, password_reset
    target VARCHAR(255), -- email or phone number
    attempts INTEGER DEFAULT 0,
    max_attempts INTEGER DEFAULT 3,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes
CREATE INDEX idx_otp_codes_user_id ON otp_codes(user_id);
CREATE INDEX idx_otp_codes_code_hash ON otp_codes(code_hash);
CREATE INDEX idx_otp_codes_expires_at ON otp_codes(expires_at);
CREATE INDEX idx_otp_codes_type_purpose ON otp_codes(type, purpose);
```

#### notifications

```sql
CREATE TABLE notifications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    type VARCHAR(50) NOT NULL, -- email, sms, push
    template VARCHAR(100) NOT NULL,
    recipient VARCHAR(255) NOT NULL,
    subject VARCHAR(255),
    content TEXT NOT NULL,
    status VARCHAR(20) DEFAULT 'pending',
    sent_at TIMESTAMPTZ,
    error_message TEXT,
    retry_count INTEGER DEFAULT 0,
    max_retries INTEGER DEFAULT 3,
    scheduled_at TIMESTAMPTZ DEFAULT NOW(),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes
CREATE INDEX idx_notifications_tenant_id ON notifications(tenant_id);
CREATE INDEX idx_notifications_user_id ON notifications(user_id);
CREATE INDEX idx_notifications_status ON notifications(status);
CREATE INDEX idx_notifications_type ON notifications(type);
CREATE INDEX idx_notifications_scheduled_at ON notifications(scheduled_at);
CREATE INDEX idx_notifications_created_at ON notifications(created_at);
```

### Audit Tables

#### audit_logs

```sql
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id),
    user_id UUID REFERENCES users(id),
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50) NOT NULL,
    resource_id UUID,
    old_values JSONB,
    new_values JSONB,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes
CREATE INDEX idx_audit_logs_tenant_id ON audit_logs(tenant_id);
CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_action ON audit_logs(action);
CREATE INDEX idx_audit_logs_resource ON audit_logs(resource_type, resource_id);
CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at);
```

## Database Functions and Triggers

### Updated At Trigger

```sql
-- Function to update updated_at column
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply to all tables with updated_at column
CREATE TRIGGER trigger_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER trigger_tenants_updated_at
    BEFORE UPDATE ON tenants
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Add to other tables as needed
```

### Audit Log Trigger

```sql
-- Function to create audit log entries
CREATE OR REPLACE FUNCTION create_audit_log()
RETURNS TRIGGER AS $$
DECLARE
    audit_user_id UUID;
    audit_tenant_id UUID;
BEGIN
    -- Get user and tenant from context
    audit_user_id := NULLIF(current_setting('app.current_user_id', true), '')::UUID;
    audit_tenant_id := NULLIF(current_setting('app.current_tenant_id', true), '')::UUID;

    IF TG_OP = 'DELETE' THEN
        INSERT INTO audit_logs (
            tenant_id, user_id, action, resource_type, resource_id, old_values
        ) VALUES (
            audit_tenant_id, audit_user_id, 'DELETE', TG_TABLE_NAME, OLD.id,
            row_to_json(OLD)
        );
        RETURN OLD;
    ELSIF TG_OP = 'UPDATE' THEN
        INSERT INTO audit_logs (
            tenant_id, user_id, action, resource_type, resource_id, old_values, new_values
        ) VALUES (
            audit_tenant_id, audit_user_id, 'UPDATE', TG_TABLE_NAME, NEW.id,
            row_to_json(OLD), row_to_json(NEW)
        );
        RETURN NEW;
    ELSIF TG_OP = 'INSERT' THEN
        INSERT INTO audit_logs (
            tenant_id, user_id, action, resource_type, resource_id, new_values
        ) VALUES (
            audit_tenant_id, audit_user_id, 'INSERT', TG_TABLE_NAME, NEW.id,
            row_to_json(NEW)
        );
        RETURN NEW;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- Apply audit trigger to important tables
CREATE TRIGGER trigger_users_audit
    AFTER INSERT OR UPDATE OR DELETE ON users
    FOR EACH ROW
    EXECUTE FUNCTION create_audit_log();
```

## Row-Level Security (RLS)

### Enable RLS

```sql
-- Enable RLS on tenant-aware tables
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE notifications ENABLE ROW LEVEL SECURITY;
```

### RLS Policies

```sql
-- Users can only access their tenant's data
CREATE POLICY tenant_isolation_users ON users
    FOR ALL TO app_user
    USING (tenant_id = current_setting('app.current_tenant_id')::UUID);

-- Roles policy
CREATE POLICY tenant_isolation_roles ON roles
    FOR ALL TO app_user
    USING (tenant_id = current_setting('app.current_tenant_id')::UUID);

-- Sessions policy - users can only see their own sessions
CREATE POLICY user_sessions_policy ON sessions
    FOR ALL TO app_user
    USING (
        user_id = current_setting('app.current_user_id')::UUID
        OR EXISTS (
            SELECT 1 FROM users u
            WHERE u.id = sessions.user_id
            AND u.tenant_id = current_setting('app.current_tenant_id')::UUID
        )
    );

-- Admin bypass policy (for system operations)
CREATE POLICY admin_bypass_users ON users
    FOR ALL TO app_admin
    USING (true);
```

## Migration Management

### Migration File Structure

```
internal/db/migrations/
├── 001_create_tenants_table.up.sql
├── 001_create_tenants_table.down.sql
├── 002_create_users_table.up.sql
├── 002_create_users_table.down.sql
├── 003_create_roles_and_permissions.up.sql
├── 003_create_roles_and_permissions.down.sql
└── ...
```

### Migration Best Practices

1. **Always create both up and down migrations**
2. **Test migrations on staging data**
3. **Use transactions for complex migrations**
4. **Never modify existing migrations**
5. **Add indexes in separate migrations for large tables**

### Example Migration

```sql
-- 001_create_users_table.up.sql
BEGIN;

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    email VARCHAR(255) NOT NULL,
    username VARCHAR(100) NOT NULL,
    password_hash TEXT NOT NULL,
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    email_verified BOOLEAN DEFAULT FALSE,
    status VARCHAR(20) DEFAULT 'active',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

-- Indexes
CREATE UNIQUE INDEX idx_users_tenant_email
    ON users(tenant_id, email)
    WHERE deleted_at IS NULL;

CREATE UNIQUE INDEX idx_users_tenant_username
    ON users(tenant_id, username)
    WHERE deleted_at IS NULL;

-- Triggers
CREATE TRIGGER trigger_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- RLS
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_users ON users
    FOR ALL TO app_user
    USING (tenant_id = current_setting('app.current_tenant_id')::UUID);

COMMIT;
```

```sql
-- 001_create_users_table.down.sql
BEGIN;

DROP POLICY IF EXISTS tenant_isolation_users ON users;
DROP TABLE IF EXISTS users CASCADE;

COMMIT;
```

## Database Configuration

### Connection Pool Settings

```yaml
database:
  host: "localhost"
  port: 5432
  user: "azth_user"
  password: "secure_password"
  name: "azth_db"
  ssl_mode: "require"

  # Connection pool settings
  max_open_conns: 100 # Maximum open connections
  max_idle_conns: 10 # Maximum idle connections
  conn_max_lifetime: "5m" # Maximum connection lifetime
  conn_max_idle_time: "1m" # Maximum idle time

  # Timeouts
  connect_timeout: "10s"
  query_timeout: "30s"

  # Retry settings
  max_retries: 3
  retry_delay: "1s"
```

### PostgreSQL Configuration

```postgresql
# postgresql.conf optimizations
shared_buffers = 256MB
effective_cache_size = 1GB
maintenance_work_mem = 64MB
checkpoint_completion_target = 0.7
wal_buffers = 16MB
default_statistics_target = 100
random_page_cost = 1.1
effective_io_concurrency = 200

# Connection settings
max_connections = 200
shared_preload_libraries = 'pg_stat_statements'

# Logging
log_statement = 'none'
log_duration = on
log_min_duration_statement = 1000
log_checkpoints = on
log_connections = on
log_disconnections = on
log_lock_waits = on
```

## Performance Optimization

### Indexing Strategy

```sql
-- Composite indexes for common queries
CREATE INDEX idx_users_tenant_status_created
    ON users(tenant_id, status, created_at);

-- Partial indexes for better performance
CREATE INDEX idx_users_active
    ON users(tenant_id, email)
    WHERE status = 'active' AND deleted_at IS NULL;

-- Covering indexes
CREATE INDEX idx_sessions_user_active
    ON sessions(user_id, expires_at)
    INCLUDE (token_hash, last_activity)
    WHERE expires_at > NOW();
```

### Query Optimization

```sql
-- Use EXPLAIN ANALYZE for query planning
EXPLAIN (ANALYZE, BUFFERS)
SELECT u.*, r.name as role_name
FROM users u
LEFT JOIN user_roles ur ON u.id = ur.user_id
LEFT JOIN roles r ON ur.role_id = r.id
WHERE u.tenant_id = $1 AND u.status = 'active'
ORDER BY u.created_at DESC
LIMIT 20;

-- Optimize with proper indexes
CREATE INDEX idx_users_tenant_status_created
    ON users(tenant_id, status, created_at);
```

### Partitioning (for large tables)

```sql
-- Partition audit_logs by month
CREATE TABLE audit_logs (
    id UUID DEFAULT gen_random_uuid(),
    tenant_id UUID,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    -- other columns...
) PARTITION BY RANGE (created_at);

-- Create monthly partitions
CREATE TABLE audit_logs_2024_01 PARTITION OF audit_logs
    FOR VALUES FROM ('2024-01-01') TO ('2024-02-01');

CREATE TABLE audit_logs_2024_02 PARTITION OF audit_logs
    FOR VALUES FROM ('2024-02-01') TO ('2024-03-01');
```

## Backup and Recovery

### Backup Strategy

```bash
#!/bin/bash
# backup-database.sh

# Configuration
DB_NAME="azth_db"
DB_USER="azth_user"
BACKUP_DIR="/backups"
DATE=$(date +%Y%m%d_%H%M%S)

# Full backup
pg_dump -h localhost -U $DB_USER -d $DB_NAME -F c -b -v \
    -f "$BACKUP_DIR/azth_db_full_$DATE.backup"

# Schema-only backup
pg_dump -h localhost -U $DB_USER -d $DB_NAME -s \
    -f "$BACKUP_DIR/azth_db_schema_$DATE.sql"

# Cleanup old backups (keep 30 days)
find $BACKUP_DIR -name "azth_db_*.backup" -mtime +30 -delete
```

### Point-in-Time Recovery

```bash
# Enable WAL archiving in postgresql.conf
archive_mode = on
archive_command = 'cp %p /archives/%f'
wal_level = replica

# Restore to specific point in time
pg_basebackup -h localhost -D /recovery -U postgres -v -P
# Edit recovery.conf
restore_command = 'cp /archives/%f %p'
recovery_target_time = '2024-01-01 12:00:00'
```

## Monitoring and Maintenance

### Health Checks

```sql
-- Connection count
SELECT count(*) as active_connections
FROM pg_stat_activity
WHERE state = 'active';

-- Long running queries
SELECT pid, now() - pg_stat_activity.query_start AS duration, query
FROM pg_stat_activity
WHERE (now() - pg_stat_activity.query_start) > interval '5 minutes';

-- Database size
SELECT pg_size_pretty(pg_database_size('azth_db'));

-- Table sizes
SELECT schemaname, tablename,
       pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as size
FROM pg_tables
WHERE schemaname = 'public'
ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;
```

### Regular Maintenance

```sql
-- Update statistics
ANALYZE;

-- Vacuum tables
VACUUM (ANALYZE, VERBOSE);

-- Reindex if needed
REINDEX DATABASE azth_db;

-- Check for bloat
SELECT schemaname, tablename,
       round(CASE WHEN otta=0 THEN 0.0 ELSE sml.relpages/otta::numeric END,1) AS tbloat
FROM (
  -- Query to calculate table bloat
  -- (complex query omitted for brevity)
) AS sml
ORDER BY tbloat DESC;
```

## Security Best Practices

### Database User Roles

```sql
-- Application user (limited permissions)
CREATE ROLE app_user LOGIN PASSWORD 'secure_password';
GRANT CONNECT ON DATABASE azth_db TO app_user;
GRANT USAGE ON SCHEMA public TO app_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO app_user;

-- Admin user (full permissions)
CREATE ROLE app_admin LOGIN PASSWORD 'admin_password';
GRANT ALL PRIVILEGES ON DATABASE azth_db TO app_admin;

-- Read-only user (for reporting)
CREATE ROLE app_readonly LOGIN PASSWORD 'readonly_password';
GRANT CONNECT ON DATABASE azth_db TO app_readonly;
GRANT USAGE ON SCHEMA public TO app_readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO app_readonly;
```

### Connection Security

```postgresql
# pg_hba.conf
# TYPE  DATABASE        USER            ADDRESS                 METHOD
local   all             postgres                                peer
host    azth_db         app_user        127.0.0.1/32           md5
host    azth_db         app_user        ::1/128                md5
hostssl azth_db         app_user        0.0.0.0/0              md5
```

### Data Encryption

```sql
-- Encrypt sensitive columns
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Example: encrypt credit card numbers
UPDATE payments
SET card_number = pgp_sym_encrypt(card_number, 'encryption_key')
WHERE card_number IS NOT NULL;

-- Decrypt when needed
SELECT pgp_sym_decrypt(card_number::bytea, 'encryption_key') as card_number
FROM payments
WHERE id = $1;
```

## Redis Configuration

### Redis Setup

```redis
# redis.conf
maxmemory 512mb
maxmemory-policy allkeys-lru
save 900 1
save 300 10
save 60 10000

# Security
requirepass your_redis_password
rename-command FLUSHDB ""
rename-command FLUSHALL ""
```

### Session Storage

```go
// Redis key patterns
const (
    SessionKeyPrefix = "session:"
    UserSessionsKey  = "user_sessions:%s"
    OTPKeyPrefix     = "otp:"
    CacheKeyPrefix   = "cache:"
)

// Session storage example
func (r *RedisSessionRepository) Store(ctx context.Context, session *Session) error {
    key := fmt.Sprintf("%s%s", SessionKeyPrefix, session.ID)
    data, _ := json.Marshal(session)

    return r.client.SetEX(ctx, key, string(data), session.TTL).Err()
}
```

## Troubleshooting

### Common Issues

1. **Connection Pool Exhausted**

   ```sql
   -- Check active connections
   SELECT count(*) FROM pg_stat_activity;

   -- Kill long-running queries
   SELECT pg_cancel_backend(pid) FROM pg_stat_activity
   WHERE state = 'active' AND query_start < NOW() - INTERVAL '1 hour';
   ```

2. **Slow Queries**

   ```sql
   -- Enable pg_stat_statements
   CREATE EXTENSION IF NOT EXISTS pg_stat_statements;

   -- Find slow queries
   SELECT query, mean_exec_time, calls, total_exec_time
   FROM pg_stat_statements
   ORDER BY mean_exec_time DESC
   LIMIT 10;
   ```

3. **Lock Contention**
   ```sql
   -- Check locks
   SELECT blocked_locks.pid AS blocked_pid,
          blocked_activity.usename AS blocked_user,
          blocking_locks.pid AS blocking_pid,
          blocking_activity.usename AS blocking_user,
          blocked_activity.query AS blocked_statement,
          blocking_activity.query AS current_statement_in_blocking_process
   FROM pg_catalog.pg_locks blocked_locks
   JOIN pg_catalog.pg_stat_activity blocked_activity
        ON blocked_activity.pid = blocked_locks.pid
   JOIN pg_catalog.pg_locks blocking_locks
        ON blocking_locks.locktype = blocked_locks.locktype
   JOIN pg_catalog.pg_stat_activity blocking_activity
        ON blocking_activity.pid = blocking_locks.pid
   WHERE NOT blocked_locks.granted;
   ```

---

For more information, see the [Architecture Guide](ARCHITECTURE.md) and [API Documentation](API.md).
