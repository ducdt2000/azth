# Database Migration Management Tool

This project includes a comprehensive migration management tool that can auto-generate migrations from Go domain models and provides full control over migration stages.

## Features

- **Auto-generation from Go models**: Generate CREATE TABLE statements from Go structs with proper field mapping
- **Migration stage control**: Run specific migrations up/down with version targeting
- **Schema analysis**: Parse Go models and extract database schema information
- **Foreign key detection**: Automatically handle table dependencies and ordering
- **Index management**: Support for creating indexes and constraints
- **Rollback support**: Safe rollback with confirmation prompts
- **Migration status tracking**: View current migration state and pending changes

## Installation & Setup

1. **Build the migration tool**:

```bash
cd backend
go build -o bin/migrate cmd/migrate/main.go
```

2. **Make it executable** (optional):

```bash
chmod +x bin/migrate
```

3. **Add to PATH** (optional):

```bash
export PATH=$PATH:$(pwd)/bin
```

## Usage

### Basic Commands

#### Generate Migration from Models

Auto-generate a migration based on your Go domain models:

```bash
# Generate migration from all models in internal/domain
./bin/migrate -action=generate -name=create_initial_schema -from-models

# Generate from specific path
./bin/migrate -action=generate -name=add_tenant_tables -from-models -model-path=internal/domain

# Generate empty migration template
./bin/migrate -action=generate -name=add_custom_indexes
```

#### Run Migrations

```bash
# Run all pending migrations
./bin/migrate -action=up

# Migrate to specific version
./bin/migrate -action=up -target=003

# Check migration status
./bin/migrate -action=status

# Get current version
./bin/migrate -action=version
```

#### Rollback Migrations

```bash
# Rollback one migration (with confirmation)
./bin/migrate -action=down

# Rollback to specific version (with confirmation)
./bin/migrate -action=down -target=002

# Force rollback without confirmation
./bin/migrate -action=down -force

# Reset all migrations (dangerous!)
./bin/migrate -action=reset -force
```

#### Development Commands

```bash
# Create tables directly from models (dev only)
./bin/migrate -action=create-tables -model-path=internal/domain
```

### Command Line Options

| Option         | Description                                                                  | Default           |
| -------------- | ---------------------------------------------------------------------------- | ----------------- |
| `-action`      | Migration action (generate, up, down, status, reset, version, create-tables) | Required          |
| `-name`        | Migration name (required for generate)                                       | -                 |
| `-target`      | Target version for up/down operations                                        | -                 |
| `-force`       | Skip confirmation prompts                                                    | false             |
| `-from-models` | Generate migration from Go models                                            | false             |
| `-model-path`  | Path to domain models                                                        | `internal/domain` |

## Model-to-SQL Mapping

The tool automatically converts Go types to PostgreSQL types:

| Go Type                  | PostgreSQL Type              |
| ------------------------ | ---------------------------- |
| `string`                 | `TEXT`                       |
| `int`, `int32`           | `INTEGER`                    |
| `int64`                  | `BIGINT`                     |
| `bool`                   | `BOOLEAN`                    |
| `float32`                | `REAL`                       |
| `float64`                | `DOUBLE PRECISION`           |
| `time.Time`              | `TIMESTAMP WITH TIME ZONE`   |
| `uuid.UUID`              | `UUID`                       |
| `[]Type`                 | `Type[]` (PostgreSQL arrays) |
| `*Type`                  | Nullable version of Type     |
| `map[string]interface{}` | `JSONB`                      |

### Struct Tag Support

The tool reads standard Go struct tags for database mapping:

```go
type User struct {
    ID       uuid.UUID `db:"id" json:"id"`                    // Maps to "id" column
    Email    string    `db:"email" json:"email" validate:"required,email"` // NOT NULL constraint
    Username *string   `db:"username" json:"username,omitempty"` // Nullable
    IsActive bool      `db:"is_active" json:"is_active"`       // Boolean column
}
```

### Automatic Features

- **Primary Keys**: Fields named `ID` are automatically set as primary keys with UUID default
- **Timestamps**: `CreatedAt`, `UpdatedAt` fields are recognized as timestamp columns
- **Soft Deletes**: `DeletedAt` fields enable soft delete pattern
- **Foreign Keys**: Fields ending with `ID` that reference other model IDs
- **Indexes**: Automatically creates indexes on foreign keys and commonly queried fields
- **Table Naming**: Converts `CamelCase` struct names to `snake_case` table names with pluralization

## Examples

### 1. Generate Initial Schema

```bash
# This will analyze all models in internal/domain and create a comprehensive migration
./bin/migrate -action=generate -name=create_initial_schema -from-models
```

Generated migration will include:

- All tables with proper column types and constraints
- Primary key constraints and auto-generated UUIDs
- Foreign key relationships with proper ordering
- Indexes on foreign keys and commonly queried fields
- Timestamp defaults and triggers

### 2. Add New Model

After creating a new model in `internal/domain/product.go`:

```bash
./bin/migrate -action=generate -name=add_product_table -from-models
```

### 3. Migration Management Workflow

```bash
# Check current status
./bin/migrate -action=status

# Run pending migrations
./bin/migrate -action=up

# If something goes wrong, rollback
./bin/migrate -action=down

# Check new status
./bin/migrate -action=status
```

### 4. Production Deployment

```bash
# In production, always check status first
./bin/migrate -action=status

# Run migrations with explicit version targeting
./bin/migrate -action=up -target=005

# Verify final state
./bin/migrate -action=version
```

## Migration File Structure

Generated migration files follow this structure:

```sql
-- 20240101120000
-- Migration: create_initial_schema
-- Auto-generated from models in internal/domain

-- +goose Up
CREATE TABLE IF NOT EXISTS tenants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE,
    domain TEXT,
    status TEXT NOT NULL,
    settings JSONB,
    metadata JSONB,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMP WITH TIME ZONE,
    created_by UUID NOT NULL,
    updated_by UUID
);

CREATE INDEX IF NOT EXISTS idx_tenants_slug ON tenants (slug);
CREATE INDEX IF NOT EXISTS idx_tenants_status ON tenants (status);
CREATE INDEX IF NOT EXISTS idx_tenants_deleted_at ON tenants (deleted_at);

-- +goose Down
DROP TABLE IF EXISTS tenants;
```

## Best Practices

1. **Always backup production data** before running migrations
2. **Test migrations in staging** environment first
3. **Use version targeting** in production deployments
4. **Keep migrations small and focused** - one logical change per migration
5. **Review generated SQL** before applying, especially for production
6. **Use descriptive migration names** that explain the change
7. **Never edit existing migration files** - create new ones for changes
8. **Document breaking changes** in migration comments

## Integration with Application

The migration tool integrates with the existing database setup:

```go
// In internal/db/db.go, migrations run automatically on startup
func (d *DB) Migrate() error {
    // Uses embedded migrations from internal/db/migrations/
    return goose.Up(d.DB.DB, "migrations")
}
```

For manual control, disable auto-migration and use the CLI tool instead.

## Troubleshooting

### Common Issues

1. **"No tables found"**: Ensure your models have `db` tags or recognizable field names
2. **"Circular dependency"**: Check foreign key relationships for cycles
3. **"Migration failed"**: Check PostgreSQL logs for constraint violations
4. **"Version mismatch"**: Use `./bin/migrate -action=status` to see current state

### Debug Mode

For detailed output, check the application logs or add debug logging to the migration tool.

### Recovery

If migrations get into a bad state:

```bash
# Check current status
./bin/migrate -action=status

# Reset if necessary (DANGER: loses data)
./bin/migrate -action=reset -force

# Reapply from clean state
./bin/migrate -action=up
```

## Configuration

The tool uses the same database configuration as the main application. Ensure your `config.yaml` has correct database settings:

```yaml
database:
  url: "postgres://user:pass@localhost:5432/dbname?sslmode=disable"
  # or individual settings:
  host: "localhost"
  port: 5432
  user: "azth"
  password: "azth"
  name: "azth"
  ssl_mode: "disable"
```
