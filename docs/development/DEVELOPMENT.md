# Development Guide

## Getting Started

This guide will help you set up your development environment and understand the development workflow for the AZTH Backend project.

## Prerequisites

### Required Software

- **Go 1.21+**: [Download](https://golang.org/dl/)
- **PostgreSQL 13+**: [Download](https://www.postgresql.org/download/)
- **Redis 6+**: [Download](https://redis.io/download)
- **Git**: [Download](https://git-scm.com/downloads)

### Optional Tools

- **Docker & Docker Compose**: For containerized development
- **Make**: For running build commands
- **VS Code**: Recommended IDE with Go extension
- **Postman/Insomnia**: For API testing

## Environment Setup

### 1. Clone Repository

```bash
git clone <repository-url>
cd azth/backend
```

### 2. Install Dependencies

```bash
go mod download
```

### 3. Database Setup

#### PostgreSQL

```bash
# Create database
createdb azth_dev

# Create test database
createdb azth_test

# Verify connection
psql -d azth_dev -c "SELECT version();"
```

#### Redis

```bash
# Start Redis
redis-server

# Verify connection
redis-cli ping
```

### 4. Configuration

```bash
# Copy example config
cp config.yaml.example config.yaml

# Edit configuration
vim config.yaml
```

**Example config.yaml:**

```yaml
app:
  name: "AZTH Backend"
  version: "1.0.0"
  environment: "development"
  port: 8080
  debug: true

database:
  host: "localhost"
  port: 5432
  user: "postgres"
  password: "password"
  name: "azth_dev"
  ssl_mode: "disable"
  max_open_conns: 25
  max_idle_conns: 5
  conn_max_lifetime: "5m"

redis:
  addr: "localhost:6379"
  password: ""
  db: 0

auth:
  mode: "stateful" # or "stateless"
  jwt_secret: "your-jwt-secret-change-in-production"
  session_ttl: "24h"
  refresh_token_ttl: "168h"
  max_login_attempts: 5
  lockout_duration: "15m"

logging:
  level: "debug"
  format: "json"
  output: "stdout"
```

### 5. Environment Variables

Create `.env` file:

```bash
# Database
DATABASE_URL=postgres://postgres:password@localhost:5432/azth_dev?sslmode=disable
REDIS_URL=redis://localhost:6379/0

# Authentication
JWT_SECRET=your-jwt-secret-here
SESSION_SECRET=your-session-secret-here

# Application
APP_ENV=development
LOG_LEVEL=debug
PORT=8080

# External Services
SMTP_HOST=localhost
SMTP_PORT=587
SMTP_USER=test@example.com
SMTP_PASS=password

# Testing
TEST_DATABASE_URL=postgres://postgres:password@localhost:5432/azth_test?sslmode=disable
```

### 6. Run Migrations

```bash
# Run database migrations
make migrate-up

# Verify migrations
make migrate-status
```

### 7. Start Development Server

```bash
# Start with hot reload
make run-dev

# Or start normally
make run
```

## Development Workflow

### 1. Feature Development

```bash
# Create feature branch
git checkout -b feature/user-authentication

# Make changes
# Write tests
# Update documentation

# Run tests
make test

# Run linting
make lint

# Format code
make fmt

# Commit changes
git add .
git commit -m "feat: add user authentication"

# Push and create PR
git push origin feature/user-authentication
```

### 2. Testing Workflow

```bash
# Run all tests
make test

# Run tests with coverage
make test-coverage

# Run specific module tests
go test ./internal/modules/auth/...

# Run integration tests
make test-integration

# Run with race detection
go test -race ./...

# Run benchmarks
make benchmark
```

### 3. Database Workflow

```bash
# Create new migration
make migrate-create name=add_user_table

# Run migrations
make migrate-up

# Rollback migrations
make migrate-down

# Check migration status
make migrate-status

# Reset database (development only)
make migrate-reset
```

## Project Structure

### Directory Layout

```
backend/
├── cmd/                    # Application entrypoints
│   └── main.go            # Main application
├── internal/               # Private application code
│   ├── config/            # Configuration management
│   ├── db/                # Database connections and migrations
│   ├── domain/            # Domain models and business rules
│   ├── fx/                # Dependency injection setup
│   ├── server/            # HTTP server setup
│   └── modules/           # Feature modules
│       ├── auth/          # Authentication module
│       ├── user/          # User management
│       ├── tenant/        # Multi-tenancy
│       ├── role/          # Role management
│       ├── permission/    # Permission management
│       ├── otp/           # OTP and MFA
│       └── notification/  # Notifications
├── pkg/                   # Shared utilities and packages
│   ├── logger/            # Structured logging
│   ├── middleware/        # HTTP middleware
│   ├── utils/             # Utility functions
│   └── validators/        # Input validation
├── configs/               # Configuration files
├── scripts/               # Build and deployment scripts
├── docs/                  # Documentation
└── tests/                 # Integration and E2E tests
```

### Module Structure

Each module follows this structure:

```
module/
├── handlers/              # HTTP handlers
│   ├── http.go           # Route definitions
│   └── handlers.go       # Handler implementations
├── service/              # Business logic
│   ├── interface.go      # Service interface
│   └── impl.go           # Service implementation
├── repository/           # Data access
│   ├── interface.go      # Repository interface
│   └── postgres.go       # PostgreSQL implementation
├── dto/                  # Data transfer objects
│   └── dto.go           # Request/response DTOs
└── cqrs/                 # Command/Query handlers (optional)
    ├── commands.go       # Command handlers
    └── queries.go        # Query handlers
```

## Coding Standards

### Go Code Style

Follow the [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments).

#### Naming Conventions

```go
// Package names: lowercase, single word
package user

// Interface names: noun or noun phrase
type UserRepository interface {
    GetByID(ctx context.Context, id uuid.UUID) (*User, error)
}

// Struct names: CamelCase
type UserService struct {
    repo UserRepository
}

// Function names: CamelCase
func (s *UserService) CreateUser(ctx context.Context, req *CreateUserRequest) error {
    // implementation
}

// Constants: CamelCase or ALL_CAPS for public constants
const MaxRetries = 3
const DEFAULT_PAGE_SIZE = 20

// Variables: camelCase
var userCache = make(map[string]*User)
```

#### Error Handling

```go
// Wrap errors with context
func (s *UserService) GetUser(ctx context.Context, id uuid.UUID) (*User, error) {
    user, err := s.repo.GetByID(ctx, id)
    if err != nil {
        return nil, fmt.Errorf("failed to get user %s: %w", id, err)
    }
    return user, nil
}

// Use typed errors for business logic
type ValidationError struct {
    Field   string
    Message string
}

func (e ValidationError) Error() string {
    return fmt.Sprintf("validation error: %s - %s", e.Field, e.Message)
}
```

#### Context Usage

```go
// Always accept context as first parameter
func (s *UserService) CreateUser(ctx context.Context, req *CreateUserRequest) error {
    // Pass context to all downstream calls
    if err := s.repo.Create(ctx, user); err != nil {
        return err
    }

    // Use context for cancellation
    select {
    case <-ctx.Done():
        return ctx.Err()
    default:
        // continue processing
    }

    return nil
}
```

#### Logging

```go
// Use structured logging
func (s *UserService) CreateUser(ctx context.Context, req *CreateUserRequest) error {
    s.logger.Info("Creating user",
        "email", req.Email,
        "username", req.Username,
    )

    user, err := s.repo.Create(ctx, req)
    if err != nil {
        s.logger.Error("Failed to create user",
            "error", err,
            "email", req.Email,
        )
        return err
    }

    s.logger.Info("User created successfully",
        "user_id", user.ID,
        "email", user.Email,
    )

    return nil
}
```

### Database Conventions

#### Migration Files

```sql
-- migrations/001_create_users_table.up.sql
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
    mfa_enabled BOOLEAN DEFAULT FALSE,
    mfa_secret TEXT,
    backup_codes TEXT[],
    status VARCHAR(20) DEFAULT 'active',
    last_login_at TIMESTAMPTZ,
    login_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

-- Indexes
CREATE UNIQUE INDEX idx_users_tenant_email ON users(tenant_id, email) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX idx_users_tenant_username ON users(tenant_id, username) WHERE deleted_at IS NULL;
CREATE INDEX idx_users_status ON users(status);
CREATE INDEX idx_users_created_at ON users(created_at);

-- Triggers
CREATE TRIGGER trigger_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
```

#### Repository Patterns

```go
// Always use prepared statements or parameterized queries
func (r *PostgresUserRepository) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
    query := `
        SELECT id, tenant_id, email, username, password_hash,
               first_name, last_name, avatar, email_verified,
               mfa_enabled, status, created_at, updated_at
        FROM users
        WHERE email = $1 AND tenant_id = $2 AND deleted_at IS NULL
    `

    tenantID := tenant.FromContext(ctx)
    var user domain.User

    err := r.db.QueryRowContext(ctx, query, email, tenantID).Scan(
        &user.ID, &user.TenantID, &user.Email, &user.Username,
        &user.PasswordHash, &user.FirstName, &user.LastName,
        &user.Avatar, &user.EmailVerified, &user.MFAEnabled,
        &user.Status, &user.CreatedAt, &user.UpdatedAt,
    )

    if err != nil {
        if err == sql.ErrNoRows {
            return nil, ErrUserNotFound
        }
        return nil, fmt.Errorf("failed to get user by email: %w", err)
    }

    return &user, nil
}
```

### API Design

#### Handler Structure

```go
// Use dependency injection
type UserHandler struct {
    userService UserService
    logger      *logger.Logger
    validator   *validator.Validate
}

// Register routes
func (h *UserHandler) RegisterRoutes(g *echo.Group) {
    g.GET("/users/me", h.GetProfile)
    g.PUT("/users/me", h.UpdateProfile)
    g.GET("/users", h.ListUsers, middleware.RequireRole("admin"))
}

// Handler implementation
func (h *UserHandler) GetProfile(c echo.Context) error {
    userID := c.Get("user_id").(uuid.UUID)

    user, err := h.userService.GetByID(c.Request().Context(), userID)
    if err != nil {
        return h.handleError(c, err)
    }

    return c.JSON(http.StatusOK, map[string]interface{}{
        "data": user,
    })
}
```

#### DTO Validation

```go
// Use struct tags for validation
type CreateUserRequest struct {
    Email     string `json:"email" validate:"required,email"`
    Username  string `json:"username" validate:"required,min=3,max=50"`
    Password  string `json:"password" validate:"required,min=8"`
    FirstName string `json:"first_name" validate:"required,max=100"`
    LastName  string `json:"last_name" validate:"required,max=100"`
}

// Validate in handler
func (h *UserHandler) CreateUser(c echo.Context) error {
    var req CreateUserRequest
    if err := c.Bind(&req); err != nil {
        return c.JSON(http.StatusBadRequest, map[string]string{
            "error": "Invalid request format",
        })
    }

    if err := h.validator.Struct(&req); err != nil {
        return h.handleValidationError(c, err)
    }

    // Process request...
}
```

## Testing

### Unit Testing

```go
// Use table-driven tests
func TestUserService_CreateUser(t *testing.T) {
    tests := []struct {
        name        string
        req         *CreateUserRequest
        setupMocks  func(*mocks.UserRepository)
        wantErr     bool
        expectedErr string
    }{
        {
            name: "successful_creation",
            req: &CreateUserRequest{
                Email:    "test@example.com",
                Username: "testuser",
                Password: "password123",
            },
            setupMocks: func(repo *mocks.UserRepository) {
                repo.On("EmailExists", mock.Anything, "test@example.com", mock.Anything).
                    Return(false, nil)
                repo.On("Create", mock.Anything, mock.AnythingOfType("*domain.User")).
                    Return(nil)
            },
            wantErr: false,
        },
        {
            name: "email_already_exists",
            req: &CreateUserRequest{
                Email:    "existing@example.com",
                Username: "testuser",
                Password: "password123",
            },
            setupMocks: func(repo *mocks.UserRepository) {
                repo.On("EmailExists", mock.Anything, "existing@example.com", mock.Anything).
                    Return(true, nil)
            },
            wantErr:     true,
            expectedErr: "email already exists",
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Setup
            mockRepo := &mocks.UserRepository{}
            mockLogger := &mocks.Logger{}
            service := NewUserService(mockRepo, mockLogger)

            tt.setupMocks(mockRepo)

            // Execute
            err := service.CreateUser(context.Background(), tt.req)

            // Assert
            if tt.wantErr {
                assert.Error(t, err)
                if tt.expectedErr != "" {
                    assert.Contains(t, err.Error(), tt.expectedErr)
                }
            } else {
                assert.NoError(t, err)
            }

            mockRepo.AssertExpectations(t)
        })
    }
}
```

### Integration Testing

```go
// Use test database
func TestUserRepository_Integration(t *testing.T) {
    if testing.Short() {
        t.Skip("Skipping integration test")
    }

    // Setup test database
    db := setupTestDB(t)
    defer cleanupTestDB(t, db)

    repo := NewPostgresUserRepository(db, logger.NewTestLogger())

    // Test case
    t.Run("create_and_get_user", func(t *testing.T) {
        user := &domain.User{
            ID:       uuid.New(),
            Email:    "test@example.com",
            Username: "testuser",
            // ... other fields
        }

        // Create
        err := repo.Create(context.Background(), user)
        require.NoError(t, err)

        // Get
        retrieved, err := repo.GetByEmail(context.Background(), user.Email)
        require.NoError(t, err)
        assert.Equal(t, user.Email, retrieved.Email)
        assert.Equal(t, user.Username, retrieved.Username)
    })
}
```

## Debug and Troubleshooting

### Logging

```go
// Configure structured logging
logger := logger.NewLogger(&logger.Config{
    Level:   "debug",
    Format:  "json",
    Output:  "stdout",
})

// Use context for correlation
ctx := logger.WithRequestID(ctx, "req_123456789")
logger.InfoContext(ctx, "Processing request", "endpoint", "/users")
```

### Performance Profiling

```go
// Add pprof endpoints (development only)
import _ "net/http/pprof"

// In main.go
if config.Environment == "development" {
    go func() {
        log.Println(http.ListenAndServe("localhost:6060", nil))
    }()
}
```

```bash
# Profile CPU
go tool pprof http://localhost:6060/debug/pprof/profile?seconds=30

# Profile memory
go tool pprof http://localhost:6060/debug/pprof/heap

# View goroutines
go tool pprof http://localhost:6060/debug/pprof/goroutine
```

### Database Debugging

```sql
-- Enable query logging (PostgreSQL)
SET log_statement = 'all';
SET log_min_duration_statement = 0;

-- Check slow queries
SELECT query, mean_exec_time, calls
FROM pg_stat_statements
ORDER BY mean_exec_time DESC
LIMIT 10;

-- Check active connections
SELECT count(*) FROM pg_stat_activity;
```

## IDE Configuration

### VS Code Settings

Create `.vscode/settings.json`:

```json
{
  "go.useLanguageServer": true,
  "go.formatTool": "goimports",
  "go.lintTool": "golangci-lint",
  "go.lintOnSave": "package",
  "go.testFlags": ["-v", "-race"],
  "go.testTimeout": "30s",
  "editor.formatOnSave": true,
  "editor.codeActionsOnSave": {
    "source.organizeImports": true
  }
}
```

### Recommended Extensions

- Go (Google)
- GitLens
- Error Lens
- REST Client
- PostgreSQL (cweijan)
- Redis for VS Code

## Git Workflow

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
type(scope): description

feat(auth): add JWT token refresh functionality
fix(user): resolve email validation issue
docs(api): update authentication endpoints
test(auth): add unit tests for login service
refactor(db): improve connection pooling
perf(cache): optimize user lookup queries
style(lint): fix formatting issues
chore(deps): update Go dependencies
```

### Branch Naming

```
feature/feature-name
bugfix/bug-description
hotfix/critical-fix
docs/documentation-update
refactor/code-improvement
test/test-coverage
```

### Pull Request Template

```markdown
## Description

Brief description of changes

## Type of Change

- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing

- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Manual testing completed

## Checklist

- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] No breaking changes
```

## Make Commands Reference

```bash
# Development
make run              # Run application
make run-dev          # Run with hot reload
make build            # Build binary
make clean            # Clean build artifacts

# Testing
make test             # Run tests
make test-coverage    # Run tests with coverage
make test-integration # Run integration tests
make benchmark        # Run benchmarks

# Database
make migrate-up       # Run migrations
make migrate-down     # Rollback migrations
make migrate-create   # Create new migration
make migrate-status   # Check migration status

# Code Quality
make lint             # Run linters
make fmt              # Format code
make vet              # Run go vet
make security         # Security scan

# Docker
make docker-build     # Build Docker image
make docker-run       # Run in Docker
make docker-compose   # Run with docker-compose

# Documentation
make docs             # Generate documentation
make docs-serve       # Serve documentation locally
```

## Environment-Specific Configuration

### Development

```yaml
# config.development.yaml
app:
  environment: "development"
  debug: true
  port: 8080

logging:
  level: "debug"
  format: "text"

database:
  name: "azth_dev"
  debug: true
```

### Testing

```yaml
# config.testing.yaml
app:
  environment: "testing"
  debug: false

database:
  name: "azth_test"

logging:
  level: "warn"
  output: "/dev/null"
```

### Production

```yaml
# config.production.yaml
app:
  environment: "production"
  debug: false
  port: 8080

logging:
  level: "info"
  format: "json"

database:
  ssl_mode: "require"
  max_open_conns: 100
```

## Contributing Guidelines

1. **Fork the repository**
2. **Create a feature branch**
3. **Write tests for new functionality**
4. **Follow coding standards**
5. **Update documentation**
6. **Submit a pull request**

### Code Review Process

1. Automated checks must pass
2. At least one approving review required
3. All conversations must be resolved
4. Branch must be up to date with main

For more detailed information, see the [Contributing Guide](CONTRIBUTING.md).
