# Architecture Guide

## Overview

AZTH Backend is built using **Clean Architecture** principles, implementing a modular microservices approach with Go. The system emphasizes separation of concerns, dependency inversion, and maintainable code structure.

## Architectural Principles

### Clean Architecture

```
┌─────────────────────────────────────────────┐
│                 External                    │
│            (HTTP, Database, etc.)           │
└─────────────────┬───────────────────────────┘
                  │
┌─────────────────┴───────────────────────────┐
│              Interface Layer                │
│         (Handlers, Controllers)             │
└─────────────────┬───────────────────────────┘
                  │
┌─────────────────┴───────────────────────────┐
│             Application Layer               │
│            (Services, Use Cases)            │
└─────────────────┬───────────────────────────┘
                  │
┌─────────────────┴───────────────────────────┐
│               Domain Layer                  │
│          (Entities, Business Rules)         │
└─────────────────────────────────────────────┘
```

### Layer Responsibilities

#### 1. Domain Layer (`internal/domain/`)

- **Core business entities and rules**
- **Domain models**: User, Tenant, Role, Permission, etc.
- **Business logic**: Validation, domain services
- **No external dependencies**

#### 2. Application Layer (`internal/modules/*/service/`)

- **Use cases and application services**
- **Business workflows**
- **Orchestrates domain objects**
- **Depends only on domain layer**

#### 3. Interface Layer (`internal/modules/*/handlers/`)

- **HTTP handlers and controllers**
- **Request/response DTOs**
- **Input validation**
- **Protocol-specific logic**

#### 4. Infrastructure Layer (`internal/modules/*/repository/`)

- **External service interfaces**
- **Database access**
- **Third-party integrations**
- **Configuration**

## System Components

### Core Modules

```
internal/modules/
├── auth/               # Authentication & Authorization
├── user/               # User Management
├── tenant/             # Multi-tenancy
├── role/               # Role-Based Access Control
├── permission/         # Permission Management
├── otp/                # One-Time Passwords & MFA
└── notification/       # Email/SMS Notifications
```

### Shared Components

```
internal/
├── config/             # Configuration Management
├── db/                 # Database Connections
├── domain/             # Shared Domain Models
├── fx/                 # Dependency Injection
├── constants/          # Application Constants
├── kv/                 # Key-Value Store
├── redis/              # Redis Client
└── server/             # HTTP Server Setup
```

### Support Packages

```
pkg/
├── logger/             # Structured Logging
├── middleware/         # HTTP Middleware
├── utils/              # Utility Functions
└── validators/         # Input Validation
```

## Design Patterns

### 1. Shared Repository Pattern

**Problem**: Multiple modules need user data access  
**Solution**: Single, comprehensive UserRepository interface

```go
// Shared across all modules
type UserRepository interface {
    GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error)
    GetByEmail(ctx context.Context, email string) (*domain.User, error)
    // ... comprehensive interface
}

// Usage in Auth module
type AuthService struct {
    userRepo userRepo.UserRepository  // Shared interface
}

// Usage in Notification module
type NotificationService struct {
    userRepo userRepo.UserRepository  // Same interface
}
```

**Benefits**:

- DRY principle adherence
- Consistent behavior across modules
- Single source of truth
- Type safety

### 2. CQRS (Command Query Responsibility Segregation)

**Commands**: Modify system state  
**Queries**: Read system state

```go
// Command Handler
type CreateUserCommand struct {
    Email     string
    Username  string
    Password  string
}

func (h *UserCommandHandler) CreateUser(ctx context.Context, cmd *CreateUserCommand) error {
    // Validation, business logic, persistence
}

// Query Handler
type GetUserQuery struct {
    UserID uuid.UUID
}

func (h *UserQueryHandler) GetUser(ctx context.Context, query *GetUserQuery) (*UserDTO, error) {
    // Data retrieval and transformation
}
```

### 3. Dependency Injection (Uber FX)

**Provides automatic dependency resolution**:

```go
// Service Registration
var ServiceModule = fx.Module("services",
    fx.Provide(NewUserService),
    fx.Provide(NewAuthService),
    fx.Provide(NewNotificationService),
)

// Constructor
func NewAuthService(
    userRepo userRepo.UserRepository,
    sessionRepo SessionRepository,
    logger *logger.Logger,
) AuthService {
    return &authService{...}
}
```

### 4. Interface-Driven Development

**All dependencies are interfaces**:

```go
// Interface definition
type EmailSender interface {
    Send(to, subject, body string) error
}

// Implementation
type SMTPSender struct { /* ... */ }
func (s *SMTPSender) Send(to, subject, body string) error { /* ... */ }

// Usage
type NotificationService struct {
    emailSender EmailSender  // Interface, not concrete type
}
```

## Module Architecture

### Standard Module Structure

```
module/
├── handlers/           # HTTP request handlers
│   ├── http.go        # HTTP routes and handlers
│   └── middleware.go  # Module-specific middleware
├── service/           # Business logic layer
│   ├── interface.go   # Service interface
│   └── impl.go        # Service implementation
├── repository/        # Data access layer
│   ├── interface.go   # Repository interface
│   └── postgres.go    # PostgreSQL implementation
├── dto/               # Data transfer objects
│   └── dto.go         # Request/response DTOs
└── cqrs/              # Command/Query handlers (optional)
    ├── commands.go    # Command handlers
    └── queries.go     # Query handlers
```

### Authentication Module Example

```
auth/
├── handlers/
│   ├── auth_handler.go           # Login, logout, refresh
│   ├── session_handler.go        # Session management
│   └── password_reset_handler.go # Password reset flow
├── service/
│   ├── auth_service.go           # Authentication interface
│   ├── auth_service_impl.go      # Auth implementation
│   └── password_reset_service.go # Password reset logic
├── strategy/
│   ├── jwt_strategy.go           # JWT-based auth
│   ├── session_strategy.go       # Session-based auth
│   └── factory.go                # Strategy factory
├── repository/
│   ├── session_repository.go     # Session data access
│   └── postgres.go               # PostgreSQL implementation
└── dto/
    └── auth_dto.go               # Auth DTOs
```

## Data Flow

### Request Processing Flow

```
1. HTTP Request
   ↓
2. Router → Handler (Interface Layer)
   ↓
3. DTO Validation & Transformation
   ↓
4. Service Call (Application Layer)
   ↓
5. Business Logic & Domain Rules
   ↓
6. Repository Call (Infrastructure Layer)
   ↓
7. Database Operation
   ↓
8. Response Transformation
   ↓
9. HTTP Response
```

### Authentication Flow Example

```
1. POST /auth/login
   ↓
2. AuthHandler.Login()
   ↓
3. Validate LoginRequest DTO
   ↓
4. AuthService.Login()
   ↓
5. UserRepository.GetByEmail()
   ↓
6. Password verification
   ↓
7. Strategy-based token generation
   ↓
8. Session/JWT creation
   ↓
9. LoginResponse DTO
   ↓
10. HTTP 200 + tokens
```

## Database Architecture

### Multi-Tenant Data Isolation

```sql
-- Tenant-aware tables
CREATE TABLE users (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    email VARCHAR(255) NOT NULL,
    -- ...
    UNIQUE(tenant_id, email)
);

-- Row-level security
CREATE POLICY tenant_isolation ON users
    FOR ALL TO app_user
    USING (tenant_id = current_setting('app.current_tenant')::UUID);
```

### Repository Pattern Implementation

```go
type PostgresUserRepository struct {
    db     *sql.DB
    logger *logger.Logger
}

func (r *PostgresUserRepository) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
    // Tenant-aware query
    query := `
        SELECT id, tenant_id, email, username, password_hash, created_at
        FROM users
        WHERE email = $1 AND tenant_id = $2 AND deleted_at IS NULL
    `

    tenantID := tenant.FromContext(ctx)
    var user domain.User
    err := r.db.QueryRowContext(ctx, query, email, tenantID).Scan(
        &user.ID, &user.TenantID, &user.Email, &user.Username,
        &user.PasswordHash, &user.CreatedAt,
    )

    if err != nil {
        return nil, fmt.Errorf("failed to get user: %w", err)
    }

    return &user, nil
}
```

## Security Architecture

### Authentication Strategies

**JWT Strategy (Stateless)**:

```go
// Self-contained tokens
// No server-side storage
// Horizontal scaling friendly
// Token blacklisting challenging
```

**Session Strategy (Stateful)**:

```go
// Server-side session storage
// Easy token revocation
// Requires sticky sessions
// Database dependency
```

### Authorization Model

**Role-Based Access Control (RBAC)**:

```
User → UserRole → Role → RolePermission → Permission
```

```go
type Permission struct {
    ID          uuid.UUID
    Name        string      // "users:read", "orders:write"
    Resource    string      // "users", "orders"
    Action      string      // "read", "write", "delete"
    Scope       string      // "own", "tenant", "global"
}

type Role struct {
    ID          uuid.UUID
    Name        string      // "admin", "user", "manager"
    Permissions []Permission
}
```

### Multi-Factor Authentication

**TOTP (Time-based One-Time Password)**:

```go
func (s *AuthService) ValidateMFA(ctx context.Context, userID uuid.UUID, code string) (bool, error) {
    user, err := s.userRepo.GetByID(ctx, userID)
    if err != nil {
        return false, err
    }

    // TOTP validation
    valid := totp.Validate(code, user.MFASecret)
    if valid {
        return true, nil
    }

    // Backup code validation
    return s.validateBackupCode(ctx, userID, code)
}
```

## Error Handling Architecture

### Typed Error System

```go
// Domain errors
type DomainError struct {
    Code    string
    Message string
    Cause   error
}

// Application errors
type ValidationError struct {
    Field   string
    Value   interface{}
    Rule    string
    Message string
}

// HTTP error responses
type ErrorResponse struct {
    Error   string            `json:"error"`
    Code    string            `json:"code"`
    Details map[string]string `json:"details,omitempty"`
}
```

### Error Propagation

```go
// Service layer
func (s *UserService) CreateUser(ctx context.Context, req *CreateUserRequest) error {
    if err := s.validateUser(req); err != nil {
        return fmt.Errorf("validation failed: %w", err)
    }

    if err := s.userRepo.Create(ctx, user); err != nil {
        return fmt.Errorf("failed to create user: %w", err)
    }

    return nil
}

// Handler layer
func (h *UserHandler) CreateUser(c echo.Context) error {
    if err := h.userService.CreateUser(ctx, req); err != nil {
        return h.handleError(c, err)
    }

    return c.JSON(http.StatusCreated, response)
}
```

## Performance Considerations

### Connection Pooling

```go
// Database connection pool
type DB struct {
    *sqlx.DB
    maxOpenConns    int
    maxIdleConns    int
    connMaxLifetime time.Duration
}

// Redis connection pool
type Redis struct {
    *redis.Client
    poolSize     int
    minIdleConns int
    maxRetries   int
}
```

### Caching Strategy

```go
// Multi-level caching
type CacheService struct {
    l1Cache *cache.Memory   // In-memory cache
    l2Cache *cache.Redis    // Distributed cache
    db      Repository      // Database fallback
}

func (c *CacheService) GetUser(ctx context.Context, id uuid.UUID) (*User, error) {
    // L1 cache check
    if user := c.l1Cache.Get(id); user != nil {
        return user, nil
    }

    // L2 cache check
    if user := c.l2Cache.Get(ctx, id); user != nil {
        c.l1Cache.Set(id, user)
        return user, nil
    }

    // Database fallback
    user, err := c.db.GetByID(ctx, id)
    if err != nil {
        return nil, err
    }

    // Populate caches
    c.l2Cache.Set(ctx, id, user)
    c.l1Cache.Set(id, user)

    return user, nil
}
```

## Deployment Architecture

### Container Structure

```dockerfile
# Multi-stage build
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o main ./cmd/main.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/main .
CMD ["./main"]
```

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: azth-backend
spec:
  replicas: 3
  selector:
    matchLabels:
      app: azth-backend
  template:
    metadata:
      labels:
        app: azth-backend
    spec:
      containers:
        - name: azth-backend
          image: azth/backend:latest
          ports:
            - containerPort: 8080
          env:
            - name: DATABASE_URL
              valueFrom:
                secretKeyRef:
                  name: db-secret
                  key: url
```

## Monitoring & Observability

### OpenTelemetry Integration

```go
func (s *UserService) CreateUser(ctx context.Context, req *CreateUserRequest) error {
    // Start span
    ctx, span := otel.Tracer("user-service").Start(ctx, "CreateUser")
    defer span.End()

    // Add attributes
    span.SetAttributes(
        attribute.String("user.email", req.Email),
        attribute.String("user.username", req.Username),
    )

    // Business logic...
    if err := s.userRepo.Create(ctx, user); err != nil {
        span.RecordError(err)
        span.SetStatus(codes.Error, "Failed to create user")
        return err
    }

    span.SetStatus(codes.Ok, "User created successfully")
    return nil
}
```

### Metrics Collection

```go
var (
    userCreationCounter = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "users_created_total",
            Help: "Total number of users created",
        },
        []string{"tenant", "status"},
    )

    userCreationDuration = prometheus.NewHistogramVec(
        prometheus.HistogramOpts{
            Name: "user_creation_duration_seconds",
            Help: "Duration of user creation operations",
        },
        []string{"tenant"},
    )
)
```

## Testing Architecture

### Testing Pyramid

```
┌─────────────────────────────────────┐
│              E2E Tests              │ ← Few, High-level
├─────────────────────────────────────┤
│           Integration Tests         │ ← Some, Module-level
├─────────────────────────────────────┤
│             Unit Tests              │ ← Many, Function-level
└─────────────────────────────────────┘
```

### Test Structure

```go
// Unit test
func TestUserService_CreateUser(t *testing.T) {
    // Setup mocks
    mockRepo := &mocks.UserRepository{}
    mockLogger := &mocks.Logger{}

    service := NewUserService(mockRepo, mockLogger)

    // Test cases
    tests := []struct {
        name    string
        req     *CreateUserRequest
        mockFn  func()
        wantErr bool
    }{
        // Test cases...
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            tt.mockFn()
            err := service.CreateUser(context.Background(), tt.req)
            assert.Equal(t, tt.wantErr, err != nil)
        })
    }
}
```

## Conclusion

This architecture provides:

1. **Scalability**: Modular design allows independent scaling
2. **Maintainability**: Clear separation of concerns
3. **Testability**: Interface-driven development enables easy mocking
4. **Security**: Multi-layer security with proper isolation
5. **Performance**: Optimized data access and caching
6. **Observability**: Comprehensive monitoring and logging

The architecture is designed to evolve with business requirements while maintaining code quality and system reliability.
