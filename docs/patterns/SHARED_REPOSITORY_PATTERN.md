# Shared Repository Pattern Implementation

## Overview

This document explains how to use the shared `UserRepository` across all modules in the application, following Clean Architecture principles and Go microservices best practices.

## Architecture Benefits

### ✅ **DRY Principle**

- Single source of truth for user data operations
- No duplicate interface definitions
- Consistent behavior across modules

### ✅ **Clean Architecture**

- Clear separation of concerns
- Interface-driven development
- Dependency inversion principle

### ✅ **Maintainability**

- Single place to add new user operations
- Consistent error handling and logging
- Easier testing and mocking

### ✅ **Type Safety**

- Compile-time verification of method signatures
- Consistent parameter types across modules
- IDE autocompletion and refactoring support

## Implementation Structure

```
backend/internal/modules/user/repository/
├── interface.go          # Shared UserRepository interface
└── postgres.go          # PostgreSQL implementation

backend/internal/modules/auth/service/
├── auth_service.go      # Uses shared UserRepository
└── password_reset_service.go  # Uses shared UserRepository

backend/internal/modules/auth/strategy/
├── jwt_strategy.go      # Uses shared UserRepository
└── session_strategy.go  # Uses shared UserRepository
```

## Shared UserRepository Interface

The `UserRepository` interface in `backend/internal/modules/user/repository/interface.go` provides:

### Basic CRUD Operations

```go
Create(ctx context.Context, user *domain.User) error
GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error)
GetByEmail(ctx context.Context, email string) (*domain.User, error)
GetByUsername(ctx context.Context, username string) (*domain.User, error)
Update(ctx context.Context, user *domain.User) error
Delete(ctx context.Context, id uuid.UUID) error
```

### Query Operations

```go
List(ctx context.Context, req *dto.UserListRequest) ([]*domain.User, int, error)
GetByTenantID(ctx context.Context, tenantID uuid.UUID, req *dto.UserListRequest) ([]*domain.User, int, error)
EmailExists(ctx context.Context, email string, excludeUserID *uuid.UUID) (bool, error)
UsernameExists(ctx context.Context, username string, excludeUserID *uuid.UUID) (bool, error)
```

### Authentication & Security

```go
UpdateLastLogin(ctx context.Context, userID uuid.UUID, loginTime time.Time) error
UpdateLoginAttempts(ctx context.Context, userID uuid.UUID, attempts int) error
IncrementLoginAttempts(ctx context.Context, userID uuid.UUID) error
ResetLoginAttempts(ctx context.Context, userID uuid.UUID) error
LockUser(ctx context.Context, userID uuid.UUID, lockedUntil *time.Time) error
```

### Password Operations

```go
HashPassword(password string) (string, error)
VerifyPassword(password, hash string) bool
UpdatePassword(ctx context.Context, userID uuid.UUID, hashedPassword string) error
```

### MFA Operations

```go
UpdateMFASecret(ctx context.Context, userID uuid.UUID, secret string) error
UpdateBackupCodes(ctx context.Context, userID uuid.UUID, codes []string) error
```

### Role & Session Management

```go
GetUserRoles(ctx context.Context, userID uuid.UUID) ([]*domain.UserRole, error)
AssignRole(ctx context.Context, userRole *domain.UserRole) error
RevokeRole(ctx context.Context, userID, roleID uuid.UUID) error
GetUserSessions(ctx context.Context, userID uuid.UUID) ([]*domain.Session, error)
RevokeAllSessions(ctx context.Context, userID uuid.UUID) error
```

## Usage Examples

### 1. Auth Module Usage

```go
package service

import (
    userRepo "github.com/ducdt2000/azth/backend/internal/modules/user/repository"
)

type authService struct {
    userRepo userRepo.UserRepository  // Shared repository
    // ... other dependencies
}

func (s *authService) ValidateCredentials(ctx context.Context, email, password string) (*domain.User, error) {
    // Get user using shared repository
    user, err := s.userRepo.GetByEmail(ctx, email)
    if err != nil {
        return nil, fmt.Errorf("invalid credentials")
    }

    // Verify password using shared repository
    if !s.userRepo.VerifyPassword(password, user.PasswordHash) {
        // Increment failed attempts using shared repository
        s.userRepo.IncrementLoginAttempts(ctx, user.ID)
        return nil, fmt.Errorf("invalid credentials")
    }

    // Reset attempts and update last login using shared repository
    s.userRepo.ResetLoginAttempts(ctx, user.ID)
    s.userRepo.UpdateLastLogin(ctx, user.ID, time.Now())

    return user, nil
}
```

### 2. Notification Module Usage

```go
package service

import (
    userRepo "github.com/ducdt2000/azth/backend/internal/modules/user/repository"
)

type NotificationService struct {
    userRepo userRepo.UserRepository  // Shared repository
    // ... other dependencies
}

func (n *NotificationService) SendWelcomeEmail(ctx context.Context, userID uuid.UUID) error {
    // Get user details using shared repository
    user, err := n.userRepo.GetByID(ctx, userID)
    if err != nil {
        return fmt.Errorf("user not found: %w", err)
    }

    // Send email to user
    return n.emailSender.Send(user.Email, "Welcome!", "Welcome to our platform!")
}

func (n *NotificationService) SendPasswordResetEmail(ctx context.Context, email string, token string) error {
    // Check if user exists using shared repository
    user, err := n.userRepo.GetByEmail(ctx, email)
    if err != nil {
        // Don't reveal if email exists for security
        return nil
    }

    // Send reset email
    return n.emailSender.Send(user.Email, "Password Reset", fmt.Sprintf("Reset token: %s", token))
}
```

### 3. Tenant Module Usage

```go
package service

import (
    userRepo "github.com/ducdt2000/azth/backend/internal/modules/user/repository"
)

type TenantService struct {
    userRepo userRepo.UserRepository  // Shared repository
    // ... other dependencies
}

func (t *TenantService) GetTenantUsers(ctx context.Context, tenantID uuid.UUID) ([]*domain.User, int, error) {
    // Get users by tenant using shared repository
    req := &dto.UserListRequest{
        Page:     1,
        PageSize: 100,
    }
    return t.userRepo.GetByTenantID(ctx, tenantID, req)
}

func (t *TenantService) DeactivateTenantUsers(ctx context.Context, tenantID uuid.UUID) error {
    // Get all tenant users
    users, _, err := t.GetTenantUsers(ctx, tenantID)
    if err != nil {
        return err
    }

    // Deactivate each user
    for _, user := range users {
        user.Status = domain.UserStatusInactive
        if err := t.userRepo.Update(ctx, user); err != nil {
            return fmt.Errorf("failed to deactivate user %s: %w", user.ID, err)
        }
    }

    return nil
}
```

### 4. Audit Module Usage

```go
package service

import (
    userRepo "github.com/ducdt2000/azth/backend/internal/modules/user/repository"
)

type AuditService struct {
    userRepo userRepo.UserRepository  // Shared repository
    // ... other dependencies
}

func (a *AuditService) LogUserAction(ctx context.Context, userID uuid.UUID, action string) error {
    // Get user details for audit log using shared repository
    user, err := a.userRepo.GetByID(ctx, userID)
    if err != nil {
        return fmt.Errorf("user not found for audit: %w", err)
    }

    // Create audit log entry
    auditEntry := &domain.AuditLog{
        UserID:    user.ID,
        UserEmail: user.Email,
        TenantID:  user.TenantID,
        Action:    action,
        Timestamp: time.Now(),
    }

    return a.auditRepo.Create(ctx, auditEntry)
}
```

## Dependency Injection Setup

### Using Uber FX

```go
// backend/internal/fx/service.go
func NewAuthService(
    userRepo userRepo.UserRepository,  // Shared repository injected
    sessionRepo authRepo.SessionRepository,
    logger *logger.Logger,
) authSvc.AuthService {
    config := authSvc.DefaultAuthConfig()
    return authSvc.NewAuthService(userRepo, sessionRepo, logger, config)
}

func NewNotificationService(
    userRepo userRepo.UserRepository,  // Same shared repository injected
    emailSender EmailSender,
    logger *logger.Logger,
) notificationSvc.NotificationService {
    return notificationSvc.NewNotificationService(userRepo, emailSender, logger)
}
```

### Repository Registration

```go
// backend/internal/fx/repository.go
var RepositoryModule = fx.Module("repositories",
    fx.Provide(NewUserRepository),  // Single registration
    // ... other repositories
)

func NewUserRepository(db *db.DB, logger *logger.Logger) userRepo.UserRepository {
    return userRepo.NewPostgresUserRepository(db, logger)
}
```

## Security Features

### Password Hashing

- **Argon2ID** (default): Memory-hard, secure against GPU attacks
- **bcrypt** (legacy): Backward compatibility support
- **Constant-time comparison**: Prevents timing attacks

### Account Security

- **Login attempt tracking**: Automatic increment/reset
- **Account locking**: Configurable lockout duration
- **MFA support**: Secret and backup code management

### Audit Trail

- **Last login tracking**: Timestamp updates
- **Session management**: Active session tracking
- **Role changes**: Assignment/revocation logging

## Testing Strategy

### Unit Tests

```go
func TestAuthService_ValidateCredentials(t *testing.T) {
    // Create mock shared repository
    mockUserRepo := &mocks.UserRepository{}

    // Setup expectations
    mockUserRepo.On("GetByEmail", mock.Anything, "test@example.com").
        Return(&domain.User{...}, nil)
    mockUserRepo.On("VerifyPassword", "password", "hash").
        Return(true)
    mockUserRepo.On("ResetLoginAttempts", mock.Anything, mock.Anything).
        Return(nil)

    // Test the service
    authSvc := NewAuthService(mockUserRepo, ...)
    user, err := authSvc.ValidateCredentials(ctx, "test@example.com", "password")

    assert.NoError(t, err)
    assert.NotNil(t, user)
    mockUserRepo.AssertExpectations(t)
}
```

### Integration Tests

```go
func TestUserRepository_Integration(t *testing.T) {
    // Test with real database
    db := setupTestDB(t)
    userRepo := NewPostgresUserRepository(db, logger)

    // Test password operations
    hash, err := userRepo.HashPassword("password123")
    assert.NoError(t, err)

    valid := userRepo.VerifyPassword("password123", hash)
    assert.True(t, valid)

    invalid := userRepo.VerifyPassword("wrongpassword", hash)
    assert.False(t, invalid)
}
```

## Migration Guide

### From Duplicate Interfaces

1. **Remove duplicate interfaces** from individual modules
2. **Update imports** to use shared repository
3. **Update constructors** to accept shared interface
4. **Update dependency injection** configuration
5. **Run tests** to ensure compatibility

### Example Migration

**Before:**

```go
// auth/service/auth_service.go
type UserRepository interface {
    GetByEmail(ctx context.Context, email string) (*domain.User, error)
    // ... limited methods
}
```

**After:**

```go
// auth/service/auth_service.go
import userRepo "github.com/ducdt2000/azth/backend/internal/modules/user/repository"

type authService struct {
    userRepo userRepo.UserRepository  // Full shared interface
}
```

## Best Practices

### ✅ **Do's**

- Always use the shared `UserRepository` interface
- Import with alias: `userRepo "github.com/.../user/repository"`
- Add new methods to shared interface when needed
- Use dependency injection for repository instances
- Write tests with mocked shared interface

### ❌ **Don'ts**

- Don't create duplicate user repository interfaces
- Don't bypass the repository for direct database access
- Don't add module-specific methods to shared interface
- Don't create tight coupling between modules
- Don't forget to update all modules when interface changes

## Performance Considerations

### Connection Pooling

- Single database connection pool shared across modules
- Efficient resource utilization
- Consistent connection management

### Caching Strategy

- Repository-level caching for frequently accessed users
- Cache invalidation on user updates
- Consistent cache behavior across modules

### Query Optimization

- Optimized queries in shared implementation
- Proper indexing for common access patterns
- Batch operations for bulk updates

## Conclusion

The shared `UserRepository` pattern provides:

1. **Consistency** across all modules
2. **Maintainability** through single source of truth
3. **Type safety** with compile-time verification
4. **Testability** with easy mocking
5. **Performance** through optimized shared implementation

This pattern follows Clean Architecture principles and Go microservices best practices, making the codebase more maintainable and scalable.
