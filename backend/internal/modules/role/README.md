# Role and Permission Module

This module implements a comprehensive Role-Based Access Control (RBAC) system for the AZTH SSO application. It provides fine-grained permission management and role-based authorization capabilities.

## Architecture

The module follows Clean Architecture principles with clear separation of concerns:

```
role/
├── dto/           # Data Transfer Objects
├── handlers/      # HTTP handlers
├── repository/    # Data access layer
└── service/       # Business logic layer

permission/
├── dto/           # Data Transfer Objects
├── handlers/      # HTTP handlers
├── repository/    # Data access layer
└── service/       # Business logic layer
```

## Features

### Role Management

- **Hierarchical Roles**: Support for role priorities and inheritance
- **Multi-tenant Roles**: Tenant-specific and global roles
- **System Roles**: Built-in system roles that cannot be modified
- **Default Roles**: Automatically assigned roles for new users
- **Role Validation**: Slug and name uniqueness validation

### Permission Management

- **Granular Permissions**: Module/Resource/Action-based permissions
- **System Permissions**: Built-in permissions for core functionality
- **Default Permissions**: Standard permissions for common operations
- **Permission Validation**: Code and structure validation
- **Bulk Operations**: Efficient bulk creation and management

### User Role Assignment

- **Dynamic Assignment**: Assign/revoke roles to/from users
- **Tenant Context**: Role assignments are tenant-specific
- **Audit Trail**: Track who assigned/revoked roles and when
- **Bulk Operations**: Efficient bulk role assignments

### Access Control

- **RBAC Middleware**: HTTP middleware for route protection
- **Permission Checking**: Utility functions for permission validation
- **Role Checking**: Utility functions for role validation
- **Context-aware**: Tenant and user context-aware authorization

## Domain Models

### Role

```go
type Role struct {
    ID          uuid.UUID  `json:"id"`
    TenantID    *uuid.UUID `json:"tenant_id"`    // NULL for global roles
    Name        string     `json:"name"`
    Slug        string     `json:"slug"`
    Description *string    `json:"description"`
    IsSystem    bool       `json:"is_system"`    // Cannot be modified
    IsGlobal    bool       `json:"is_global"`    // Available to all tenants
    IsDefault   bool       `json:"is_default"`   // Assigned to new users
    Priority    int        `json:"priority"`     // Role hierarchy
    Metadata    JSONMap    `json:"metadata"`
    CreatedAt   time.Time  `json:"created_at"`
    UpdatedAt   time.Time  `json:"updated_at"`
    DeletedAt   *time.Time `json:"deleted_at"`
    CreatedBy   uuid.UUID  `json:"created_by"`
    UpdatedBy   *uuid.UUID `json:"updated_by"`
}
```

### Permission

```go
type Permission struct {
    ID          uuid.UUID  `json:"id"`
    Name        string     `json:"name"`
    Code        string     `json:"code"`         // Unique identifier
    Description *string    `json:"description"`
    Module      string     `json:"module"`       // e.g., "user", "tenant"
    Resource    string     `json:"resource"`     // e.g., "profile", "settings"
    Action      string     `json:"action"`       // e.g., "read", "write", "delete"
    IsSystem    bool       `json:"is_system"`    // Cannot be modified
    IsDefault   bool       `json:"is_default"`   // Standard permission
    Metadata    JSONMap    `json:"metadata"`
    CreatedAt   time.Time  `json:"created_at"`
    UpdatedAt   time.Time  `json:"updated_at"`
    DeletedAt   *time.Time `json:"deleted_at"`
}
```

### UserRole

```go
type UserRole struct {
    ID        uuid.UUID  `json:"id"`
    UserID    uuid.UUID  `json:"user_id"`
    RoleID    uuid.UUID  `json:"role_id"`
    TenantID  uuid.UUID  `json:"tenant_id"`
    CreatedAt time.Time  `json:"created_at"`
    UpdatedAt time.Time  `json:"updated_at"`
    DeletedAt *time.Time `json:"deleted_at"`
    CreatedBy uuid.UUID  `json:"created_by"`
    UpdatedBy *uuid.UUID `json:"updated_by"`
}
```

## API Endpoints

### Role Endpoints

#### Basic CRUD

- `POST /api/v1/roles` - Create a new role
- `GET /api/v1/roles` - List roles with filtering and pagination
- `GET /api/v1/roles/:id` - Get role by ID
- `PUT /api/v1/roles/:id` - Update role
- `DELETE /api/v1/roles/:id` - Delete role
- `GET /api/v1/roles/slug/:slug` - Get role by slug

#### Role Queries

- `GET /api/v1/roles/global` - Get global roles
- `GET /api/v1/roles/system` - Get system roles
- `GET /api/v1/roles/default` - Get default roles
- `GET /api/v1/roles/stats` - Get role statistics
- `GET /api/v1/tenants/:tenant_id/roles` - Get roles for a tenant

#### Permission Management

- `GET /api/v1/roles/:id/permissions` - Get role permissions
- `POST /api/v1/roles/:id/permissions` - Assign permissions to role
- `PUT /api/v1/roles/:id/permissions` - Replace role permissions
- `DELETE /api/v1/roles/:id/permissions` - Revoke permissions from role

#### User Management

- `POST /api/v1/roles/:id/users` - Assign role to user
- `DELETE /api/v1/roles/:id/users` - Revoke role from user
- `GET /api/v1/users/:user_id/roles` - Get user roles
- `GET /api/v1/users/:user_id/permissions` - Get user permissions

#### Bulk Operations

- `POST /api/v1/roles/bulk` - Bulk create roles
- `DELETE /api/v1/roles/bulk` - Bulk delete roles

#### Initialization

- `POST /api/v1/roles/initialize` - Initialize default roles

### Permission Endpoints

#### Basic CRUD

- `POST /api/v1/permissions` - Create a new permission
- `GET /api/v1/permissions` - List permissions with filtering and pagination
- `GET /api/v1/permissions/:id` - Get permission by ID
- `PUT /api/v1/permissions/:id` - Update permission
- `DELETE /api/v1/permissions/:id` - Delete permission

#### Permission Queries

- `GET /api/v1/permissions/code/:code` - Get permission by code
- `GET /api/v1/permissions/default` - Get default permissions
- `GET /api/v1/permissions/system` - Get system permissions
- `GET /api/v1/permissions/modules` - Get permission modules
- `GET /api/v1/permissions/grouped` - Get permissions grouped by module/resource

#### Hierarchical Queries

- `GET /api/v1/permissions/module/:module` - Get permissions by module
- `GET /api/v1/permissions/module/:module/resource/:resource` - Get permissions by resource
- `GET /api/v1/permissions/module/:module/resource/:resource/action/:action` - Get specific permission

#### Validation

- `POST /api/v1/permissions/validate/code` - Validate permission code
- `POST /api/v1/permissions/validate/action` - Validate module/resource/action

#### Bulk Operations

- `POST /api/v1/permissions/bulk` - Bulk create permissions
- `DELETE /api/v1/permissions/bulk` - Bulk delete permissions

#### Initialization

- `POST /api/v1/permissions/initialize` - Initialize default permissions

## Usage Examples

### Creating a Role

```bash
curl -X POST http://localhost:8080/api/v1/roles \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Content Manager",
    "slug": "content-manager",
    "description": "Manages content and articles",
    "is_global": false,
    "is_default": false,
    "priority": 500
  }'
```

### Assigning Permissions to Role

```bash
curl -X POST http://localhost:8080/api/v1/roles/{role_id}/permissions \
  -H "Content-Type: application/json" \
  -d '{
    "permission_ids": [
      "perm-id-1",
      "perm-id-2",
      "perm-id-3"
    ]
  }'
```

### Assigning Role to User

```bash
curl -X POST http://localhost:8080/api/v1/roles/{role_id}/users \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "user-id",
    "tenant_id": "tenant-id"
  }'
```

### Creating a Permission

```bash
curl -X POST http://localhost:8080/api/v1/permissions \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Read User Profile",
    "code": "user.profile.read",
    "description": "Allows reading user profile information",
    "module": "user",
    "resource": "profile",
    "action": "read",
    "is_default": true
  }'
```

## RBAC Middleware Usage

### Protecting Routes with Permissions

```go
// Require specific permission
rbac := middleware.NewRBACMiddleware(roleService, logger)
e.GET("/api/v1/users", userHandler.ListUsers, rbac.RequirePermission("user.list"))

// Require any of multiple permissions
e.GET("/api/v1/admin", adminHandler.Dashboard,
    rbac.RequireAnyPermission("admin.read", "super.admin"))
```

### Protecting Routes with Roles

```go
// Require specific role
e.GET("/api/v1/admin", adminHandler.Dashboard, rbac.RequireRole("admin"))

// Require any of multiple roles
e.GET("/api/v1/management", mgmtHandler.Dashboard,
    rbac.RequireAnyRole("admin", "manager"))

// Require admin role (shorthand)
e.DELETE("/api/v1/users/:id", userHandler.DeleteUser, rbac.RequireAdmin())

// Require super admin role (shorthand)
e.POST("/api/v1/system/reset", systemHandler.Reset, rbac.RequireSuperAdmin())
```

### Permission Checking in Handlers

```go
func (h *UserHandler) GetUser(c echo.Context) error {
    checker := middleware.NewPermissionChecker(h.roleService, h.logger)

    userID := getUserIDFromContext(c)
    tenantID := getTenantIDFromContext(c)

    // Check if user has permission
    hasPermission, err := checker.HasPermission(c.Request().Context(),
        userID, tenantID, "user.profile.read")
    if err != nil {
        return c.JSON(500, map[string]string{"error": "Permission check failed"})
    }

    if !hasPermission {
        return c.JSON(403, map[string]string{"error": "Insufficient permissions"})
    }

    // Continue with handler logic...
}
```

## Default Roles

The system comes with predefined roles:

1. **Super Admin** (`super-admin`)

   - Global role with all permissions
   - Cannot be deleted or modified
   - Highest priority (1000)

2. **Admin** (`admin`)

   - Tenant-specific administrative role
   - High priority (900)
   - Full tenant management permissions

3. **Manager** (`manager`)

   - Tenant-specific management role
   - Medium priority (800)
   - Limited administrative permissions

4. **User** (`user`)

   - Default role for new users
   - Low priority (100)
   - Basic user permissions

5. **Guest** (`guest`)
   - Limited access role
   - Lowest priority (50)
   - Read-only permissions

## Default Permissions

The system includes default permissions for common operations:

- **User Management**: `user.create`, `user.read`, `user.update`, `user.delete`
- **Tenant Management**: `tenant.create`, `tenant.read`, `tenant.update`, `tenant.delete`
- **Role Management**: `role.create`, `role.read`, `role.update`, `role.delete`
- **Permission Management**: `permission.create`, `permission.read`, `permission.update`, `permission.delete`
- **System Operations**: `system.admin`, `system.audit`, `system.config`

## Observability

The module includes comprehensive observability features:

### OpenTelemetry Tracing

- All service methods are traced
- Span attributes include user IDs, role IDs, permission codes
- Error tracking and performance monitoring

### Structured Logging

- All operations are logged with context
- Log levels: DEBUG, INFO, WARN, ERROR
- Correlation IDs for request tracking

### Metrics

- Role assignment/revocation counts
- Permission check latencies
- Error rates and success rates

## Security Considerations

1. **Input Validation**: All inputs are validated and sanitized
2. **SQL Injection Prevention**: Parameterized queries and ORM usage
3. **Authorization**: Multi-layer authorization checks
4. **Audit Trail**: Complete audit trail for all operations
5. **Rate Limiting**: Built-in rate limiting for API endpoints
6. **Secure Defaults**: Secure default configurations

## Testing

The module includes comprehensive tests:

- **Unit Tests**: Service and repository layer tests
- **Integration Tests**: Database integration tests
- **API Tests**: HTTP endpoint tests
- **Performance Tests**: Load and stress tests

Run tests:

```bash
go test ./internal/modules/role/...
go test ./internal/modules/permission/...
```

## Migration and Initialization

### Database Migration

The module requires database tables for roles, permissions, and user roles. Migration scripts are provided in the `migrations/` directory.

### Default Data Initialization

Initialize default roles and permissions:

```bash
curl -X POST http://localhost:8080/api/v1/permissions/initialize
curl -X POST http://localhost:8080/api/v1/roles/initialize
```

## Configuration

The module can be configured through environment variables:

```yaml
rbac:
  default_role_slug: "user"
  max_roles_per_user: 10
  permission_cache_ttl: "5m"
  role_cache_ttl: "10m"
```

## Performance Optimization

1. **Caching**: Redis caching for frequently accessed roles and permissions
2. **Pagination**: Efficient pagination for large datasets
3. **Bulk Operations**: Optimized bulk operations for better performance
4. **Database Indexing**: Proper database indexes for fast queries
5. **Connection Pooling**: Database connection pooling for scalability

## Future Enhancements

1. **Dynamic Permissions**: Runtime permission creation and modification
2. **Role Templates**: Predefined role templates for common use cases
3. **Permission Inheritance**: Hierarchical permission inheritance
4. **Time-based Roles**: Temporary role assignments with expiration
5. **Conditional Permissions**: Context-aware permission evaluation
