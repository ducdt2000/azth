# Enhanced Authorization Middleware

This package provides a comprehensive authorization middleware system with role-based permissions, session/JWT token management, and KV store caching for optimal performance.

## Features

- **Dual Authentication Modes**: Supports both JWT and session-based authentication
- **Role-Based Access Control (RBAC)**: Fine-grained permission system based on user roles
- **KV Store Integration**: Redis/local KV store for session management and performance caching
- **Permission Caching**: Automatic caching of user roles and permissions for improved performance
- **JWT Blacklisting**: Support for JWT token revocation using KV store
- **Refresh Token Management**: Secure refresh token storage and validation
- **Tenant Isolation**: Multi-tenant support with tenant-specific access control
- **Wildcard Permissions**: Support for wildcard permissions (e.g., `user:*`)

## Architecture

### Core Components

1. **EnhancedAuthMiddleware**: Main authentication and authorization middleware
2. **AuthHelpers**: Utility functions for common authorization patterns
3. **RBACMiddleware**: Role-based access control middleware
4. **AuthorizationMiddleware**: Advanced authorization with resource ownership

### Authentication Flow

```
Request → Extract Token → Validate Token → Check KV Cache → Enhance Context → Apply Authorization Rules
```

### Session/JWT Management with KV Store

#### Session Mode

- Session tokens stored in database
- Session data cached in KV store for performance
- Automatic cache invalidation on logout/revocation

#### JWT Mode

- JWT tokens validated cryptographically
- Blacklisted JWTs stored in KV store
- Refresh tokens stored in KV store with TTL

## Usage Examples

### Basic Authentication

```go
// Require authentication for all routes in group
users := v1.Group("/users")
users.Use(enhancedAuth.RequireAuth())

// Optional authentication
public := v1.Group("/public")
public.Use(enhancedAuth.OptionalAuth())
```

### Role-Based Authorization

```go
// Require specific role
admin := v1.Group("/admin")
admin.Use(enhancedAuth.RequireRole("admin"))

// Require any of multiple roles
moderator := v1.Group("/moderate")
moderator.Use(enhancedAuth.RequireRole("admin", "moderator"))

// Require ALL specified roles
superUser := v1.Group("/super")
superUser.Use(enhancedAuth.RequireAllRoles("admin", "super_user"))
```

### Permission-Based Authorization

```go
// Require specific permission
users.POST("", createUserHandler, enhancedAuth.RequirePermission("user:create"))

// Require any of multiple permissions
users.GET("", listUsersHandler, enhancedAuth.RequirePermission("user:read", "user:list"))

// Require ALL specified permissions
users.POST("/bulk", bulkCreateHandler, enhancedAuth.RequireAllPermissions("user:create", "user:bulk"))
```

### Advanced Configuration

```go
// Custom authorization configuration
config := middleware.AuthConfig{
    Required:            true,
    RequiredRoles:       []string{"admin", "moderator"},
    RequiredPermissions: []string{"user:read"},
    TenantIDParam:       "tenant_id",
    CacheEnabled:        true,
    RequireAll:          false, // OR logic for roles/permissions
}

users.GET("/:id", getUserHandler, enhancedAuth.AuthWithConfig(config))
```

### Tenant-Specific Access Control

```go
// Ensure user can only access their tenant's data
tenants.GET("/:tenant_id/users", listTenantUsers,
    enhancedAuth.RequireAuth(),
    enhancedAuth.RequireTenantAccess("tenant_id"),
    enhancedAuth.RequirePermission("user:read"))
```

### Using Auth Helpers in Handlers

```go
func getUserHandler(c echo.Context) error {
    // Get authenticated user info
    userID, err := middleware.GetUserID(c)
    if err != nil {
        return echo.NewHTTPError(http.StatusUnauthorized, "User not authenticated")
    }

    tenantID, _ := middleware.GetTenantID(c)

    // Check permissions programmatically
    if !middleware.HasPermission(c, "user:read") {
        return echo.NewHTTPError(http.StatusForbidden, "Insufficient permissions")
    }

    // Check if user can access target user
    targetUserID := c.Param("id")
    if !middleware.CanAccessUser(c, uuid.MustParse(targetUserID)) {
        return echo.NewHTTPError(http.StatusForbidden, "Cannot access this user")
    }

    // Business logic here...
    return c.JSON(200, user)
}
```

### Cache Management

```go
// Invalidate user cache when roles/permissions change
func updateUserRoles(c echo.Context) error {
    userID := uuid.MustParse(c.Param("id"))
    tenantID, _ := middleware.GetTenantID(c)

    // Update roles in database...

    // Invalidate cache
    if err := authHelpers.InvalidateUserCacheByID(c.Request().Context(), userID, tenantID); err != nil {
        logger.Warn("Failed to invalidate user cache", "error", err)
    }

    return c.JSON(200, "Roles updated")
}
```

### JWT Blacklisting

```go
func revokeToken(c echo.Context) error {
    token := extractTokenFromHeader(c)

    // Extract JTI from JWT
    jti, err := utils.ExtractJTIFromJWT(token)
    if err != nil {
        return echo.NewHTTPError(http.StatusBadRequest, "Invalid token")
    }

    // Add to blacklist
    ttl := 24 * time.Hour // Should match token expiry
    if err := enhancedAuth.BlacklistJWT(c.Request().Context(), jti, ttl); err != nil {
        return echo.NewHTTPError(http.StatusInternalServerError, "Failed to revoke token")
    }

    return c.JSON(200, "Token revoked")
}
```

### Refresh Token Management

```go
func refreshToken(c echo.Context) error {
    var req RefreshTokenRequest
    if err := c.Bind(&req); err != nil {
        return echo.NewHTTPError(http.StatusBadRequest, "Invalid request")
    }

    // Validate refresh token
    userID, err := enhancedAuth.ValidateRefreshToken(c.Request().Context(), req.RefreshToken)
    if err != nil {
        return echo.NewHTTPError(http.StatusUnauthorized, "Invalid refresh token")
    }

    // Generate new tokens...

    // Store new refresh token
    newRefreshTTL := 7 * 24 * time.Hour
    if err := enhancedAuth.StoreRefreshToken(c.Request().Context(), newRefreshToken, userID, newRefreshTTL); err != nil {
        return echo.NewHTTPError(http.StatusInternalServerError, "Failed to store refresh token")
    }

    // Revoke old refresh token
    enhancedAuth.RevokeRefreshToken(c.Request().Context(), req.RefreshToken)

    return c.JSON(200, response)
}
```

## Permission System

### Permission Format

Permissions follow the format: `module:resource:action` or `module:action`

Examples:

- `user:create` - Create users
- `user:read` - Read user data
- `user:update` - Update user data
- `user:delete` - Delete users
- `user:*` - All user permissions (wildcard)
- `tenant:admin` - Tenant administration
- `role:assign` - Assign roles to users

### Predefined Permissions

The system includes predefined permission constants:

```go
// User permissions
middleware.PermUserCreate       // "user:create"
middleware.PermUserRead         // "user:read"
middleware.PermUserUpdate       // "user:update"
middleware.PermUserDelete       // "user:delete"
middleware.PermUserAll          // "user:*"

// Role permissions
middleware.PermRoleCreate       // "role:create"
middleware.PermRoleRead         // "role:read"
// ... etc
```

### Wildcard Permissions

Wildcard permissions allow granting broad access:

- `user:*` - All user-related permissions
- `admin:*` - All admin permissions
- `*` - All permissions (super admin)

## Role System

### Predefined Roles

```go
middleware.RoleSuperAdmin   // "super_admin" - Full system access
middleware.RoleAdmin        // "admin" - Administrative access
middleware.RoleTenantAdmin  // "tenant_admin" - Tenant-level admin
middleware.RoleUser         // "user" - Standard user
middleware.RoleModerator    // "moderator" - Content moderation
middleware.RoleViewer       // "viewer" - Read-only access
```

### Role Hierarchy

1. **super_admin** - Full system access, can manage all tenants
2. **admin** - Administrative access within tenant
3. **tenant_admin** - Tenant-specific administrative access
4. **moderator** - Content moderation capabilities
5. **user** - Standard user access
6. **viewer** - Read-only access

## Performance Considerations

### Caching Strategy

1. **User Permissions Cache**: 5-minute TTL
2. **User Roles Cache**: 5-minute TTL
3. **Session Data Cache**: 30-minute TTL
4. **JWT Blacklist**: 24-hour TTL (matches token expiry)

### Cache Keys

- User permissions: `user:permissions:{user_id}:{tenant_id}`
- User roles: `user:roles:{user_id}:{tenant_id}`
- Session data: `session:data:{session_token}`
- JWT blacklist: `jwt:blacklist:{jti}`
- Refresh tokens: `refresh:token:{refresh_token}`

### Cache Invalidation

Cache is automatically invalidated when:

- User roles are modified
- User permissions change
- User logs out
- Session is revoked
- JWT is blacklisted

## Security Best Practices

1. **Token Security**

   - Use secure, random tokens for sessions
   - Implement proper JWT signing and validation
   - Store refresh tokens securely in KV store

2. **Permission Granularity**

   - Use specific permissions rather than broad wildcards
   - Implement least-privilege principle
   - Regular permission audits

3. **Session Management**

   - Implement session limits per user
   - Automatic session cleanup
   - IP and user agent validation

4. **Cache Security**
   - Secure KV store access
   - Proper cache key namespacing
   - Regular cache cleanup

## Configuration

### Environment Variables

```bash
# Authentication mode
AUTH_MODE=jwt|session

# JWT Configuration
JWT_SECRET=your-secret-key
JWT_ACCESS_TOKEN_TTL=15m
JWT_REFRESH_TOKEN_TTL=7d

# Session Configuration
SESSION_TTL=24h
SESSION_REFRESH_TTL=7d
MAX_SESSIONS_PER_USER=5

# KV Store Configuration
KV_STORE_TYPE=redis|local
REDIS_URL=redis://localhost:6379
```

### Dependency Injection

The middleware is automatically configured through the FX dependency injection system:

```go
// In your main application
fx.New(
    fx.Provide(/* your dependencies */),
    MiddlewareModule, // Provides all middleware
    // ... other modules
)
```

## Error Handling

The middleware returns appropriate HTTP status codes:

- `401 Unauthorized` - Authentication required or invalid token
- `403 Forbidden` - Insufficient permissions or role access denied
- `500 Internal Server Error` - System errors (cache failures, etc.)

## Monitoring and Observability

The middleware includes OpenTelemetry tracing for:

- Authentication attempts
- Permission checks
- Cache operations
- Token validation

Metrics are available for:

- Authentication success/failure rates
- Cache hit/miss ratios
- Permission check latency
- Token validation performance

## Migration Guide

### From Basic Auth Middleware

1. Replace `authMiddleware.RequireAuth()` with `enhancedAuth.RequireAuth()`
2. Add role/permission requirements as needed
3. Update handlers to use new auth helper functions
4. Configure KV store for caching

### Adding Permissions to Existing Routes

1. Identify required permissions for each endpoint
2. Add permission middleware to routes
3. Update user roles in database
4. Test access control thoroughly

## Troubleshooting

### Common Issues

1. **Cache Misses**: Check KV store connectivity and configuration
2. **Permission Denied**: Verify user has required roles/permissions
3. **Token Validation Failures**: Check JWT secret and token format
4. **Session Issues**: Verify session storage and TTL configuration

### Debug Mode

Enable debug logging to trace middleware execution:

```go
logger.SetLevel("debug")
```

This will log:

- Authentication attempts
- Permission checks
- Cache operations
- Token validation steps
