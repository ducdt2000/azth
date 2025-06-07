# Authentication Modes Documentation

This document describes the dual authentication system that supports both **stateful (session/cookie)** and **stateless (JWT)** authentication modes with configurable password hashing algorithms.

## Overview

The authentication system supports two modes:

1. **Stateful Mode**: Traditional session-based authentication with server-side session storage
2. **Stateless Mode**: JWT-based authentication with client-side token storage

## Authentication Modes

### 1. Stateful Mode (Session/Cookie Based)

**Configuration:**

```yaml
auth:
  mode: "stateful"
  session:
    ttl: "24h"
    refresh_token_ttl: "720h"
    max_login_attempts: 5
    lockout_duration: "15m"
```

**Features:**

- Server-side session storage in PostgreSQL
- Session tokens stored in database
- Automatic session cleanup of expired sessions
- Session management (view all sessions, revoke individual/all sessions)
- IP address and user agent tracking
- Multi-tenant session isolation

**Pros:**

- Immediate token revocation capability
- Better security (server controls session state)
- Detailed session tracking and management
- Suitable for web applications with server-side rendering

**Cons:**

- Requires database storage for sessions
- Less scalable for distributed systems
- Server state dependency

### 2. Stateless Mode (JWT Based)

**Configuration:**

```yaml
auth:
  mode: "stateless"
  jwt:
    secret: "${JWT_SECRET}"
    access_token_ttl: "15m"
    refresh_token_ttl: "168h"
    issuer: "azth-auth-service"
    audience: "azth-api"
```

**Features:**

- Self-contained JWT tokens
- No server-side session storage required
- Configurable token expiration times
- Standard JWT claims (iss, aud, exp, iat, etc.)
- Custom claims (user_id, tenant_id, email, username)

**Pros:**

- Highly scalable (no server state)
- Perfect for microservices and APIs
- Reduced database load
- Better for mobile applications

**Cons:**

- Cannot revoke tokens before expiration (without blacklist)
- Larger token size
- Token refresh required for long-lived sessions

## Password Hashing Algorithms

### 1. Argon2ID (Recommended)

**Configuration:**

```yaml
auth:
  password:
    algorithm: "argon2id"
    argon2id:
      memory: 65536 # 64MB
      iterations: 3
      parallelism: 2
      salt_length: 16
      key_length: 32
```

**Features:**

- Winner of the Password Hashing Competition (2015)
- Resistant to GPU and ASIC attacks
- Memory-hard function
- Configurable memory usage, iterations, and parallelism

### 2. Bcrypt (Legacy Support)

**Configuration:**

```yaml
auth:
  password:
    algorithm: "bcrypt"
    bcrypt_cost: 12
```

**Features:**

- Well-established algorithm
- Adaptive cost parameter
- Widely supported
- Good for legacy system compatibility

## API Endpoints

### Authentication Endpoints

All endpoints work with both authentication modes:

```
POST   /auth/login           # User login
POST   /auth/logout          # User logout
POST   /auth/refresh         # Token refresh
GET    /auth/sessions        # Get user sessions (stateful mode only)
DELETE /auth/sessions/{id}   # Revoke specific session (stateful mode only)
DELETE /auth/sessions        # Revoke all sessions (stateful mode only)
```

### Login Request/Response

**Request:**

```json
{
  "email": "user@example.com",
  "password": "password123",
  "tenant_id": "uuid",
  "mfa_code": "123456",
  "remember": true
}
```

**Response (Stateful Mode):**

```json
{
  "access_token": "session_token_here",
  "refresh_token": "refresh_token_here",
  "token_type": "Bearer",
  "expires_in": 86400,
  "expires_at": "2024-01-01T12:00:00Z",
  "user": { ... },
  "session": {
    "id": "uuid",
    "ip_address": "192.168.1.1",
    "user_agent": "Mozilla/5.0...",
    "last_activity": "2024-01-01T12:00:00Z",
    "expires_at": "2024-01-01T12:00:00Z",
    "created_at": "2024-01-01T12:00:00Z"
  }
}
```

**Response (Stateless Mode):**

```json
{
  "access_token": "jwt_token_here",
  "refresh_token": "jwt_refresh_token_here",
  "token_type": "Bearer",
  "expires_in": 900,
  "expires_at": "2024-01-01T12:15:00Z",
  "user": { ... }
}
```

## Middleware Usage

### Basic Authentication

```go
// Require authentication
authMiddleware := middleware.NewAuthMiddleware(authService, logger)
protected.Use(authMiddleware.RequireAuth())

// Optional authentication
public.Use(authMiddleware.OptionalAuth())
```

### Context Helpers

```go
// Check authentication mode
if middleware.IsJWTMode(c) {
    claims := middleware.MustGetJWTClaimsFromContext(c)
    // Handle JWT mode
} else {
    session := middleware.MustGetSessionFromContext(c)
    // Handle session mode
}

// Get user information (works in both modes)
userID := middleware.MustGetUserIDFromContext(c)
tenantID := middleware.MustGetTenantIDFromContext(c)
```

## Configuration Examples

### Development Environment (Session-based)

```yaml
auth:
  mode: "stateful"
  session:
    ttl: "8h"
    refresh_token_ttl: "168h"
    max_login_attempts: 3
    lockout_duration: "5m"
  password:
    algorithm: "bcrypt"
    bcrypt_cost: 10
```

### Production Environment (JWT-based)

```yaml
auth:
  mode: "stateless"
  jwt:
    secret: "${JWT_SECRET}"
    access_token_ttl: "15m"
    refresh_token_ttl: "168h"
    issuer: "azth-auth-service"
    audience: "azth-api"
  password:
    algorithm: "argon2id"
    argon2id:
      memory: 131072 # 128MB
      iterations: 4
      parallelism: 4
      salt_length: 16
      key_length: 32
```

### Microservices Environment (JWT-based)

```yaml
auth:
  mode: "stateless"
  jwt:
    secret: "${JWT_SECRET}"
    access_token_ttl: "5m" # Short-lived for security
    refresh_token_ttl: "24h" # Daily refresh
    issuer: "azth-auth-service"
    audience: "azth-microservices"
  password:
    algorithm: "argon2id"
```

## Security Considerations

### Stateful Mode

- Sessions are stored securely in the database
- Automatic cleanup of expired sessions
- Immediate revocation capability
- Session hijacking protection through IP/User-Agent tracking

### Stateless Mode

- Use strong JWT secrets (256-bit minimum)
- Implement short access token lifetimes
- Consider token blacklisting for critical applications
- Rotate JWT secrets regularly

### Password Security

- Use Argon2ID for new applications
- Configure appropriate memory/iteration parameters
- Consider password strength requirements
- Implement account lockout mechanisms

## Migration Between Modes

### From Session to JWT

1. Update configuration to `mode: "stateless"`
2. Configure JWT settings
3. Update client applications to handle JWT tokens
4. Clean up existing sessions (optional)

### From JWT to Session

1. Update configuration to `mode: "stateful"`
2. Ensure session table exists
3. Update client applications to handle session tokens
4. Consider token blacklisting during transition

## Monitoring and Observability

### Metrics to Monitor

- Login success/failure rates
- Token refresh rates
- Session duration statistics
- Password hash timing
- Account lockout events

### Logging

- Authentication attempts (success/failure)
- Token refresh events
- Session creation/revocation
- Password hash operations
- MFA validation events

## Best Practices

1. **Choose the Right Mode:**

   - Use stateful for traditional web applications
   - Use stateless for APIs and microservices

2. **Security:**

   - Always use HTTPS in production
   - Implement proper CORS policies
   - Use secure cookie settings for session mode
   - Implement rate limiting on auth endpoints

3. **Performance:**

   - Monitor password hashing performance
   - Implement session cleanup jobs
   - Use appropriate token lifetimes
   - Consider caching for JWT validation

4. **Scalability:**
   - Use JWT mode for horizontal scaling
   - Implement session replication for stateful mode
   - Consider Redis for session storage in distributed environments

## Troubleshooting

### Common Issues

1. **Token Validation Failures:**

   - Check JWT secret configuration
   - Verify token expiration times
   - Ensure proper token format

2. **Session Issues:**

   - Check database connectivity
   - Verify session table schema
   - Monitor session cleanup jobs

3. **Password Hashing Performance:**
   - Adjust Argon2ID parameters
   - Monitor hash timing
   - Consider bcrypt for lower-end hardware

### Debug Commands

```bash
# Check authentication configuration
curl -H "Authorization: Bearer <token>" /auth/sessions

# Validate JWT token
jwt decode <token>

# Check session in database
SELECT * FROM sessions WHERE token = '<token>';
```
