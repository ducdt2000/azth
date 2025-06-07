# Authentication Module

The authentication module provides comprehensive session-based authentication with multi-factor authentication (MFA) support for the AZTH platform.

## Features

### Core Authentication

- **Session-based Authentication**: Stateful session management with secure token generation
- **Login/Logout**: Standard authentication flows with proper session lifecycle management
- **Token Refresh**: Automatic token refresh mechanism for seamless user experience
- **Multi-tenant Support**: Session isolation per tenant with proper context management

### Security Features

- **Multi-Factor Authentication (MFA)**: TOTP-based MFA with backup codes
- **Account Lockout**: Automatic account locking after failed login attempts
- **Password Security**: bcrypt password hashing with configurable cost
- **Session Security**: Secure session token generation and validation
- **IP Tracking**: Track user sessions by IP address and user agent

### Session Management

- **Active Session Tracking**: View and manage all active user sessions
- **Session Revocation**: Revoke individual sessions or all sessions for a user
- **Session Cleanup**: Automatic cleanup of expired sessions
- **Session Activity**: Track last activity for each session

## Architecture

The module follows Clean Architecture principles with clear separation of concerns:

```
auth/
├── dto/           # Data Transfer Objects
├── handlers/      # HTTP handlers
├── repository/    # Data access layer
└── service/       # Business logic
```

### Components

#### Service Layer (`service/`)

- `AuthService`: Main authentication service interface
- `authService`: Implementation with all authentication logic
- `AuthConfig`: Configuration for authentication parameters

#### Repository Layer (`repository/`)

- `SessionRepository`: Interface for session data access
- `sessionRepository`: PostgreSQL implementation with OpenTelemetry tracing

#### Handler Layer (`handlers/`)

- `AuthHandler`: HTTP handlers for authentication endpoints
- Route registration and middleware integration

#### DTOs (`dto/`)

- Request/response structures for all authentication operations
- Error types and constants for consistent error handling

## API Endpoints

### Public Endpoints (No Authentication Required)

#### POST `/auth/login`

Authenticate user with email and password.

**Request:**

```json
{
  "email": "user@example.com",
  "password": "password123",
  "tenant_id": "optional-tenant-uuid",
  "mfa_code": "123456",
  "remember": false
}
```

**Response:**

```json
{
  "access_token": "session-token",
  "refresh_token": "refresh-token",
  "token_type": "Bearer",
  "expires_in": 86400,
  "expires_at": "2024-01-01T12:00:00Z",
  "user": {
    "id": "user-uuid",
    "email": "user@example.com",
    "username": "username",
    "first_name": "John",
    "last_name": "Doe",
    "mfa_enabled": true,
    "status": "active",
    "tenant_id": "tenant-uuid"
  },
  "session": {
    "id": "session-uuid",
    "ip_address": "192.168.1.1",
    "user_agent": "Mozilla/5.0...",
    "last_activity": "2024-01-01T12:00:00Z",
    "expires_at": "2024-01-02T12:00:00Z",
    "created_at": "2024-01-01T12:00:00Z"
  },
  "requires_mfa": false
}
```

#### POST `/auth/refresh`

Refresh an expired access token.

**Request:**

```json
{
  "refresh_token": "refresh-token"
}
```

#### POST `/auth/logout`

Logout from current session or all sessions.

**Request:**

```json
{
  "all": false
}
```

### Protected Endpoints (Authentication Required)

#### GET `/auth/sessions`

Get all active sessions for the authenticated user.

#### DELETE `/auth/sessions/{id}`

Revoke a specific session by ID.

#### DELETE `/auth/sessions`

Revoke all sessions for the authenticated user.

### MFA Endpoints

#### POST `/auth/mfa/enable`

Enable multi-factor authentication for the user.

**Response:**

```json
{
  "secret": "base32-encoded-secret",
  "qr_code_url": "otpauth://totp/...",
  "backup_codes": ["code1", "code2", "..."]
}
```

#### DELETE `/auth/mfa/disable`

Disable multi-factor authentication.

#### POST `/auth/mfa/validate`

Validate an MFA code.

**Request:**

```json
{
  "user_id": "user-uuid",
  "code": "123456"
}
```

#### POST `/auth/mfa/backup-codes`

Generate new backup codes.

## Configuration

The authentication service can be configured with the following parameters:

```go
type AuthConfig struct {
    SessionTTL       time.Duration // Session lifetime (default: 24h)
    RefreshTokenTTL  time.Duration // Refresh token lifetime (default: 30 days)
    MaxLoginAttempts int           // Max failed attempts before lockout (default: 5)
    LockoutDuration  time.Duration // Account lockout duration (default: 15min)
    JWTSecret        string        // JWT signing secret
    BCryptCost       int           // bcrypt cost factor (default: 12)
}
```

## Middleware

The module provides several middleware functions for protecting routes:

### `RequireAuth()`

Requires valid authentication. Adds session, user_id, and tenant_id to context.

### `OptionalAuth()`

Optionally extracts authentication info without failing if not present.

### `RequireTenant()`

Requires a valid tenant context (use after RequireAuth).

### `RequireRole(roles ...string)`

Requires specific roles (placeholder - needs implementation).

### `RequirePermission(permissions ...string)`

Requires specific permissions (placeholder - needs implementation).

## Usage Examples

### Basic Authentication Flow

```go
// Login
loginReq := &dto.LoginRequest{
    Email:    "user@example.com",
    Password: "password123",
}
response, err := authService.Login(ctx, loginReq)

// Use session token for subsequent requests
session, err := authService.ValidateSession(ctx, response.AccessToken)

// Logout
err = authService.Logout(ctx, response.AccessToken)
```

### MFA Setup

```go
// Enable MFA
mfaResponse, err := authService.EnableMFA(ctx, userID)
// User scans QR code and sets up authenticator app

// Validate MFA during login
valid, err := authService.ValidateMFA(ctx, userID, "123456")
```

### Session Management

```go
// Get all user sessions
sessions, err := authService.GetUserSessions(ctx, userID)

// Revoke specific session
err = authService.RevokeSession(ctx, sessionID, "user_request")

// Logout from all sessions
err = authService.LogoutAll(ctx, userID)
```

## Database Schema

The module requires a `sessions` table with the following structure:

```sql
CREATE TABLE sessions (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    token VARCHAR(255) NOT NULL UNIQUE,
    refresh_token VARCHAR(255) NOT NULL UNIQUE,
    ip_address INET,
    user_agent TEXT,
    last_activity TIMESTAMP WITH TIME ZONE NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at TIMESTAMP WITH TIME ZONE,
    revoked_reason VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL
);
```

## Security Considerations

1. **Token Security**: Session tokens are cryptographically secure random values
2. **Password Hashing**: Uses bcrypt with configurable cost factor
3. **Session Isolation**: Sessions are isolated per tenant
4. **Account Lockout**: Automatic lockout after failed attempts
5. **MFA Support**: TOTP-based MFA with backup codes
6. **Audit Trail**: All authentication events are logged
7. **Session Cleanup**: Expired sessions are automatically cleaned up

## Error Handling

The module provides structured error handling with specific error codes:

- `INVALID_CREDENTIALS`: Invalid email or password
- `ACCOUNT_LOCKED`: Account temporarily locked
- `MFA_REQUIRED`: MFA code required
- `INVALID_MFA`: Invalid MFA code
- `SESSION_EXPIRED`: Session has expired
- `SESSION_NOT_FOUND`: Session not found
- `INVALID_TOKEN`: Invalid token provided

## Observability

The module includes comprehensive observability features:

- **OpenTelemetry Tracing**: All operations are traced
- **Structured Logging**: Detailed logging with context
- **Metrics**: Key authentication metrics (TODO)
- **Health Checks**: Session cleanup and validation (TODO)

## Future Enhancements

- [ ] OAuth2/OIDC integration
- [ ] Social login providers
- [ ] Advanced rate limiting
- [ ] Audit log integration
- [ ] Metrics and monitoring
- [ ] WebAuthn/FIDO2 support
- [ ] Risk-based authentication
