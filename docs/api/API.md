# API Documentation

## Overview

The AZTH Backend provides a RESTful API for user management, authentication, and multi-tenant applications. All endpoints follow REST conventions and return JSON responses.

## Base URL

```
Production: https://api.azth.com/v1
Development: http://localhost:8080/api/v1
```

## Authentication

### Authentication Modes

The API supports two authentication modes:

1. **Session-based** (Stateful): Uses cookies and server-side sessions
2. **JWT-based** (Stateless): Uses JSON Web Tokens

### Headers

```http
# For JWT authentication
Authorization: Bearer <jwt_token>

# For session authentication (automatically handled by cookies)
Cookie: session_id=<session_token>

# Content type for all requests with body
Content-Type: application/json

# Optional: Tenant selection
X-Tenant-ID: <tenant_uuid>
```

## Response Format

### Success Response

```json
{
  "data": {
    // Response data
  },
  "meta": {
    "timestamp": "2024-01-01T00:00:00Z",
    "request_id": "req_123456789"
  }
}
```

### Error Response

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Validation failed",
    "details": {
      "field": "email",
      "rule": "required"
    }
  },
  "meta": {
    "timestamp": "2024-01-01T00:00:00Z",
    "request_id": "req_123456789"
  }
}
```

### Pagination Response

```json
{
  "data": {
    "items": [...],
    "pagination": {
      "page": 1,
      "page_size": 20,
      "total": 100,
      "total_pages": 5,
      "has_next": true,
      "has_prev": false
    }
  }
}
```

## Error Codes

| Code               | Description               |
| ------------------ | ------------------------- |
| `VALIDATION_ERROR` | Request validation failed |
| `UNAUTHORIZED`     | Authentication required   |
| `FORBIDDEN`        | Insufficient permissions  |
| `NOT_FOUND`        | Resource not found        |
| `CONFLICT`         | Resource already exists   |
| `RATE_LIMITED`     | Too many requests         |
| `INTERNAL_ERROR`   | Server error              |
| `MAINTENANCE`      | Service under maintenance |

## Authentication Endpoints

### Login

Authenticate user and create session/JWT.

```http
POST /auth/login
```

**Request:**

```json
{
  "email": "user@example.com",
  "password": "password123",
  "tenant_id": "550e8400-e29b-41d4-a716-446655440000",
  "mfa_code": "123456",
  "remember": true
}
```

**Response (Session Mode):**

```json
{
  "data": {
    "access_token": "sess_abc123...",
    "refresh_token": "refresh_xyz789...",
    "token_type": "Bearer",
    "expires_in": 86400,
    "expires_at": "2024-01-02T00:00:00Z",
    "user": {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "email": "user@example.com",
      "username": "johndoe",
      "first_name": "John",
      "last_name": "Doe",
      "avatar": "https://cdn.example.com/avatar.jpg",
      "email_verified": true,
      "mfa_enabled": true,
      "status": "active",
      "tenant_id": "550e8400-e29b-41d4-a716-446655440000"
    },
    "session": {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "ip_address": "192.168.1.100",
      "user_agent": "Mozilla/5.0...",
      "last_activity": "2024-01-01T00:00:00Z",
      "expires_at": "2024-01-02T00:00:00Z",
      "created_at": "2024-01-01T00:00:00Z"
    },
    "requires_mfa": false
  }
}
```

**Response (JWT Mode):**

```json
{
  "data": {
    "access_token": "eyJhbGciOiJIUzI1NiIs...",
    "refresh_token": "eyJhbGciOiJIUzI1NiIs...",
    "token_type": "Bearer",
    "expires_in": 900,
    "expires_at": "2024-01-01T00:15:00Z",
    "user": {
      /* same as above */
    },
    "requires_mfa": false
  }
}
```

**MFA Required Response:**

```json
{
  "data": {
    "requires_mfa": true,
    "user": {
      /* user info */
    }
  }
}
```

### Logout

End current session or invalidate JWT.

```http
POST /auth/logout
```

**Headers:**

```http
Authorization: Bearer <token>
```

**Request:**

```json
{
  "all": false // If true, logout from all sessions
}
```

**Response:**

```json
{
  "data": {
    "message": "Logged out successfully"
  }
}
```

### Refresh Token

Refresh access token using refresh token.

```http
POST /auth/refresh
```

**Request:**

```json
{
  "refresh_token": "refresh_xyz789..."
}
```

**Response:**

```json
{
  "data": {
    "access_token": "new_token_here...",
    "refresh_token": "new_refresh_token...",
    "token_type": "Bearer",
    "expires_in": 900,
    "expires_at": "2024-01-01T00:15:00Z"
  }
}
```

### Password Reset

#### Request Password Reset

```http
POST /auth/password/reset/request
```

**Request:**

```json
{
  "email": "user@example.com",
  "tenant_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Response:**

```json
{
  "data": {
    "message": "If the email exists, a password reset code has been sent",
    "token_sent": true
  }
}
```

#### Confirm Password Reset

```http
POST /auth/password/reset/confirm
```

**Request:**

```json
{
  "token": "reset_token_123456",
  "new_password": "newpassword123",
  "tenant_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Response:**

```json
{
  "data": {
    "success": true,
    "message": "Password has been reset successfully"
  }
}
```

#### Update Password (Authenticated)

```http
PUT /auth/password/update
```

**Headers:**

```http
Authorization: Bearer <token>
```

**Request:**

```json
{
  "current_password": "oldpassword123",
  "new_password": "newpassword123",
  "mfa_code": "123456"
}
```

**Response:**

```json
{
  "data": {
    "success": true,
    "message": "Password updated successfully",
    "sessions_revoked": false
  }
}
```

## User Management Endpoints

### Get User Profile

```http
GET /users/me
```

**Headers:**

```http
Authorization: Bearer <token>
```

**Response:**

```json
{
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "user@example.com",
    "username": "johndoe",
    "first_name": "John",
    "last_name": "Doe",
    "avatar": "https://cdn.example.com/avatar.jpg",
    "email_verified": true,
    "mfa_enabled": true,
    "status": "active",
    "tenant_id": "550e8400-e29b-41d4-a716-446655440000",
    "roles": ["user", "manager"],
    "permissions": ["users:read", "orders:write"],
    "created_at": "2024-01-01T00:00:00Z",
    "updated_at": "2024-01-01T00:00:00Z"
  }
}
```

### Update User Profile

```http
PUT /users/me
```

**Headers:**

```http
Authorization: Bearer <token>
```

**Request:**

```json
{
  "first_name": "John",
  "last_name": "Doe",
  "username": "johndoe",
  "avatar": "https://cdn.example.com/new-avatar.jpg"
}
```

**Response:**

```json
{
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "user@example.com",
    "username": "johndoe",
    "first_name": "John",
    "last_name": "Doe",
    "avatar": "https://cdn.example.com/new-avatar.jpg",
    "updated_at": "2024-01-01T00:00:00Z"
  }
}
```

### List Users (Admin)

```http
GET /users
```

**Headers:**

```http
Authorization: Bearer <token>
```

**Query Parameters:**

```
page=1
page_size=20
search=john
status=active
role=manager
sort=created_at
order=desc
```

**Response:**

```json
{
  "data": {
    "items": [
      {
        "id": "550e8400-e29b-41d4-a716-446655440000",
        "email": "user@example.com",
        "username": "johndoe",
        "first_name": "John",
        "last_name": "Doe",
        "status": "active",
        "roles": ["user"],
        "created_at": "2024-01-01T00:00:00Z"
      }
    ],
    "pagination": {
      "page": 1,
      "page_size": 20,
      "total": 1,
      "total_pages": 1,
      "has_next": false,
      "has_prev": false
    }
  }
}
```

### Create User (Admin)

```http
POST /users
```

**Headers:**

```http
Authorization: Bearer <token>
```

**Request:**

```json
{
  "email": "newuser@example.com",
  "username": "newuser",
  "first_name": "New",
  "last_name": "User",
  "password": "password123",
  "roles": ["user"],
  "send_welcome_email": true
}
```

**Response:**

```json
{
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440001",
    "email": "newuser@example.com",
    "username": "newuser",
    "first_name": "New",
    "last_name": "User",
    "status": "active",
    "email_verified": false,
    "mfa_enabled": false,
    "created_at": "2024-01-01T00:00:00Z"
  }
}
```

## Multi-Factor Authentication

### Enable MFA

```http
POST /auth/mfa/enable
```

**Headers:**

```http
Authorization: Bearer <token>
```

**Response:**

```json
{
  "data": {
    "secret": "JBSWY3DPEHPK3PXP",
    "qr_code_url": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAA...",
    "backup_codes": ["123456", "789012", "345678", "901234", "567890"]
  }
}
```

### Verify MFA Setup

```http
POST /auth/mfa/verify
```

**Headers:**

```http
Authorization: Bearer <token>
```

**Request:**

```json
{
  "code": "123456"
}
```

**Response:**

```json
{
  "data": {
    "verified": true,
    "enabled": true,
    "message": "MFA has been enabled successfully"
  }
}
```

### Disable MFA

```http
POST /auth/mfa/disable
```

**Headers:**

```http
Authorization: Bearer <token>
```

**Request:**

```json
{
  "password": "current_password",
  "mfa_code": "123456"
}
```

**Response:**

```json
{
  "data": {
    "message": "MFA has been disabled successfully"
  }
}
```

### Generate Backup Codes

```http
POST /auth/mfa/backup-codes
```

**Headers:**

```http
Authorization: Bearer <token>
```

**Request:**

```json
{
  "mfa_code": "123456"
}
```

**Response:**

```json
{
  "data": {
    "backup_codes": [
      "new_code_1",
      "new_code_2",
      "new_code_3",
      "new_code_4",
      "new_code_5"
    ],
    "message": "New backup codes generated. Previous codes are now invalid."
  }
}
```

## Session Management

### List Sessions

```http
GET /auth/sessions
```

**Headers:**

```http
Authorization: Bearer <token>
```

**Response:**

```json
{
  "data": {
    "sessions": [
      {
        "id": "550e8400-e29b-41d4-a716-446655440000",
        "ip_address": "192.168.1.100",
        "user_agent": "Mozilla/5.0...",
        "last_activity": "2024-01-01T00:00:00Z",
        "expires_at": "2024-01-02T00:00:00Z",
        "created_at": "2024-01-01T00:00:00Z",
        "is_current": true
      }
    ],
    "total": 1
  }
}
```

### Revoke Session

```http
DELETE /auth/sessions/{session_id}
```

**Headers:**

```http
Authorization: Bearer <token>
```

**Response:**

```json
{
  "data": {
    "message": "Session revoked successfully"
  }
}
```

### Revoke All Sessions

```http
DELETE /auth/sessions
```

**Headers:**

```http
Authorization: Bearer <token>
```

**Response:**

```json
{
  "data": {
    "message": "All sessions revoked successfully",
    "revoked_count": 3
  }
}
```

## Role & Permission Management

### List Roles

```http
GET /roles
```

**Headers:**

```http
Authorization: Bearer <token>
```

**Query Parameters:**

```
page=1
page_size=20
search=admin
```

**Response:**

```json
{
  "data": {
    "items": [
      {
        "id": "550e8400-e29b-41d4-a716-446655440000",
        "name": "admin",
        "description": "Administrator role",
        "permissions": [
          {
            "id": "550e8400-e29b-41d4-a716-446655440001",
            "name": "users:write",
            "resource": "users",
            "action": "write",
            "scope": "tenant"
          }
        ],
        "created_at": "2024-01-01T00:00:00Z"
      }
    ],
    "pagination": {
      /* ... */
    }
  }
}
```

### Create Role

```http
POST /roles
```

**Headers:**

```http
Authorization: Bearer <token>
```

**Request:**

```json
{
  "name": "manager",
  "description": "Manager role",
  "permissions": ["550e8400-e29b-41d4-a716-446655440001"]
}
```

**Response:**

```json
{
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440002",
    "name": "manager",
    "description": "Manager role",
    "permissions": [
      /* ... */
    ],
    "created_at": "2024-01-01T00:00:00Z"
  }
}
```

### Assign Role to User

```http
POST /users/{user_id}/roles
```

**Headers:**

```http
Authorization: Bearer <token>
```

**Request:**

```json
{
  "role_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Response:**

```json
{
  "data": {
    "message": "Role assigned successfully"
  }
}
```

## Tenant Management

### Get Current Tenant

```http
GET /tenant
```

**Headers:**

```http
Authorization: Bearer <token>
```

**Response:**

```json
{
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "name": "Acme Corp",
    "slug": "acme-corp",
    "domain": "acme.com",
    "status": "active",
    "plan": "enterprise",
    "settings": {
      "branding": {
        "logo": "https://cdn.example.com/logo.png",
        "primary_color": "#007bff"
      }
    },
    "created_at": "2024-01-01T00:00:00Z"
  }
}
```

### Update Tenant Settings

```http
PUT /tenant/settings
```

**Headers:**

```http
Authorization: Bearer <token>
```

**Request:**

```json
{
  "settings": {
    "branding": {
      "logo": "https://cdn.example.com/new-logo.png",
      "primary_color": "#28a745"
    },
    "auth": {
      "require_mfa": true,
      "session_timeout": 3600
    }
  }
}
```

**Response:**

```json
{
  "data": {
    "settings": {
      /* updated settings */
    },
    "updated_at": "2024-01-01T00:00:00Z"
  }
}
```

## OTP & Notifications

### Send OTP

```http
POST /otp/send
```

**Headers:**

```http
Authorization: Bearer <token>
```

**Request:**

```json
{
  "type": "email",
  "purpose": "email_verification",
  "target": "user@example.com"
}
```

**Response:**

```json
{
  "data": {
    "success": true,
    "message": "OTP sent successfully",
    "code_sent": true,
    "expires_in": 300
  }
}
```

### Verify OTP

```http
POST /otp/verify
```

**Headers:**

```http
Authorization: Bearer <token>
```

**Request:**

```json
{
  "code": "123456",
  "type": "email",
  "purpose": "email_verification",
  "target": "user@example.com"
}
```

**Response:**

```json
{
  "data": {
    "valid": true,
    "verified": true,
    "message": "OTP verified successfully",
    "purpose": "email_verification"
  }
}
```

## WebSocket Events

### Authentication Events

```json
// User logged in
{
  "event": "auth.login",
  "data": {
    "user_id": "550e8400-e29b-41d4-a716-446655440000",
    "session_id": "550e8400-e29b-41d4-a716-446655440001",
    "timestamp": "2024-01-01T00:00:00Z"
  }
}

// User logged out
{
  "event": "auth.logout",
  "data": {
    "user_id": "550e8400-e29b-41d4-a716-446655440000",
    "reason": "user_initiated",
    "timestamp": "2024-01-01T00:00:00Z"
  }
}
```

### User Events

```json
// Profile updated
{
  "event": "user.updated",
  "data": {
    "user_id": "550e8400-e29b-41d4-a716-446655440000",
    "changes": ["first_name", "avatar"],
    "timestamp": "2024-01-01T00:00:00Z"
  }
}
```

## Rate Limiting

### Limits

| Endpoint Category | Limit         | Window   |
| ----------------- | ------------- | -------- |
| Authentication    | 10 requests   | 1 minute |
| Password Reset    | 5 requests    | 1 hour   |
| OTP               | 10 requests   | 1 hour   |
| General API       | 1000 requests | 1 hour   |
| Admin API         | 5000 requests | 1 hour   |

### Headers

Rate limit information is included in response headers:

```http
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1704067200
X-RateLimit-Window: 3600
```

### Rate Limit Exceeded

```json
{
  "error": {
    "code": "RATE_LIMITED",
    "message": "Rate limit exceeded",
    "details": {
      "limit": 1000,
      "window": 3600,
      "reset_at": "2024-01-01T01:00:00Z"
    }
  }
}
```

## SDKs and Examples

### cURL Examples

```bash
# Login
curl -X POST https://api.azth.com/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "password123"
  }'

# Get user profile
curl -X GET https://api.azth.com/v1/users/me \
  -H "Authorization: Bearer <token>"

# List users with pagination
curl -X GET "https://api.azth.com/v1/users?page=1&page_size=20" \
  -H "Authorization: Bearer <token>"
```

### JavaScript/TypeScript Example

```typescript
// Using fetch API
const response = await fetch("https://api.azth.com/v1/auth/login", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
  },
  body: JSON.stringify({
    email: "user@example.com",
    password: "password123",
  }),
});

const data = await response.json();

if (response.ok) {
  // Store token
  localStorage.setItem("token", data.data.access_token);
} else {
  console.error("Login failed:", data.error);
}
```

### Go Example

```go
package main

import (
    "bytes"
    "encoding/json"
    "fmt"
    "net/http"
)

type LoginRequest struct {
    Email    string `json:"email"`
    Password string `json:"password"`
}

func login() error {
    req := LoginRequest{
        Email:    "user@example.com",
        Password: "password123",
    }

    jsonData, _ := json.Marshal(req)

    resp, err := http.Post(
        "https://api.azth.com/v1/auth/login",
        "application/json",
        bytes.NewBuffer(jsonData),
    )
    if err != nil {
        return err
    }
    defer resp.Body.Close()

    // Handle response...
    return nil
}
```

## Status Codes

| Code | Description                                           |
| ---- | ----------------------------------------------------- |
| 200  | OK - Request successful                               |
| 201  | Created - Resource created                            |
| 204  | No Content - Request successful, no data              |
| 400  | Bad Request - Invalid request data                    |
| 401  | Unauthorized - Authentication required                |
| 403  | Forbidden - Insufficient permissions                  |
| 404  | Not Found - Resource not found                        |
| 409  | Conflict - Resource already exists                    |
| 422  | Unprocessable Entity - Validation failed              |
| 429  | Too Many Requests - Rate limit exceeded               |
| 500  | Internal Server Error - Server error                  |
| 502  | Bad Gateway - Upstream service error                  |
| 503  | Service Unavailable - Service temporarily unavailable |

## Changelog

### v1.0.0 (2024-01-01)

- Initial API release
- Authentication endpoints
- User management
- Role-based access control
- Multi-factor authentication
- Session management
- Multi-tenant support

---

For more information, see the [Architecture Guide](ARCHITECTURE.md) and [Development Guide](DEVELOPMENT.md).
