# Typed Error System

This document explains the new typed error system that replaces string-based error matching.

## Overview

The new system provides type-safe, contextual error handling with rich metadata support.

## Key Components

### 1. Service Error Types (`pkg/response/service_errors.go`)

```go
type ServiceErrorCode string
type ServiceError struct {
    Code    ServiceErrorCode
    Message string
    Details interface{}
}
```

### 2. Error Constructor Functions

```go
func NewAuthInvalidCredentials(details ...interface{}) *ServiceError
func NewUserEmailExists(details ...interface{}) *ServiceError
// ... more constructors
```

### 3. Response Builder Integration

The response builder automatically maps service error codes to HTTP responses:

```go
func (rb *ResponseBuilder) ServiceError(c echo.Context, err error) error {
    var serviceErr *ServiceError
    if errors.As(err, &serviceErr) {
        return rb.handleTypedServiceError(c, serviceErr)
    }
    return rb.handleGenericError(c, err)
}
```

## Usage

### In Services

```go
func (s *AuthService) Login(email, password string) (*LoginResponse, error) {
    if !s.validateCredentials(email, password) {
        return nil, response.NewAuthInvalidCredentials(map[string]interface{}{
            "attempt_count": 3,
            "lockout_time":  300,
        })
    }
    // ... success logic
}
```

### In Handlers

```go
func (h *AuthHandler) Login(c echo.Context) error {
    response, err := h.authService.Login(req.Email, req.Password)
    if err != nil {
        return h.response.ServiceError(c, err) // Automatic type-safe handling
    }
    return h.response.Success(c, AUTH_LOGIN_SUCCESS, response, nil)
}
```

## Benefits

- ✅ Type-safe error handling
- ✅ Rich contextual information
- ✅ No string matching required
- ✅ Better internationalization support
- ✅ Consistent error responses
- ✅ Backward compatibility with fallback handling
