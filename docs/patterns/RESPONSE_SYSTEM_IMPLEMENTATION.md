# Normalized Response System Implementation

## Overview

This document describes the implementation of a comprehensive normalized response system for the Go microservices project. The system provides standardized API responses with specific error codes and multilanguage support using TOML files.

## What Was Implemented

### 1. Core Response System (`pkg/response/`)

#### Files Created:

- `response.go` - Main response builder with standardized response structure
- `codes.go` - Comprehensive set of response codes for all scenarios
- `i18n.go` - Internationalization manager for multilanguage support
- `time.go` - Time utilities for consistent timestamp handling
- `provider.go` - Dependency injection integration with uber/fx
- `middleware.go` - Echo middleware for request ID, language detection, and response builder injection
- `helpers.go` - Helper functions for common response patterns and error mapping
- `README.md` - Comprehensive documentation and usage examples

#### Language Files:

- `locales/en.toml` - English language messages
- `locales/es.toml` - Spanish language messages (example)

#### Example Implementation:

- `examples/response_integration_example.go` - Complete integration example
- `internal/modules/user/handlers/user_updated.go` - Updated user handler demonstrating new system

## Key Features

### 1. Standardized Response Format

All API responses follow this consistent structure:

```json
{
  "success": true,
  "code": "USER_CREATED",
  "message": "User created successfully",
  "data": {...},
  "error": {...},
  "meta": {
    "request_id": "req-1234567890abcdef",
    "version": "v1",
    "pagination": {...}
  },
  "timestamp": 1640995200
}
```

### 2. Comprehensive Error Codes

Over 100 predefined response codes covering:

- **User operations**: `USER_CREATED`, `USER_NOT_FOUND`, `USER_EMAIL_EXISTS`, etc.
- **Authentication**: `AUTH_LOGIN_SUCCESS`, `AUTH_TOKEN_EXPIRED`, `AUTH_MFA_REQUIRED`, etc.
- **Tenant management**: `TENANT_CREATED`, `TENANT_QUOTA_EXCEEDED`, etc.
- **Role & Permission**: `ROLE_ASSIGNED`, `PERMISSION_INSUFFICIENT`, etc.
- **System errors**: `DATABASE_ERROR`, `SYSTEM_UNAVAILABLE`, etc.
- **Validation**: `VALIDATION_ERROR`, `VALIDATION_FIELD_REQUIRED`, etc.

### 3. Multilanguage Support

- **TOML-based translations**: Easy to manage and extend
- **Automatic language detection**: From headers, query params, or defaults
- **Fallback mechanism**: Falls back to default language if translation missing
- **Runtime language switching**: No server restart required

### 4. Request Tracking

- **Automatic request ID generation**: Unique identifier for each request
- **Request ID propagation**: Available throughout the request lifecycle
- **Response headers**: Request ID included in response headers

### 5. Service Error Mapping

Automatic mapping of service layer errors to appropriate HTTP responses:

```go
// Service layer error
return errors.New("user not found")

// Automatically mapped to
{
  "success": false,
  "code": "USER_NOT_FOUND",
  "message": "User not found",
  "error": {...}
}
```

## Integration Guide

### 1. Add to Dependency Injection

```go
import "github.com/ducdt2000/azth/backend/pkg/response"

fx.New(
    // Add response module
    response.Module,

    // Your existing modules...
)
```

### 2. Update Handlers

**Before:**

```go
func (h *UserHandler) CreateUser(c echo.Context) error {
    // ... business logic

    return c.JSON(http.StatusCreated, dto.APIResponse{
        Success: true,
        Message: "User created successfully",
        Data:    user,
    })
}
```

**After:**

```go
func (h *UserHandler) CreateUser(c echo.Context) error {
    // ... business logic

    location := "/api/v1/users/" + user.ID.String()
    return h.response.CreatedWithLocation(c, response.USER_CREATED, user, location)
}
```

### 3. Add Middleware

```go
func setupMiddleware(e *echo.Echo, rb *response.ResponseBuilder, i18n *response.I18nManager) {
    supportedLangs := i18n.GetAvailableLanguages()
    e.Use(response.CombinedMiddleware(rb, "en", supportedLangs))
}
```

## Benefits

### 1. Consistency

- All API responses follow the same structure
- Consistent error handling across all endpoints
- Standardized status codes and messages

### 2. Internationalization

- Easy to add new languages
- Automatic language detection
- Consistent translations across the application

### 3. Developer Experience

- Type-safe response codes
- Helper methods for common patterns
- Automatic error mapping
- Comprehensive documentation

### 4. Observability

- Request ID tracking for debugging
- Consistent error reporting
- Structured response format for monitoring

### 5. Maintainability

- Centralized response handling
- Easy to modify response format
- Separation of concerns
- Testable components

## Usage Examples

### Success Responses

```go
// Simple success
return rb.Success(c, response.USER_RETRIEVED, user)

// Success with metadata
meta := rb.WithRequestID(requestID)
return rb.Success(c, response.USER_RETRIEVED, user, meta)

// Success with pagination
pagination := response.NewPaginationMeta(page, limit, total)
return rb.SuccessWithPagination(c, response.USERS_LISTED, users, pagination)

// Created with location
location := "/api/v1/users/" + user.ID.String()
return rb.CreatedWithLocation(c, response.USER_CREATED, user, location)
```

### Error Responses

```go
// Validation error
return rb.ValidationError(c, map[string]interface{}{
    "field": "email",
    "error": "Invalid email format",
})

// Service error mapping
return rb.UserServiceError(c, err)

// Specific error codes
return rb.NotFound(c, response.USER_NOT_FOUND, nil)
return rb.Unauthorized(c, response.AUTH_TOKEN_EXPIRED, nil)
return rb.Conflict(c, response.USER_EMAIL_EXISTS, nil)
```

### Language Detection

```go
// Automatic detection from:
// 1. Query param: ?lang=es
// 2. Header: X-Language: es
// 3. Accept-Language: es-ES,es;q=0.9
// 4. Default: en

lang := response.GetLanguage(c)
```

## Testing

The system includes utilities for testing:

```go
// Mock time for consistent testing
response.SetTimeProvider(func() time.Time { return fixedTime })
defer response.ResetTimeProvider()

// Test response structure
var resp response.Response
json.Unmarshal(rec.Body.Bytes(), &resp)
assert.True(t, resp.Success)
assert.Equal(t, "USER_CREATED", resp.Code)
```

## Migration Strategy

### Phase 1: Parallel Implementation

- Keep existing response system
- Implement new system in parallel
- Update new endpoints to use new system

### Phase 2: Gradual Migration

- Update existing handlers one by one
- Test thoroughly at each step
- Monitor for any issues

### Phase 3: Complete Migration

- Remove old response system
- Update all documentation
- Train team on new system

## Performance Considerations

- **Language files**: Loaded once at startup, cached in memory
- **Request ID generation**: Uses crypto/rand for security
- **Context values**: Minimal overhead for metadata storage
- **Error mapping**: Optimized string matching

## Future Enhancements

### Potential Improvements:

1. **Response caching**: Cache frequently used responses
2. **Metrics integration**: Automatic metrics collection
3. **Response compression**: Automatic compression for large responses
4. **Custom serializers**: Support for different response formats
5. **Response validation**: Validate response structure in development

### Additional Languages:

- French (`fr.toml`)
- German (`de.toml`)
- Japanese (`ja.toml`)
- Chinese (`zh.toml`)

## Conclusion

The normalized response system provides a robust, scalable, and maintainable foundation for API responses in the Go microservices project. It ensures consistency, improves developer experience, and provides excellent support for internationalization and observability.

The system is designed to be:

- **Easy to adopt**: Minimal changes required to existing code
- **Flexible**: Supports various response patterns and use cases
- **Extensible**: Easy to add new languages, codes, and features
- **Testable**: Comprehensive testing utilities included
- **Observable**: Built-in request tracking and error reporting

This implementation follows Go best practices and integrates seamlessly with the existing Echo and uber/fx architecture.
