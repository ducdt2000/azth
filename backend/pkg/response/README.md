# Normalized Response System

This package provides a standardized response system for the Go microservices project with specific error codes and multilanguage support using TOML files.

## Features

- **Standardized Response Format**: Consistent JSON response structure across all endpoints
- **Specific Error Codes**: Predefined error codes for different scenarios
- **Multilanguage Support**: Internationalization using TOML files
- **Request ID Tracking**: Automatic request ID generation and tracking
- **Language Detection**: Automatic language detection from headers and query parameters
- **Pagination Support**: Built-in pagination metadata handling
- **Service Error Mapping**: Automatic mapping of service errors to appropriate HTTP responses

## Response Structure

All API responses follow this standardized structure:

```json
{
  "success": true,
  "code": "USER_CREATED",
  "message": "User created successfully",
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "john@example.com"
  },
  "error": null,
  "meta": {
    "request_id": "req-1234567890abcdef",
    "version": "v1",
    "pagination": {
      "page": 1,
      "limit": 20,
      "total": 100,
      "total_pages": 5
    }
  },
  "timestamp": 1640995200
}
```

## Quick Start

### 1. Setup Dependencies

Add the response system to your dependency injection:

```go
package main

import (
    "github.com/ducdt2000/azth/backend/pkg/response"
    "go.uber.org/fx"
)

func main() {
    fx.New(
        // Add the response module
        response.Module,

        // Your other modules...
        fx.Invoke(startServer),
    ).Run()
}
```

### 2. Configure Language Files

Create TOML files in the `locales` directory:

**locales/en.toml**

```toml
[messages]
USER_CREATED = "User created successfully"
USER_NOT_FOUND = "User not found"
VALIDATION_ERROR = "Validation error"
```

**locales/es.toml**

```toml
[messages]
USER_CREATED = "Usuario creado exitosamente"
USER_NOT_FOUND = "Usuario no encontrado"
VALIDATION_ERROR = "Error de validación"
```

### 3. Use in Handlers

```go
package handlers

import (
    "github.com/ducdt2000/azth/backend/pkg/response"
    "github.com/labstack/echo/v4"
)

type UserHandler struct {
    response *response.ResponseBuilder
}

func NewUserHandler(rb *response.ResponseBuilder) *UserHandler {
    return &UserHandler{response: rb}
}

func (h *UserHandler) CreateUser(c echo.Context) error {
    // Validation error
    if err := validateRequest(req); err != nil {
        return h.response.ValidationError(c, map[string]interface{}{
            "field": "email",
            "error": err.Error(),
        })
    }

    // Success response
    user, err := h.userService.CreateUser(ctx, req)
    if err != nil {
        return h.response.UserServiceError(c, err)
    }

    location := "/api/v1/users/" + user.ID.String()
    return h.response.CreatedWithLocation(c, response.USER_CREATED, user, location)
}

func (h *UserHandler) GetUser(c echo.Context) error {
    user, err := h.userService.GetUser(ctx, userID)
    if err != nil {
        return h.response.UserServiceError(c, err)
    }

    // Add metadata
    requestID := response.GetRequestID(c)
    meta := h.response.WithRequestID(requestID)

    return h.response.Success(c, response.USER_RETRIEVED, user, meta)
}

func (h *UserHandler) ListUsers(c echo.Context) error {
    users, err := h.userService.ListUsers(ctx, req)
    if err != nil {
        return h.response.UserServiceError(c, err)
    }

    // With pagination
    pagination := response.NewPaginationMeta(page, limit, total)
    return h.response.SuccessWithPagination(c, response.USERS_LISTED, users, pagination)
}
```

## Middleware Setup

Add the response middleware to your Echo server:

```go
func setupMiddleware(e *echo.Echo, rb *response.ResponseBuilder) {
    // Combined middleware for request ID, language detection, and response builder
    supportedLangs := []string{"en", "es", "fr", "de"}
    e.Use(response.CombinedMiddleware(rb, "en", supportedLangs))

    // Or use individual middleware
    e.Use(response.RequestIDMiddleware())
    e.Use(response.LanguageMiddleware("en", supportedLangs))
    e.Use(response.ResponseBuilderMiddleware(rb))
}
```

## Language Detection

The system detects user language preference in this order:

1. **Query Parameter**: `?lang=es`
2. **Custom Header**: `X-Language: es`
3. **Accept-Language Header**: `Accept-Language: es-ES,es;q=0.9,en;q=0.8`
4. **Default Language**: Falls back to configured default (usually "en")

## Response Codes

### Success Codes

- `SUCCESS` - General success
- `CREATED` - Resource created
- `USER_CREATED` - User created successfully
- `USER_UPDATED` - User updated successfully
- `USER_RETRIEVED` - User retrieved successfully

### Error Codes

- `USER_NOT_FOUND` - User not found
- `USER_EMAIL_EXISTS` - Email already in use
- `VALIDATION_ERROR` - Validation failed
- `UNAUTHORIZED` - Authentication required
- `FORBIDDEN` - Access denied

[See complete list in codes.go](./codes.go)

## Helper Methods

### Response Builder Methods

```go
// Success responses
rb.Success(c, response.USER_RETRIEVED, user)
rb.Created(c, response.USER_CREATED, user)
rb.SuccessWithPagination(c, response.USERS_LISTED, users, pagination)

// Error responses
rb.BadRequest(c, response.VALIDATION_ERROR, details)
rb.NotFound(c, response.USER_NOT_FOUND, nil)
rb.Unauthorized(c, response.AUTH_TOKEN_EXPIRED, nil)
rb.InternalServerError(c, response.SYSTEM_ERROR, nil)

// Service error mapping
rb.UserServiceError(c, err)
rb.AuthServiceError(c, err)
rb.TenantServiceError(c, err)
```

### Metadata Helpers

```go
// Add request ID
meta := rb.WithRequestID(requestID)

// Add pagination
meta := rb.WithPagination(pagination)

// Add multiple metadata
meta := rb.WithMeta(requestID, "v1", pagination)
```

### Context Helpers

```go
// Get values from context
requestID := response.GetRequestID(c)
language := response.GetLanguage(c)
responseBuilder := response.GetResponseBuilder(c)
```

## Configuration

### Custom Configuration

```go
config := response.NewResponseConfig().
    WithCustomLanguagesDir("./custom-locales").
    WithDefaultLanguage("es")

app := fx.New(
    fx.Supply(config),
    response.ProviderWithConfig(config),
    // ... other modules
)
```

### Environment-based Configuration

```go
func createResponseConfig() *response.ResponseConfig {
    config := response.NewResponseConfig()

    if langDir := os.Getenv("LANGUAGES_DIR"); langDir != "" {
        config.WithCustomLanguagesDir(langDir)
    }

    if defaultLang := os.Getenv("DEFAULT_LANGUAGE"); defaultLang != "" {
        config.WithDefaultLanguage(defaultLang)
    }

    return config
}
```

## Error Handling Best Practices

### Service Layer Errors

Create specific error types in your service layer:

```go
package service

import "errors"

var (
    ErrUserNotFound = errors.New("user not found")
    ErrEmailExists  = errors.New("email already exists")
    ErrInvalidPassword = errors.New("invalid password")
)

func (s *UserService) GetUser(ctx context.Context, id uuid.UUID) (*User, error) {
    user, err := s.repo.GetByID(ctx, id)
    if err != nil {
        if errors.Is(err, sql.ErrNoRows) {
            return nil, ErrUserNotFound
        }
        return nil, fmt.Errorf("failed to get user: %w", err)
    }
    return user, nil
}
```

### Handler Error Mapping

The response builder automatically maps common error patterns:

```go
func (h *UserHandler) GetUser(c echo.Context) error {
    user, err := h.userService.GetUser(ctx, userID)
    if err != nil {
        // This automatically maps service.ErrUserNotFound to USER_NOT_FOUND response
        return h.response.UserServiceError(c, err)
    }

    return h.response.Success(c, response.USER_RETRIEVED, user)
}
```

## Testing

### Unit Testing Responses

```go
func TestUserHandler_CreateUser(t *testing.T) {
    // Setup
    rb := response.NewResponseBuilder(i18nManager)
    handler := NewUserHandler(rb)

    // Test
    rec := httptest.NewRecorder()
    c := echo.New().NewContext(req, rec)

    err := handler.CreateUser(c)
    assert.NoError(t, err)

    // Verify response
    var resp response.Response
    json.Unmarshal(rec.Body.Bytes(), &resp)

    assert.True(t, resp.Success)
    assert.Equal(t, "USER_CREATED", resp.Code)
    assert.NotNil(t, resp.Data)
}
```

### Mock Time for Testing

```go
func TestWithFixedTime(t *testing.T) {
    // Set fixed time for testing
    fixedTime := time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)
    response.SetTimeProvider(func() time.Time { return fixedTime })
    defer response.ResetTimeProvider()

    // Your test code here
}
```

## Migration from Old Response System

### Before (Old System)

```go
func (h *UserHandler) CreateUser(c echo.Context) error {
    // ... validation and business logic

    return c.JSON(http.StatusCreated, dto.APIResponse{
        Success: true,
        Message: "User created successfully",
        Data:    user,
    })
}
```

### After (New System)

```go
func (h *UserHandler) CreateUser(c echo.Context) error {
    // ... validation and business logic

    location := "/api/v1/users/" + user.ID.String()
    return h.response.CreatedWithLocation(c, response.USER_CREATED, user, location)
}
```

## Performance Considerations

- **Language Files**: Loaded once at startup and cached in memory
- **Request ID Generation**: Uses crypto/rand for security but consider UUIDs for better performance in high-throughput scenarios
- **Context Values**: Minimal overhead for storing request metadata
- **Error Mapping**: String matching is optimized but consider using error types for better performance

## Contributing

When adding new response codes:

1. Add the code constant to `codes.go`
2. Add translations to all language files in `locales/`
3. Update this documentation
4. Add tests for the new functionality

## Examples

See the complete example in [user_updated.go](../../internal/modules/user/handlers/user_updated.go) for a full implementation using the new response system.
