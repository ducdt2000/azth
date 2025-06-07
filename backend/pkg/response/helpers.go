package response

import (
	"errors"
	"strings"

	"github.com/labstack/echo/v4"
)

// PaginationMeta represents pagination metadata
type PaginationMeta struct {
	Page       int `json:"page" example:"1"`
	Limit      int `json:"limit" example:"20"`
	Total      int `json:"total" example:"150"`
	TotalPages int `json:"total_pages" example:"8"`
}

// NewPaginationMeta creates new pagination metadata
func NewPaginationMeta(page, limit, total int) *PaginationMeta {
	totalPages := (total + limit - 1) / limit
	if totalPages < 1 {
		totalPages = 1
	}

	return &PaginationMeta{
		Page:       page,
		Limit:      limit,
		Total:      total,
		TotalPages: totalPages,
	}
}

// SuccessWithPagination creates a success response with pagination
func (rb *ResponseBuilder) SuccessWithPagination(c echo.Context, code ResponseCode, data interface{}, pagination *PaginationMeta) error {
	meta := rb.WithPagination(pagination)
	return rb.Success(c, code, data, meta)
}

// CreatedWithLocation creates a created response with location header
func (rb *ResponseBuilder) CreatedWithLocation(c echo.Context, code ResponseCode, data interface{}, location string) error {
	c.Response().Header().Set("Location", location)
	return rb.Created(c, code, data)
}

// ValidationError creates a validation error response
func (rb *ResponseBuilder) ValidationError(c echo.Context, details interface{}) error {
	return rb.BadRequest(c, VALIDATION_ERROR, details)
}

// DatabaseError creates a database error response
func (rb *ResponseBuilder) DatabaseError(c echo.Context, err error) error {
	details := map[string]interface{}{
		"type": "database_error",
	}

	// Only include error details in development mode
	if isDevelopmentMode(c) {
		details["error"] = err.Error()
	}

	return rb.InternalServerError(c, DATABASE_ERROR, details)
}

// ServiceError handles service layer errors and maps them to appropriate HTTP responses
func (rb *ResponseBuilder) ServiceError(c echo.Context, err error) error {
	if err == nil {
		return rb.InternalServerError(c, INTERNAL_SERVER_ERROR, nil)
	}

	// Check if it's a typed ServiceError
	var serviceErr *ServiceError
	if errors.As(err, &serviceErr) {
		return rb.handleTypedServiceError(c, serviceErr)
	}

	// Fallback to generic error handling for untyped errors
	return rb.handleGenericError(c, err)
}

// handleTypedServiceError handles typed service errors
func (rb *ResponseBuilder) handleTypedServiceError(c echo.Context, serviceErr *ServiceError) error {
	// Map service error codes to response codes and HTTP status
	switch serviceErr.Code {
	// Authentication errors
	case AuthInvalidCredentials:
		return rb.Unauthorized(c, AUTH_INVALID_CREDENTIALS, serviceErr.Details)
	case AuthTokenExpired:
		return rb.Unauthorized(c, AUTH_TOKEN_EXPIRED, serviceErr.Details)
	case AuthTokenInvalid:
		return rb.Unauthorized(c, AUTH_TOKEN_INVALID, serviceErr.Details)
	case AuthTokenMissing:
		return rb.Unauthorized(c, AUTH_TOKEN_MISSING, serviceErr.Details)
	case AuthMFARequired:
		return rb.Unauthorized(c, AUTH_MFA_REQUIRED, serviceErr.Details)
	case AuthMFAInvalidCode:
		return rb.BadRequest(c, AUTH_MFA_INVALID_CODE, serviceErr.Details)
	case AuthSessionNotFound:
		return rb.NotFound(c, AUTH_SESSION_NOT_FOUND, serviceErr.Details)
	case AuthSessionExpired:
		return rb.Unauthorized(c, AUTH_TOKEN_EXPIRED, serviceErr.Details)
	case AuthAccountLocked:
		return rb.Forbidden(c, FORBIDDEN, serviceErr.Details)

	// User errors
	case UserNotFound:
		return rb.NotFound(c, USER_NOT_FOUND, serviceErr.Details)
	case UserAlreadyExists:
		return rb.Conflict(c, USER_ALREADY_EXISTS, serviceErr.Details)
	case UserEmailExists:
		return rb.Conflict(c, USER_EMAIL_EXISTS, serviceErr.Details)
	case UserUsernameExists:
		return rb.Conflict(c, USER_USERNAME_EXISTS, serviceErr.Details)
	case UserInvalidStatus:
		return rb.BadRequest(c, USER_INVALID_STATUS, serviceErr.Details)
	case UserPasswordInvalid:
		return rb.BadRequest(c, USER_PASSWORD_INVALID, serviceErr.Details)
	case UserUnauthorized:
		return rb.Unauthorized(c, USER_UNAUTHORIZED, serviceErr.Details)
	case UserSuspended:
		return rb.Forbidden(c, USER_SUSPENDED_ACCOUNT, serviceErr.Details)
	case UserInactive:
		return rb.Forbidden(c, USER_INACTIVE_ACCOUNT, serviceErr.Details)

	// Tenant errors
	case TenantNotFound:
		return rb.NotFound(c, TENANT_NOT_FOUND, serviceErr.Details)
	case TenantAlreadyExists:
		return rb.Conflict(c, TENANT_ALREADY_EXISTS, serviceErr.Details)
	case TenantSlugExists:
		return rb.Conflict(c, TENANT_SLUG_EXISTS, serviceErr.Details)
	case TenantDomainExists:
		return rb.Conflict(c, TENANT_DOMAIN_EXISTS, serviceErr.Details)
	case TenantQuotaExceeded:
		return rb.BadRequest(c, TENANT_QUOTA_EXCEEDED, serviceErr.Details)
	case TenantAccessDenied:
		return rb.Forbidden(c, TENANT_ACCESS_DENIED, serviceErr.Details)

	// Role errors
	case RoleNotFound:
		return rb.NotFound(c, ROLE_NOT_FOUND, serviceErr.Details)
	case RoleAlreadyExists:
		return rb.Conflict(c, ROLE_ALREADY_EXISTS, serviceErr.Details)
	case RoleSlugExists:
		return rb.Conflict(c, ROLE_SLUG_EXISTS, serviceErr.Details)
	case RoleSystemRole:
		return rb.Forbidden(c, ROLE_SYSTEM_ROLE, serviceErr.Details)
	case RoleCannotDelete:
		return rb.Forbidden(c, ROLE_CANNOT_DELETE, serviceErr.Details)
	case RoleAssignmentFailed:
		return rb.BadRequest(c, ROLE_ASSIGNMENT_FAILED, serviceErr.Details)

	// Permission errors
	case PermissionNotFound:
		return rb.NotFound(c, PERMISSION_NOT_FOUND, serviceErr.Details)
	case PermissionAlreadyExists:
		return rb.Conflict(c, PERMISSION_ALREADY_EXISTS, serviceErr.Details)
	case PermissionAccessDenied:
		return rb.Forbidden(c, PERMISSION_ACCESS_DENIED, serviceErr.Details)
	case PermissionInsufficient:
		return rb.Forbidden(c, PERMISSION_INSUFFICIENT, serviceErr.Details)
	case PermissionAssignmentFailed:
		return rb.BadRequest(c, PERMISSION_ASSIGNMENT_FAILED, serviceErr.Details)

	// General errors
	case ValidationError:
		return rb.BadRequest(c, VALIDATION_ERROR, serviceErr.Details)
	case DatabaseError:
		return rb.InternalServerError(c, DATABASE_ERROR, serviceErr.Details)
	case ExternalServiceError:
		return rb.ServiceUnavailable(c, EXTERNAL_SERVICE_ERROR, serviceErr.Details)
	case InternalError:
		return rb.InternalServerError(c, INTERNAL_SERVER_ERROR, serviceErr.Details)

	default:
		// Unknown service error code, fallback to generic error
		return rb.handleGenericError(c, serviceErr)
	}
}

// handleGenericError handles untyped errors with fallback string matching
func (rb *ResponseBuilder) handleGenericError(c echo.Context, err error) error {
	errMsg := strings.ToLower(err.Error())

	// Fallback string matching for untyped errors (legacy support)
	switch {
	case contains(errMsg, "not found"):
		return rb.NotFound(c, NOT_FOUND, nil)
	case contains(errMsg, "already exists"):
		return rb.Conflict(c, CONFLICT, nil)
	case contains(errMsg, "unauthorized"):
		return rb.Unauthorized(c, UNAUTHORIZED, nil)
	case contains(errMsg, "forbidden"):
		return rb.Forbidden(c, FORBIDDEN, nil)
	case contains(errMsg, "validation"):
		return rb.BadRequest(c, VALIDATION_ERROR, nil)
	case contains(errMsg, "database"):
		return rb.InternalServerError(c, DATABASE_ERROR, nil)
	default:
		return rb.InternalServerError(c, INTERNAL_SERVER_ERROR, map[string]interface{}{
			"error": err.Error(),
		})
	}
}

// Deprecated: Use ServiceError instead
// AuthServiceError handles authentication service errors with string matching (deprecated)
func (rb *ResponseBuilder) AuthServiceError(c echo.Context, err error) error {
	return rb.ServiceError(c, err)
}

// Deprecated: Use ServiceError instead
// UserServiceError handles user service errors with string matching (deprecated)
func (rb *ResponseBuilder) UserServiceError(c echo.Context, err error) error {
	return rb.ServiceError(c, err)
}

// GetRequestID is handled in middleware.go to avoid duplication

// contains checks if a string contains a substring (case-insensitive)
func contains(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}

// HealthCheck creates a health check response
func (rb *ResponseBuilder) HealthCheck(c echo.Context, healthy bool) error {
	if healthy {
		return rb.Success(c, SYSTEM_HEALTHY, map[string]interface{}{
			"status":    "healthy",
			"timestamp": GetCurrentTimestamp(),
		})
	}

	return rb.ServiceUnavailable(c, SYSTEM_UNAVAILABLE, map[string]interface{}{
		"status":    "unhealthy",
		"timestamp": GetCurrentTimestamp(),
	})
}

// Helper functions for error type checking
func isDevelopmentMode(c echo.Context) bool {
	// Check environment variable or config
	env := c.Get("environment")
	if env != nil {
		return env.(string) == "development" || env.(string) == "dev"
	}
	return false
}

// WithMeta creates a meta object with multiple properties
func (rb *ResponseBuilder) WithMeta(requestID, version string, pagination interface{}) *Meta {
	return &Meta{
		RequestID:  requestID,
		Version:    version,
		Pagination: pagination,
	}
}

// NewErrorResponse creates a new error response (utility for testing)
func NewErrorResponse(success bool, code, message string, details interface{}) Response {
	return Response{
		Success: success,
		Code:    code,
		Message: message,
		Error: &ErrorInfo{
			Code:    code,
			Message: message,
			Details: details,
		},
		Timestamp: GetCurrentTimestamp(),
	}
}

// NewSuccessResponse creates a new success response (utility for testing)
func NewSuccessResponse(code, message string, data interface{}) Response {
	return Response{
		Success:   true,
		Code:      code,
		Message:   message,
		Data:      data,
		Timestamp: GetCurrentTimestamp(),
	}
}
