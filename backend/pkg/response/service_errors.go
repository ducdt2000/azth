package response

import "fmt"

// ServiceErrorCode represents typed service error codes
type ServiceErrorCode string

// Authentication service error codes
const (
	// Auth success codes (informational)
	AuthLoginSuccess   ServiceErrorCode = "AUTH_LOGIN_SUCCESS"
	AuthLogoutSuccess  ServiceErrorCode = "AUTH_LOGOUT_SUCCESS"
	AuthTokenRefreshed ServiceErrorCode = "AUTH_TOKEN_REFRESHED"
	AuthMFAEnabled     ServiceErrorCode = "AUTH_MFA_ENABLED"
	AuthMFADisabled    ServiceErrorCode = "AUTH_MFA_DISABLED"

	// Auth error codes
	AuthInvalidCredentials ServiceErrorCode = "AUTH_INVALID_CREDENTIALS"
	AuthTokenExpired       ServiceErrorCode = "AUTH_TOKEN_EXPIRED"
	AuthTokenInvalid       ServiceErrorCode = "AUTH_TOKEN_INVALID"
	AuthTokenMissing       ServiceErrorCode = "AUTH_TOKEN_MISSING"
	AuthMFARequired        ServiceErrorCode = "AUTH_MFA_REQUIRED"
	AuthMFAInvalidCode     ServiceErrorCode = "AUTH_MFA_INVALID_CODE"
	AuthSessionNotFound    ServiceErrorCode = "AUTH_SESSION_NOT_FOUND"
	AuthSessionExpired     ServiceErrorCode = "AUTH_SESSION_EXPIRED"
	AuthAccountLocked      ServiceErrorCode = "AUTH_ACCOUNT_LOCKED"
)

// User service error codes
const (
	UserNotFound        ServiceErrorCode = "USER_NOT_FOUND"
	UserAlreadyExists   ServiceErrorCode = "USER_ALREADY_EXISTS"
	UserEmailExists     ServiceErrorCode = "USER_EMAIL_EXISTS"
	UserUsernameExists  ServiceErrorCode = "USER_USERNAME_EXISTS"
	UserInvalidStatus   ServiceErrorCode = "USER_INVALID_STATUS"
	UserPasswordInvalid ServiceErrorCode = "USER_PASSWORD_INVALID"
	UserUnauthorized    ServiceErrorCode = "USER_UNAUTHORIZED"
	UserSuspended       ServiceErrorCode = "USER_SUSPENDED"
	UserInactive        ServiceErrorCode = "USER_INACTIVE"
)

// Tenant service error codes
const (
	TenantNotFound      ServiceErrorCode = "TENANT_NOT_FOUND"
	TenantAlreadyExists ServiceErrorCode = "TENANT_ALREADY_EXISTS"
	TenantSlugExists    ServiceErrorCode = "TENANT_SLUG_EXISTS"
	TenantDomainExists  ServiceErrorCode = "TENANT_DOMAIN_EXISTS"
	TenantQuotaExceeded ServiceErrorCode = "TENANT_QUOTA_EXCEEDED"
	TenantAccessDenied  ServiceErrorCode = "TENANT_ACCESS_DENIED"
)

// Role service error codes
const (
	RoleNotFound         ServiceErrorCode = "ROLE_NOT_FOUND"
	RoleAlreadyExists    ServiceErrorCode = "ROLE_ALREADY_EXISTS"
	RoleSlugExists       ServiceErrorCode = "ROLE_SLUG_EXISTS"
	RoleSystemRole       ServiceErrorCode = "ROLE_SYSTEM_ROLE"
	RoleCannotDelete     ServiceErrorCode = "ROLE_CANNOT_DELETE"
	RoleAssignmentFailed ServiceErrorCode = "ROLE_ASSIGNMENT_FAILED"
)

// Permission service error codes
const (
	PermissionNotFound         ServiceErrorCode = "PERMISSION_NOT_FOUND"
	PermissionAlreadyExists    ServiceErrorCode = "PERMISSION_ALREADY_EXISTS"
	PermissionAccessDenied     ServiceErrorCode = "PERMISSION_ACCESS_DENIED"
	PermissionInsufficient     ServiceErrorCode = "PERMISSION_INSUFFICIENT"
	PermissionAssignmentFailed ServiceErrorCode = "PERMISSION_ASSIGNMENT_FAILED"
)

// General service error codes
const (
	ValidationError      ServiceErrorCode = "VALIDATION_ERROR"
	DatabaseError        ServiceErrorCode = "DATABASE_ERROR"
	ExternalServiceError ServiceErrorCode = "EXTERNAL_SERVICE_ERROR"
	InternalError        ServiceErrorCode = "INTERNAL_ERROR"
)

// ServiceError represents a typed service error
type ServiceError struct {
	Code    ServiceErrorCode `json:"code"`
	Message string           `json:"message"`
	Details interface{}      `json:"details,omitempty"`
}

// Error implements the error interface
func (e *ServiceError) Error() string {
	if e.Details != nil {
		return fmt.Sprintf("%s: %s (details: %v)", e.Code, e.Message, e.Details)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Is checks if the error matches a specific error (implements Go's error interface)
func (e *ServiceError) Is(target error) bool {
	if other, ok := target.(*ServiceError); ok {
		return e.Code == other.Code
	}
	return false
}

// HasCode checks if the error matches a specific service error code
func (e *ServiceError) HasCode(code ServiceErrorCode) bool {
	return e.Code == code
}

// NewServiceError creates a new service error
func NewServiceError(code ServiceErrorCode, message string, details ...interface{}) *ServiceError {
	var detail interface{}
	if len(details) > 0 {
		detail = details[0]
	}
	return &ServiceError{
		Code:    code,
		Message: message,
		Details: detail,
	}
}

// Auth service error constructors
func NewAuthInvalidCredentials(details ...interface{}) *ServiceError {
	return NewServiceError(AuthInvalidCredentials, "Invalid credentials provided", details...)
}

func NewAuthTokenExpired(details ...interface{}) *ServiceError {
	return NewServiceError(AuthTokenExpired, "Authentication token has expired", details...)
}

func NewAuthTokenInvalid(details ...interface{}) *ServiceError {
	return NewServiceError(AuthTokenInvalid, "Invalid authentication token", details...)
}

func NewAuthMFARequired(details ...interface{}) *ServiceError {
	return NewServiceError(AuthMFARequired, "Multi-factor authentication required", details...)
}

func NewAuthMFAInvalidCode(details ...interface{}) *ServiceError {
	return NewServiceError(AuthMFAInvalidCode, "Invalid MFA code provided", details...)
}

func NewAuthSessionNotFound(details ...interface{}) *ServiceError {
	return NewServiceError(AuthSessionNotFound, "Session not found", details...)
}

func NewAuthAccountLocked(details ...interface{}) *ServiceError {
	return NewServiceError(AuthAccountLocked, "Account is locked", details...)
}

// User service error constructors
func NewUserNotFound(details ...interface{}) *ServiceError {
	return NewServiceError(UserNotFound, "User not found", details...)
}

func NewUserAlreadyExists(details ...interface{}) *ServiceError {
	return NewServiceError(UserAlreadyExists, "User already exists", details...)
}

func NewUserEmailExists(details ...interface{}) *ServiceError {
	return NewServiceError(UserEmailExists, "Email address already exists", details...)
}

func NewUserPasswordInvalid(details ...interface{}) *ServiceError {
	return NewServiceError(UserPasswordInvalid, "Invalid password", details...)
}

// Tenant service error constructors
func NewTenantNotFound(details ...interface{}) *ServiceError {
	return NewServiceError(TenantNotFound, "Tenant not found", details...)
}

func NewTenantAlreadyExists(details ...interface{}) *ServiceError {
	return NewServiceError(TenantAlreadyExists, "Tenant already exists", details...)
}

func NewTenantSlugExists(details ...interface{}) *ServiceError {
	return NewServiceError(TenantSlugExists, "Tenant slug already exists", details...)
}

// Role service error constructors
func NewRoleNotFound(details ...interface{}) *ServiceError {
	return NewServiceError(RoleNotFound, "Role not found", details...)
}

func NewRoleAlreadyExists(details ...interface{}) *ServiceError {
	return NewServiceError(RoleAlreadyExists, "Role already exists", details...)
}

func NewRoleCannotDelete(details ...interface{}) *ServiceError {
	return NewServiceError(RoleCannotDelete, "Cannot delete system role", details...)
}

// Permission service error constructors
func NewPermissionNotFound(details ...interface{}) *ServiceError {
	return NewServiceError(PermissionNotFound, "Permission not found", details...)
}

func NewPermissionAlreadyExists(details ...interface{}) *ServiceError {
	return NewServiceError(PermissionAlreadyExists, "Permission already exists", details...)
}

func NewPermissionAccessDenied(details ...interface{}) *ServiceError {
	return NewServiceError(PermissionAccessDenied, "Permission access denied", details...)
}

// General service error constructors
func NewValidationError(message string, details ...interface{}) *ServiceError {
	return NewServiceError(ValidationError, message, details...)
}

func NewDatabaseError(details ...interface{}) *ServiceError {
	return NewServiceError(DatabaseError, "Database operation failed", details...)
}

func NewInternalError(details ...interface{}) *ServiceError {
	return NewServiceError(InternalError, "Internal server error", details...)
}
