package dto

import (
	"time"

	"github.com/ducdt2000/azth/backend/internal/domain"
	"github.com/google/uuid"
)

// UserResponse represents a user in API responses
type UserResponse struct {
	ID                uuid.UUID         `json:"id" example:"550e8400-e29b-41d4-a716-446655440000"`
	TenantID          uuid.UUID         `json:"tenant_id" example:"550e8400-e29b-41d4-a716-446655440001"`
	Email             string            `json:"email" example:"john.doe@example.com"`
	Username          string            `json:"username" example:"johndoe"`
	FirstName         string            `json:"first_name" example:"John"`
	LastName          string            `json:"last_name" example:"Doe"`
	Avatar            *string           `json:"avatar" example:"https://example.com/avatar.jpg"`
	EmailVerified     bool              `json:"email_verified" example:"true"`
	EmailVerifiedAt   *time.Time        `json:"email_verified_at" example:"2023-01-15T10:30:00Z"`
	PhoneNumber       *string           `json:"phone_number" example:"+1234567890"`
	PhoneVerified     bool              `json:"phone_verified" example:"false"`
	PhoneVerifiedAt   *time.Time        `json:"phone_verified_at"`
	MFAEnabled        bool              `json:"mfa_enabled" example:"false"`
	Status            domain.UserStatus `json:"status" example:"active"`
	LastLoginAt       *time.Time        `json:"last_login_at" example:"2023-12-01T08:15:30Z"`
	PasswordChangedAt *time.Time        `json:"password_changed_at" example:"2023-01-15T10:30:00Z"`
	Metadata          domain.JSONMap    `json:"metadata"`
	CreatedAt         time.Time         `json:"created_at" example:"2023-01-15T10:30:00Z"`
	UpdatedAt         time.Time         `json:"updated_at" example:"2023-12-01T08:15:30Z"`
}

// UserListResponse represents a paginated list of users
type UserListResponse struct {
	Users      []UserResponse     `json:"users"`
	Pagination PaginationResponse `json:"pagination"`
}

// UserRoleResponse represents a user role assignment
type UserRoleResponse struct {
	ID        uuid.UUID    `json:"id" example:"550e8400-e29b-41d4-a716-446655440003"`
	UserID    uuid.UUID    `json:"user_id" example:"550e8400-e29b-41d4-a716-446655440000"`
	RoleID    uuid.UUID    `json:"role_id" example:"550e8400-e29b-41d4-a716-446655440002"`
	TenantID  uuid.UUID    `json:"tenant_id" example:"550e8400-e29b-41d4-a716-446655440001"`
	Role      *domain.Role `json:"role,omitempty"`
	CreatedAt time.Time    `json:"created_at" example:"2023-01-15T10:30:00Z"`
}

// UserStatsResponse represents user statistics
type UserStatsResponse struct {
	TotalUsers     int `json:"total_users" example:"150"`
	ActiveUsers    int `json:"active_users" example:"142"`
	InactiveUsers  int `json:"inactive_users" example:"5"`
	SuspendedUsers int `json:"suspended_users" example:"2"`
	PendingUsers   int `json:"pending_users" example:"1"`
	VerifiedEmails int `json:"verified_emails" example:"140"`
	VerifiedPhones int `json:"verified_phones" example:"85"`
	MFAEnabled     int `json:"mfa_enabled" example:"67"`
	RecentLogins   int `json:"recent_logins_24h" example:"45"`
}

// BulkOperationResponse represents the result of a bulk operation
type BulkOperationResponse struct {
	SuccessCount int         `json:"success_count" example:"5"`
	FailureCount int         `json:"failure_count" example:"1"`
	Failures     []BulkError `json:"failures,omitempty"`
}

// BulkError represents an error in bulk operations
type BulkError struct {
	ID    uuid.UUID `json:"id" example:"550e8400-e29b-41d4-a716-446655440000"`
	Error string    `json:"error" example:"User not found"`
}

// Common response structures
type APIResponse struct {
	Success bool        `json:"success" example:"true"`
	Message string      `json:"message" example:"Operation completed successfully"`
	Data    interface{} `json:"data,omitempty"`
	Error   *APIError   `json:"error,omitempty"`
}

// APIError represents an API error
type APIError struct {
	Code    string `json:"code" example:"VALIDATION_ERROR"`
	Message string `json:"message" example:"Invalid input data"`
	Details string `json:"details,omitempty" example:"Field 'email' is required"`
}

// PaginationResponse represents pagination metadata
type PaginationResponse struct {
	Page       int `json:"page" example:"1"`
	Limit      int `json:"limit" example:"20"`
	Total      int `json:"total" example:"150"`
	TotalPages int `json:"total_pages" example:"8"`
}
