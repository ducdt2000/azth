package domain

import (
	"time"

	"github.com/google/uuid"
)

// Common response structures
type APIResponse struct {
	Success bool        `json:"success" example:"true"`
	Message string      `json:"message" example:"Operation completed successfully"`
	Data    interface{} `json:"data,omitempty"`
	Error   *APIError   `json:"error,omitempty"`
}

type APIError struct {
	Code    string `json:"code" example:"VALIDATION_ERROR"`
	Message string `json:"message" example:"Invalid input data"`
	Details string `json:"details,omitempty" example:"Field 'email' is required"`
}

type PaginationRequest struct {
	Page   int    `json:"page" query:"page" example:"1" minimum:"1"`
	Limit  int    `json:"limit" query:"limit" example:"20" minimum:"1" maximum:"100"`
	Sort   string `json:"sort" query:"sort" example:"created_at" enums:"created_at,updated_at,email,name"`
	Order  string `json:"order" query:"order" example:"desc" enums:"asc,desc"`
	Search string `json:"search" query:"search" example:"john@example.com"`
	Filter string `json:"filter" query:"filter" example:"status:active"`
}

type PaginationResponse struct {
	Page       int `json:"page" example:"1"`
	Limit      int `json:"limit" example:"20"`
	Total      int `json:"total" example:"150"`
	TotalPages int `json:"total_pages" example:"8"`
}

// User API DTOs
type CreateUserRequest struct {
	Email       string                 `json:"email" binding:"required,email" example:"john.doe@example.com"`
	Username    string                 `json:"username" binding:"required,min=3,max=50" example:"johndoe"`
	Password    string                 `json:"password" binding:"required,min=8" example:"SecurePassword123!"`
	FirstName   string                 `json:"first_name" binding:"required,min=1,max=100" example:"John"`
	LastName    string                 `json:"last_name" binding:"required,min=1,max=100" example:"Doe"`
	PhoneNumber *string                `json:"phone_number,omitempty" example:"+1234567890"`
	Avatar      *string                `json:"avatar,omitempty" example:"https://example.com/avatar.jpg"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

type UpdateUserRequest struct {
	Email       *string                `json:"email,omitempty" binding:"omitempty,email" example:"john.doe@example.com"`
	Username    *string                `json:"username,omitempty" binding:"omitempty,min=3,max=50" example:"johndoe"`
	FirstName   *string                `json:"first_name,omitempty" binding:"omitempty,min=1,max=100" example:"John"`
	LastName    *string                `json:"last_name,omitempty" binding:"omitempty,min=1,max=100" example:"Doe"`
	PhoneNumber *string                `json:"phone_number,omitempty" example:"+1234567890"`
	Avatar      *string                `json:"avatar,omitempty" example:"https://example.com/avatar.jpg"`
	Status      *UserStatus            `json:"status,omitempty" enums:"active,inactive,suspended,pending"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password" binding:"required" example:"OldPassword123!"`
	NewPassword     string `json:"new_password" binding:"required,min=8" example:"NewPassword123!"`
}

type UserResponse struct {
	ID                uuid.UUID  `json:"id" example:"550e8400-e29b-41d4-a716-446655440000"`
	TenantID          uuid.UUID  `json:"tenant_id" example:"550e8400-e29b-41d4-a716-446655440001"`
	Email             string     `json:"email" example:"john.doe@example.com"`
	Username          string     `json:"username" example:"johndoe"`
	FirstName         string     `json:"first_name" example:"John"`
	LastName          string     `json:"last_name" example:"Doe"`
	Avatar            *string    `json:"avatar" example:"https://example.com/avatar.jpg"`
	EmailVerified     bool       `json:"email_verified" example:"true"`
	EmailVerifiedAt   *time.Time `json:"email_verified_at" example:"2023-01-15T10:30:00Z"`
	PhoneNumber       *string    `json:"phone_number" example:"+1234567890"`
	PhoneVerified     bool       `json:"phone_verified" example:"false"`
	PhoneVerifiedAt   *time.Time `json:"phone_verified_at"`
	MFAEnabled        bool       `json:"mfa_enabled" example:"false"`
	Status            UserStatus `json:"status" example:"active"`
	LastLoginAt       *time.Time `json:"last_login_at" example:"2023-12-01T08:15:30Z"`
	PasswordChangedAt *time.Time `json:"password_changed_at" example:"2023-01-15T10:30:00Z"`
	Metadata          JSONMap    `json:"metadata"`
	CreatedAt         time.Time  `json:"created_at" example:"2023-01-15T10:30:00Z"`
	UpdatedAt         time.Time  `json:"updated_at" example:"2023-12-01T08:15:30Z"`
}

type UserListResponse struct {
	Users      []UserResponse     `json:"users"`
	Pagination PaginationResponse `json:"pagination"`
}

// Tenant API DTOs
type CreateTenantRequest struct {
	Name           string                 `json:"name" binding:"required,min=1,max=100" example:"Acme Corporation"`
	Slug           string                 `json:"slug" binding:"required,min=3,max=50,alphanum" example:"acme-corp"`
	Domain         *string                `json:"domain,omitempty" example:"acme.com"`
	LogoURL        *string                `json:"logo_url,omitempty" example:"https://example.com/logo.png"`
	PrimaryColor   *string                `json:"primary_color,omitempty" example:"#007bff"`
	SecondaryColor *string                `json:"secondary_color,omitempty" example:"#6c757d"`
	Plan           string                 `json:"plan" binding:"required" example:"enterprise" enums:"free,pro,enterprise"`
	MaxUsers       int                    `json:"max_users" binding:"min=1" example:"100"`
	Settings       map[string]interface{} `json:"settings,omitempty"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
}

type UpdateTenantRequest struct {
	Name           *string                `json:"name,omitempty" binding:"omitempty,min=1,max=100" example:"Acme Corporation"`
	Domain         *string                `json:"domain,omitempty" example:"acme.com"`
	LogoURL        *string                `json:"logo_url,omitempty" example:"https://example.com/logo.png"`
	PrimaryColor   *string                `json:"primary_color,omitempty" example:"#007bff"`
	SecondaryColor *string                `json:"secondary_color,omitempty" example:"#6c757d"`
	Status         *TenantStatus          `json:"status,omitempty" enums:"active,inactive,suspended,trial"`
	Plan           *string                `json:"plan,omitempty" example:"enterprise" enums:"free,pro,enterprise"`
	MaxUsers       *int                   `json:"max_users,omitempty" binding:"omitempty,min=1" example:"100"`
	Settings       map[string]interface{} `json:"settings,omitempty"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
}

type TenantResponse struct {
	ID             uuid.UUID    `json:"id" example:"550e8400-e29b-41d4-a716-446655440001"`
	Name           string       `json:"name" example:"Acme Corporation"`
	Slug           string       `json:"slug" example:"acme-corp"`
	Domain         *string      `json:"domain" example:"acme.com"`
	LogoURL        *string      `json:"logo_url" example:"https://example.com/logo.png"`
	PrimaryColor   *string      `json:"primary_color" example:"#007bff"`
	SecondaryColor *string      `json:"secondary_color" example:"#6c757d"`
	Status         TenantStatus `json:"status" example:"active"`
	Plan           string       `json:"plan" example:"enterprise"`
	MaxUsers       int          `json:"max_users" example:"100"`
	CurrentUsers   int          `json:"current_users" example:"45"`
	Settings       JSONMap      `json:"settings"`
	Metadata       JSONMap      `json:"metadata"`
	CreatedAt      time.Time    `json:"created_at" example:"2023-01-15T10:30:00Z"`
	UpdatedAt      time.Time    `json:"updated_at" example:"2023-12-01T08:15:30Z"`
}

type TenantListResponse struct {
	Tenants    []TenantResponse   `json:"tenants"`
	Pagination PaginationResponse `json:"pagination"`
}

type TenantStatsResponse struct {
	TotalUsers       int `json:"total_users" example:"45"`
	ActiveUsers      int `json:"active_users" example:"42"`
	InactiveUsers    int `json:"inactive_users" example:"3"`
	TotalSessions    int `json:"total_sessions" example:"89"`
	ActiveSessions   int `json:"active_sessions" example:"12"`
	TotalOIDCClients int `json:"total_oidc_clients" example:"5"`
	ActiveClients    int `json:"active_clients" example:"4"`
}

// User role assignment DTOs
type AssignRoleRequest struct {
	RoleID uuid.UUID `json:"role_id" binding:"required" example:"550e8400-e29b-41d4-a716-446655440002"`
}

type RevokeRoleRequest struct {
	RoleID uuid.UUID `json:"role_id" binding:"required" example:"550e8400-e29b-41d4-a716-446655440002"`
}

type UserRoleResponse struct {
	ID        uuid.UUID `json:"id" example:"550e8400-e29b-41d4-a716-446655440003"`
	UserID    uuid.UUID `json:"user_id" example:"550e8400-e29b-41d4-a716-446655440000"`
	RoleID    uuid.UUID `json:"role_id" example:"550e8400-e29b-41d4-a716-446655440002"`
	TenantID  uuid.UUID `json:"tenant_id" example:"550e8400-e29b-41d4-a716-446655440001"`
	Role      *Role     `json:"role,omitempty"`
	CreatedAt time.Time `json:"created_at" example:"2023-01-15T10:30:00Z"`
}

// Bulk operations DTOs
type BulkUserRequest struct {
	UserIDs []uuid.UUID `json:"user_ids" binding:"required,min=1" example:"[\"550e8400-e29b-41d4-a716-446655440000\"]"`
	Action  string      `json:"action" binding:"required" example:"activate" enums:"activate,deactivate,suspend,delete"`
}

type BulkTenantRequest struct {
	TenantIDs []uuid.UUID `json:"tenant_ids" binding:"required,min=1" example:"[\"550e8400-e29b-41d4-a716-446655440001\"]"`
	Action    string      `json:"action" binding:"required" example:"activate" enums:"activate,deactivate,suspend,delete"`
}

type BulkOperationResponse struct {
	SuccessCount int         `json:"success_count" example:"5"`
	FailureCount int         `json:"failure_count" example:"1"`
	Failures     []BulkError `json:"failures,omitempty"`
}

type BulkError struct {
	ID    uuid.UUID `json:"id" example:"550e8400-e29b-41d4-a716-446655440000"`
	Error string    `json:"error" example:"User not found"`
}
