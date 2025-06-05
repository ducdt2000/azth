package dto

import (
	"github.com/google/uuid"
)

// CreateUserRequest represents the request to create a new user
type CreateUserRequest struct {
	Email       string                 `json:"email" binding:"required,email" example:"john.doe@example.com" validate:"required,email"`
	Username    string                 `json:"username" binding:"required,min=3,max=50" example:"johndoe" validate:"required,min=3,max=50"`
	Password    string                 `json:"password" binding:"required,min=8" example:"SecurePassword123!" validate:"required,min=8"`
	FirstName   string                 `json:"first_name" binding:"required,min=1,max=100" example:"John" validate:"required,min=1,max=100"`
	LastName    string                 `json:"last_name" binding:"required,min=1,max=100" example:"Doe" validate:"required,min=1,max=100"`
	PhoneNumber *string                `json:"phone_number,omitempty" example:"+1234567890"`
	Avatar      *string                `json:"avatar,omitempty" example:"https://example.com/avatar.jpg"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// UpdateUserRequest represents the request to update an existing user
type UpdateUserRequest struct {
	Email       *string                `json:"email,omitempty" binding:"omitempty,email" example:"john.doe@example.com" validate:"omitempty,email"`
	Username    *string                `json:"username,omitempty" binding:"omitempty,min=3,max=50" example:"johndoe" validate:"omitempty,min=3,max=50"`
	FirstName   *string                `json:"first_name,omitempty" binding:"omitempty,min=1,max=100" example:"John" validate:"omitempty,min=1,max=100"`
	LastName    *string                `json:"last_name,omitempty" binding:"omitempty,min=1,max=100" example:"Doe" validate:"omitempty,min=1,max=100"`
	PhoneNumber *string                `json:"phone_number,omitempty" example:"+1234567890"`
	Avatar      *string                `json:"avatar,omitempty" example:"https://example.com/avatar.jpg"`
	Status      *string                `json:"status,omitempty" enums:"active,inactive,suspended,pending" example:"active"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// ChangePasswordRequest represents the request to change user password
type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password" binding:"required" example:"OldPassword123!" validate:"required"`
	NewPassword     string `json:"new_password" binding:"required,min=8" example:"NewPassword123!" validate:"required,min=8"`
}

// AssignRoleRequest represents the request to assign a role to a user
type AssignRoleRequest struct {
	RoleID uuid.UUID `json:"role_id" binding:"required" example:"550e8400-e29b-41d4-a716-446655440002" validate:"required"`
}

// RevokeRoleRequest represents the request to revoke a role from a user
type RevokeRoleRequest struct {
	RoleID uuid.UUID `json:"role_id" binding:"required" example:"550e8400-e29b-41d4-a716-446655440002" validate:"required"`
}

// BulkUserRequest represents the request for bulk user operations
type BulkUserRequest struct {
	UserIDs []uuid.UUID `json:"user_ids" binding:"required,min=1" example:"[\"550e8400-e29b-41d4-a716-446655440000\"]" validate:"required,min=1"`
	Action  string      `json:"action" binding:"required" example:"activate" enums:"activate,deactivate,suspend,delete" validate:"required"`
}

// UserListRequest represents the request for listing users with pagination and filtering
type UserListRequest struct {
	Page     int    `query:"page" example:"1" minimum:"1" default:"1"`
	Limit    int    `query:"limit" example:"20" minimum:"1" maximum:"100" default:"20"`
	Sort     string `query:"sort" example:"created_at" enums:"created_at,updated_at,email,username,first_name,last_name" default:"created_at"`
	Order    string `query:"order" example:"desc" enums:"asc,desc" default:"desc"`
	Search   string `query:"search" example:"john@example.com"`
	Status   string `query:"status" example:"active" enums:"active,inactive,suspended,pending"`
	TenantID string `query:"tenant_id" example:"550e8400-e29b-41d4-a716-446655440001"`
}

// UserStatsRequest represents the request for user statistics
type UserStatsRequest struct {
	TenantID *uuid.UUID `query:"tenant_id" example:"550e8400-e29b-41d4-a716-446655440001"`
	DateFrom *string    `query:"date_from" example:"2023-01-01"`
	DateTo   *string    `query:"date_to" example:"2023-12-31"`
}
