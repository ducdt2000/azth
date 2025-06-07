package dto

import (
	"time"

	"github.com/ducdt2000/azth/backend/internal/domain"
	"github.com/ducdt2000/azth/backend/internal/modules/permission/dto"
	"github.com/google/uuid"
)

// RoleRequest represents a request to create a role
type RoleRequest struct {
	Name          string                 `json:"name" validate:"required,min=2,max=100"`
	Slug          string                 `json:"slug" validate:"required,min=2,max=100"`
	Description   *string                `json:"description,omitempty" validate:"omitempty,max=500"`
	IsGlobal      bool                   `json:"is_global"`
	IsDefault     bool                   `json:"is_default"`
	Priority      int                    `json:"priority" validate:"min=0,max=1000"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
	PermissionIDs []uuid.UUID            `json:"permission_ids,omitempty"`
}

// UpdateRoleRequest represents a request to update a role
type UpdateRoleRequest struct {
	Name        *string                `json:"name,omitempty" validate:"omitempty,min=2,max=100"`
	Description *string                `json:"description,omitempty" validate:"omitempty,max=500"`
	IsDefault   *bool                  `json:"is_default,omitempty"`
	Priority    *int                   `json:"priority,omitempty" validate:"omitempty,min=0,max=1000"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// RoleResponse represents a role in API responses
type RoleResponse struct {
	ID          uuid.UUID                 `json:"id"`
	TenantID    *uuid.UUID                `json:"tenant_id,omitempty"`
	Name        string                    `json:"name"`
	Slug        string                    `json:"slug"`
	Description *string                   `json:"description,omitempty"`
	IsSystem    bool                      `json:"is_system"`
	IsGlobal    bool                      `json:"is_global"`
	IsDefault   bool                      `json:"is_default"`
	Priority    int                       `json:"priority"`
	Metadata    map[string]interface{}    `json:"metadata,omitempty"`
	CreatedAt   time.Time                 `json:"created_at"`
	UpdatedAt   time.Time                 `json:"updated_at"`
	CreatedBy   uuid.UUID                 `json:"created_by"`
	UpdatedBy   *uuid.UUID                `json:"updated_by,omitempty"`
	Permissions []*dto.PermissionResponse `json:"permissions,omitempty"`
}

// RoleListRequest represents a request to list roles
type RoleListRequest struct {
	Page      int        `json:"page" validate:"min=1"`
	Limit     int        `json:"limit" validate:"min=1,max=100"`
	Search    string     `json:"search,omitempty"`
	TenantID  *uuid.UUID `json:"tenant_id,omitempty"`
	IsSystem  *bool      `json:"is_system,omitempty"`
	IsGlobal  *bool      `json:"is_global,omitempty"`
	IsDefault *bool      `json:"is_default,omitempty"`
	SortBy    string     `json:"sort_by,omitempty" validate:"omitempty,oneof=name slug priority created_at updated_at"`
	SortOrder string     `json:"sort_order,omitempty" validate:"omitempty,oneof=asc desc"`
}

// RoleListResponse represents a paginated list of roles
type RoleListResponse struct {
	Roles      []*RoleResponse `json:"roles"`
	Total      int64           `json:"total"`
	Page       int             `json:"page"`
	Limit      int             `json:"limit"`
	TotalPages int             `json:"total_pages"`
}

// RolePermissionRequest represents a request to manage role permissions
type RolePermissionRequest struct {
	PermissionIDs []uuid.UUID `json:"permission_ids" validate:"required,min=1"`
}

// RolePermissionResponse represents role permission assignments
type RolePermissionResponse struct {
	RoleID      uuid.UUID                 `json:"role_id"`
	Permissions []*dto.PermissionResponse `json:"permissions"`
}

// AssignRoleRequest represents a request to assign a role to a user
type AssignRoleRequest struct {
	UserID   uuid.UUID `json:"user_id" validate:"required"`
	TenantID uuid.UUID `json:"tenant_id" validate:"required"`
}

// RevokeRoleRequest represents a request to revoke a role from a user
type RevokeRoleRequest struct {
	UserID   uuid.UUID `json:"user_id" validate:"required"`
	TenantID uuid.UUID `json:"tenant_id" validate:"required"`
}

// UserRoleResponse represents a user's role assignment
type UserRoleResponse struct {
	ID        uuid.UUID     `json:"id"`
	UserID    uuid.UUID     `json:"user_id"`
	RoleID    uuid.UUID     `json:"role_id"`
	TenantID  uuid.UUID     `json:"tenant_id"`
	Role      *RoleResponse `json:"role,omitempty"`
	CreatedAt time.Time     `json:"created_at"`
	CreatedBy uuid.UUID     `json:"created_by"`
}

// BulkRoleAssignment represents a role assignment in bulk operations
type BulkRoleAssignment struct {
	UserID   uuid.UUID `json:"user_id" validate:"required"`
	RoleID   uuid.UUID `json:"role_id" validate:"required"`
	TenantID uuid.UUID `json:"tenant_id" validate:"required"`
}

// BulkRoleRequest represents a bulk operation request for roles
type BulkRoleRequest struct {
	Action      string               `json:"action" validate:"required,oneof=create delete assign revoke"`
	RoleIDs     []uuid.UUID          `json:"role_ids,omitempty"`
	Roles       []*RoleRequest       `json:"roles,omitempty"`
	Assignments []BulkRoleAssignment `json:"assignments,omitempty"`
	// For assign/revoke operations
	UserIDs  []uuid.UUID `json:"user_ids,omitempty"`
	TenantID *uuid.UUID  `json:"tenant_id,omitempty"`
}

// BulkRoleResponse represents a bulk operation response
type BulkRoleResponse struct {
	SuccessCount int             `json:"success_count"`
	FailureCount int             `json:"failure_count"`
	Errors       []string        `json:"errors,omitempty"`
	Roles        []*RoleResponse `json:"roles,omitempty"`
	Success      []uuid.UUID     `json:"success,omitempty"`
	Failed       []BulkRoleError `json:"failed,omitempty"`
	Total        int             `json:"total"`
}

// BulkRoleError represents an error in bulk operation
type BulkRoleError struct {
	RoleID *uuid.UUID `json:"role_id,omitempty"`
	UserID *uuid.UUID `json:"user_id,omitempty"`
	Index  *int       `json:"index,omitempty"`
	Error  string     `json:"error"`
}

// RoleStatsRequest represents a request for role statistics
type RoleStatsRequest struct {
	TenantID *uuid.UUID `json:"tenant_id,omitempty"`
}

// RoleStatsResponse represents role statistics
type RoleStatsResponse struct {
	TotalRoles      int64                `json:"total_roles"`
	SystemRoles     int64                `json:"system_roles"`
	CustomRoles     int64                `json:"custom_roles"`
	GlobalRoles     int64                `json:"global_roles"`
	TenantRoles     int64                `json:"tenant_roles"`
	DefaultRoles    int64                `json:"default_roles"`
	RolesByTenant   map[string]int64     `json:"roles_by_tenant,omitempty"`
	RoleAssignments int64                `json:"role_assignments"`
	TopRoles        []*RoleUsageResponse `json:"top_roles"`
}

// RoleUsageResponse represents role usage statistics
type RoleUsageResponse struct {
	Role            *RoleResponse `json:"role"`
	AssignmentCount int64         `json:"assignment_count"`
}

// DefaultRoleResponse represents default roles for a tenant
type DefaultRoleResponse struct {
	TenantRoles []RoleResponse `json:"tenant_roles"`
	GlobalRoles []RoleResponse `json:"global_roles"`
}

// RoleToResponse converts domain.Role to RoleResponse
func RoleToResponse(r *domain.Role) *RoleResponse {
	if r == nil {
		return nil
	}

	return &RoleResponse{
		ID:          r.ID,
		TenantID:    r.TenantID,
		Name:        r.Name,
		Slug:        r.Slug,
		Description: r.Description,
		IsSystem:    r.IsSystem,
		IsGlobal:    r.IsGlobal,
		IsDefault:   r.IsDefault,
		Priority:    r.Priority,
		Metadata:    r.Metadata,
		CreatedAt:   r.CreatedAt,
		UpdatedAt:   r.UpdatedAt,
		CreatedBy:   r.CreatedBy,
		UpdatedBy:   r.UpdatedBy,
	}
}

// RolesToResponse converts slice of domain.Role to slice of RoleResponse
func RolesToResponse(roles []*domain.Role) []*RoleResponse {
	result := make([]*RoleResponse, len(roles))
	for i, r := range roles {
		result[i] = RoleToResponse(r)
	}
	return result
}

// UserRoleToResponse converts domain.UserRole to UserRoleResponse
func UserRoleToResponse(ur *domain.UserRole) *UserRoleResponse {
	if ur == nil {
		return nil
	}

	return &UserRoleResponse{
		ID:        ur.ID,
		UserID:    ur.UserID,
		RoleID:    ur.RoleID,
		TenantID:  ur.TenantID,
		CreatedAt: ur.CreatedAt,
		CreatedBy: ur.CreatedBy,
	}
}

// UserRolesToResponse converts slice of domain.UserRole to slice of UserRoleResponse
func UserRolesToResponse(userRoles []*domain.UserRole) []*UserRoleResponse {
	result := make([]*UserRoleResponse, len(userRoles))
	for i, ur := range userRoles {
		result[i] = UserRoleToResponse(ur)
	}
	return result
}
