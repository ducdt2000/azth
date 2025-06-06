package dto

import (
	"time"

	"github.com/ducdt2000/azth/backend/internal/domain"
	"github.com/google/uuid"
)

// PermissionRequest represents a request to create a permission
type PermissionRequest struct {
	Name        string                 `json:"name" validate:"required,min=3,max=100"`
	Code        string                 `json:"code" validate:"required,min=3,max=100"`
	Description *string                `json:"description,omitempty" validate:"omitempty,max=500"`
	Module      string                 `json:"module" validate:"required,min=2,max=50"`
	Resource    string                 `json:"resource" validate:"required,min=2,max=50"`
	Action      string                 `json:"action" validate:"required,min=2,max=50"`
	IsDefault   bool                   `json:"is_default"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// UpdatePermissionRequest represents a request to update a permission
type UpdatePermissionRequest struct {
	Name        *string                `json:"name,omitempty" validate:"omitempty,min=3,max=100"`
	Description *string                `json:"description,omitempty" validate:"omitempty,max=500"`
	Module      *string                `json:"module,omitempty" validate:"omitempty,min=2,max=50"`
	Resource    *string                `json:"resource,omitempty" validate:"omitempty,min=2,max=50"`
	Action      *string                `json:"action,omitempty" validate:"omitempty,min=2,max=50"`
	IsDefault   *bool                  `json:"is_default,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// PermissionResponse represents a permission in API responses
type PermissionResponse struct {
	ID          uuid.UUID              `json:"id"`
	Name        string                 `json:"name"`
	Code        string                 `json:"code"`
	Description *string                `json:"description,omitempty"`
	Module      string                 `json:"module"`
	Resource    string                 `json:"resource"`
	Action      string                 `json:"action"`
	IsSystem    bool                   `json:"is_system"`
	IsDefault   bool                   `json:"is_default"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

// PermissionListRequest represents a request to list permissions
type PermissionListRequest struct {
	Page      int    `json:"page" validate:"min=1"`
	Limit     int    `json:"limit" validate:"min=1,max=100"`
	Search    string `json:"search,omitempty"`
	Module    string `json:"module,omitempty"`
	Resource  string `json:"resource,omitempty"`
	Action    string `json:"action,omitempty"`
	IsSystem  *bool  `json:"is_system,omitempty"`
	IsDefault *bool  `json:"is_default,omitempty"`
	SortBy    string `json:"sort_by,omitempty" validate:"omitempty,oneof=name code module resource action created_at updated_at"`
	SortOrder string `json:"sort_order,omitempty" validate:"omitempty,oneof=asc desc"`
}

// PermissionListResponse represents a paginated list of permissions
type PermissionListResponse struct {
	Permissions []*PermissionResponse `json:"permissions"`
	Total       int64                 `json:"total"`
	Page        int                   `json:"page"`
	Limit       int                   `json:"limit"`
	TotalPages  int                   `json:"total_pages"`
}

// PermissionGroupResponse represents permissions grouped by module/resource
type PermissionGroupResponse struct {
	Module      string                `json:"module"`
	Resource    string                `json:"resource"`
	Permissions []*PermissionResponse `json:"permissions"`
}

// PermissionModulesResponse represents available modules and their resources
type PermissionModulesResponse struct {
	Modules []PermissionModuleInfo `json:"modules"`
}

// PermissionModuleInfo represents module information
type PermissionModuleInfo struct {
	Name      string                   `json:"name"`
	Resources []PermissionResourceInfo `json:"resources"`
}

// PermissionResourceInfo represents resource information
type PermissionResourceInfo struct {
	Name    string   `json:"name"`
	Actions []string `json:"actions"`
}

// BulkPermissionRequest represents a bulk operation request for permissions
type BulkPermissionRequest struct {
	Action        string               `json:"action" validate:"required,oneof=create delete"`
	PermissionIDs []uuid.UUID          `json:"permission_ids,omitempty"`
	Permissions   []*PermissionRequest `json:"permissions,omitempty"`
}

// BulkPermissionResponse represents a bulk operation response
type BulkPermissionResponse struct {
	Success []uuid.UUID           `json:"success"`
	Failed  []BulkPermissionError `json:"failed"`
	Total   int                   `json:"total"`
}

// BulkPermissionError represents an error in bulk operation
type BulkPermissionError struct {
	PermissionID *uuid.UUID `json:"permission_id,omitempty"`
	Index        *int       `json:"index,omitempty"`
	Error        string     `json:"error"`
}

// PermissionToResponse converts domain.Permission to PermissionResponse
func PermissionToResponse(p *domain.Permission) *PermissionResponse {
	if p == nil {
		return nil
	}

	return &PermissionResponse{
		ID:          p.ID,
		Name:        p.Name,
		Code:        p.Code,
		Description: p.Description,
		Module:      p.Module,
		Resource:    p.Resource,
		Action:      p.Action,
		IsSystem:    p.IsSystem,
		IsDefault:   p.IsDefault,
		Metadata:    p.Metadata,
		CreatedAt:   p.CreatedAt,
		UpdatedAt:   p.UpdatedAt,
	}
}

// PermissionsToResponse converts slice of domain.Permission to slice of PermissionResponse
func PermissionsToResponse(permissions []*domain.Permission) []*PermissionResponse {
	result := make([]*PermissionResponse, len(permissions))
	for i, p := range permissions {
		result[i] = PermissionToResponse(p)
	}
	return result
}
