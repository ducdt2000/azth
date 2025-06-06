package service

import (
	"context"

	"github.com/ducdt2000/azth/backend/internal/modules/permission/dto"
	"github.com/google/uuid"
)

// PermissionService defines the interface for permission business logic
type PermissionService interface {
	// CreatePermission creates a new permission with validation and business rules
	CreatePermission(ctx context.Context, req *dto.PermissionRequest) (*dto.PermissionResponse, error)

	// GetPermission retrieves a permission by ID
	GetPermission(ctx context.Context, id uuid.UUID) (*dto.PermissionResponse, error)

	// GetPermissionByCode retrieves a permission by code
	GetPermissionByCode(ctx context.Context, code string) (*dto.PermissionResponse, error)

	// UpdatePermission updates an existing permission with validation
	UpdatePermission(ctx context.Context, id uuid.UUID, req *dto.UpdatePermissionRequest) (*dto.PermissionResponse, error)

	// DeletePermission soft deletes a permission
	DeletePermission(ctx context.Context, id uuid.UUID) error

	// ListPermissions retrieves permissions with filtering and pagination
	ListPermissions(ctx context.Context, req *dto.PermissionListRequest) (*dto.PermissionListResponse, error)

	// GetPermissionsByModule retrieves permissions by module
	GetPermissionsByModule(ctx context.Context, module string) ([]*dto.PermissionResponse, error)

	// GetPermissionsByResource retrieves permissions by module and resource
	GetPermissionsByResource(ctx context.Context, module, resource string) ([]*dto.PermissionResponse, error)

	// GetPermissionByAction retrieves permission by module, resource, and action
	GetPermissionByAction(ctx context.Context, module, resource, action string) (*dto.PermissionResponse, error)

	// GetDefaultPermissions retrieves all default permissions
	GetDefaultPermissions(ctx context.Context) ([]*dto.PermissionResponse, error)

	// GetSystemPermissions retrieves all system permissions
	GetSystemPermissions(ctx context.Context) ([]*dto.PermissionResponse, error)

	// GetPermissionModules retrieves available modules and their resources
	GetPermissionModules(ctx context.Context) (*dto.PermissionModulesResponse, error)

	// GetPermissionsGrouped retrieves permissions grouped by module and resource
	GetPermissionsGrouped(ctx context.Context) ([]*dto.PermissionGroupResponse, error)

	// BulkCreatePermissions creates multiple permissions in bulk
	BulkCreatePermissions(ctx context.Context, req *dto.BulkPermissionRequest) (*dto.BulkPermissionResponse, error)

	// BulkDeletePermissions deletes multiple permissions in bulk
	BulkDeletePermissions(ctx context.Context, req *dto.BulkPermissionRequest) (*dto.BulkPermissionResponse, error)

	// InitializeDefaultPermissions creates default system permissions if they don't exist
	InitializeDefaultPermissions(ctx context.Context) error

	// ValidatePermissionCode validates if a permission code is valid and available
	ValidatePermissionCode(ctx context.Context, code string) error

	// ValidateModuleResourceAction validates if the module/resource/action combination is valid
	ValidateModuleResourceAction(ctx context.Context, module, resource, action string) error
}
