package service

import (
	"context"

	permissionDto "github.com/ducdt2000/azth/backend/internal/modules/permission/dto"
	"github.com/ducdt2000/azth/backend/internal/modules/role/dto"
	"github.com/google/uuid"
)

// RoleService defines the interface for role business logic
type RoleService interface {
	// Role CRUD operations
	CreateRole(ctx context.Context, req *dto.RoleRequest, tenantID *uuid.UUID, createdBy uuid.UUID) (*dto.RoleResponse, error)
	GetRole(ctx context.Context, id uuid.UUID) (*dto.RoleResponse, error)
	GetRoleBySlug(ctx context.Context, slug string, tenantID *uuid.UUID) (*dto.RoleResponse, error)
	UpdateRole(ctx context.Context, id uuid.UUID, req *dto.UpdateRoleRequest, updatedBy uuid.UUID) (*dto.RoleResponse, error)
	DeleteRole(ctx context.Context, id uuid.UUID) error
	ListRoles(ctx context.Context, req *dto.RoleListRequest) (*dto.RoleListResponse, error)

	// Role querying
	GetRolesByTenant(ctx context.Context, tenantID uuid.UUID) ([]*dto.RoleResponse, error)
	GetGlobalRoles(ctx context.Context) ([]*dto.RoleResponse, error)
	GetSystemRoles(ctx context.Context) ([]*dto.RoleResponse, error)
	GetDefaultRoles(ctx context.Context, tenantID *uuid.UUID) (*dto.DefaultRoleResponse, error)
	GetAvailableRolesForTenant(ctx context.Context, tenantID uuid.UUID) ([]*dto.RoleResponse, error)

	// Role permissions management
	AssignPermissions(ctx context.Context, roleID uuid.UUID, req *dto.RolePermissionRequest, assignedBy uuid.UUID) (*dto.RolePermissionResponse, error)
	RevokePermissions(ctx context.Context, roleID uuid.UUID, req *dto.RolePermissionRequest) error
	ReplacePermissions(ctx context.Context, roleID uuid.UUID, req *dto.RolePermissionRequest, assignedBy uuid.UUID) (*dto.RolePermissionResponse, error)
	GetRolePermissions(ctx context.Context, roleID uuid.UUID) (*dto.RolePermissionResponse, error)

	// User role management
	AssignRoleToUser(ctx context.Context, roleID uuid.UUID, req *dto.AssignRoleRequest, assignedBy uuid.UUID) (*dto.UserRoleResponse, error)
	RevokeRoleFromUser(ctx context.Context, roleID uuid.UUID, req *dto.RevokeRoleRequest) error
	GetUserRoles(ctx context.Context, userID, tenantID uuid.UUID) ([]*dto.UserRoleResponse, error)
	GetUserRolesByUser(ctx context.Context, userID uuid.UUID) ([]*dto.UserRoleResponse, error)
	GetRoleUsers(ctx context.Context, roleID uuid.UUID) ([]*dto.UserRoleResponse, error)

	// Role validation
	ValidateRoleSlug(ctx context.Context, slug string, tenantID *uuid.UUID) error
	ValidateRoleName(ctx context.Context, name string, tenantID *uuid.UUID) error
	HasRole(ctx context.Context, userID, roleID, tenantID uuid.UUID) (bool, error)
	HasAnyRole(ctx context.Context, userID uuid.UUID, roleIDs []uuid.UUID, tenantID uuid.UUID) (bool, error)
	GetUserPermissions(ctx context.Context, userID, tenantID uuid.UUID) ([]*permissionDto.PermissionResponse, error)

	// Bulk operations
	BulkCreateRoles(ctx context.Context, req *dto.BulkRoleRequest, tenantID *uuid.UUID, createdBy uuid.UUID) (*dto.BulkRoleResponse, error)
	BulkDeleteRoles(ctx context.Context, req *dto.BulkRoleRequest) (*dto.BulkRoleResponse, error)
	BulkAssignRoles(ctx context.Context, req *dto.BulkRoleRequest, assignedBy uuid.UUID) (*dto.BulkRoleResponse, error)
	BulkRevokeRoles(ctx context.Context, req *dto.BulkRoleRequest) (*dto.BulkRoleResponse, error)

	// Role statistics and analytics
	GetRoleStats(ctx context.Context, req *dto.RoleStatsRequest) (*dto.RoleStatsResponse, error)
	GetTopRolesByUsage(ctx context.Context, limit int, tenantID *uuid.UUID) ([]*dto.RoleUsageResponse, error)

	// Default roles management
	InitializeDefaultRoles(ctx context.Context, tenantID *uuid.UUID, createdBy uuid.UUID) error
	AssignDefaultRolesToUser(ctx context.Context, userID, tenantID uuid.UUID, assignedBy uuid.UUID) error
}
