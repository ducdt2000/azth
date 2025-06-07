package repository

import (
	"context"

	"github.com/ducdt2000/azth/backend/internal/domain"
	"github.com/ducdt2000/azth/backend/internal/modules/role/dto"
	"github.com/google/uuid"
)

// RoleRepository defines the interface for role data access
type RoleRepository interface {
	// Role CRUD operations
	Create(ctx context.Context, role *domain.Role) error
	GetByID(ctx context.Context, id uuid.UUID) (*domain.Role, error)
	GetBySlug(ctx context.Context, slug string, tenantID *uuid.UUID) (*domain.Role, error)
	GetByName(ctx context.Context, name string, tenantID *uuid.UUID) (*domain.Role, error)
	Update(ctx context.Context, role *domain.Role) error
	Delete(ctx context.Context, id uuid.UUID) error
	List(ctx context.Context, req *dto.RoleListRequest) ([]*domain.Role, int64, error)

	// Role querying
	GetByTenant(ctx context.Context, tenantID uuid.UUID) ([]*domain.Role, error)
	GetGlobalRoles(ctx context.Context) ([]*domain.Role, error)
	GetSystemRoles(ctx context.Context) ([]*domain.Role, error)
	GetDefaultRoles(ctx context.Context, tenantID *uuid.UUID) ([]*domain.Role, error)
	GetAvailableRolesForTenant(ctx context.Context, tenantID uuid.UUID) ([]*domain.Role, error)

	// Role validation
	ExistsBySlug(ctx context.Context, slug string, tenantID *uuid.UUID) (bool, error)
	ExistsByName(ctx context.Context, name string, tenantID *uuid.UUID) (bool, error)

	// Bulk operations
	BulkCreate(ctx context.Context, roles []*domain.Role) error
	BulkDelete(ctx context.Context, ids []uuid.UUID) error
	GetRolesByIDs(ctx context.Context, ids []uuid.UUID) ([]*domain.Role, error)

	// Role statistics
	GetRoleStats(ctx context.Context, req *dto.RoleStatsRequest) (*dto.RoleStatsResponse, error)
	GetTopRolesByUsage(ctx context.Context, limit int, tenantID *uuid.UUID) ([]*dto.RoleUsageResponse, error)
}

// RolePermissionRepository defines the interface for role-permission relationships
type RolePermissionRepository interface {
	// Role-Permission associations
	AssignPermissions(ctx context.Context, roleID uuid.UUID, permissionIDs []uuid.UUID, createdBy uuid.UUID) error
	RevokePermissions(ctx context.Context, roleID uuid.UUID, permissionIDs []uuid.UUID) error
	ReplacePermissions(ctx context.Context, roleID uuid.UUID, permissionIDs []uuid.UUID, createdBy uuid.UUID) error
	GetRolePermissions(ctx context.Context, roleID uuid.UUID) ([]*domain.Permission, error)
	GetRolesWithPermissions(ctx context.Context, roleIDs []uuid.UUID) (map[uuid.UUID][]*domain.Permission, error)

	// Permission validation
	HasPermission(ctx context.Context, roleID uuid.UUID, permissionID uuid.UUID) (bool, error)
	GetPermissionsByCode(ctx context.Context, roleID uuid.UUID, permissionCodes []string) ([]*domain.Permission, error)

	// Bulk operations
	BulkAssignPermissions(ctx context.Context, assignments []domain.RolePermission) error
	BulkRevokePermissions(ctx context.Context, rolePermissionIDs []uuid.UUID) error
}

// UserRoleRepository defines the interface for user-role relationships
type UserRoleRepository interface {
	// User-Role associations
	AssignRole(ctx context.Context, userRole *domain.UserRole) error
	RevokeRole(ctx context.Context, userID, roleID, tenantID uuid.UUID) error
	GetUserRoles(ctx context.Context, userID, tenantID uuid.UUID) ([]*domain.UserRole, error)
	GetUserRolesByUser(ctx context.Context, userID uuid.UUID) ([]*domain.UserRole, error)
	GetRoleUsers(ctx context.Context, roleID uuid.UUID) ([]*domain.UserRole, error)

	// Role validation for users
	HasRole(ctx context.Context, userID, roleID, tenantID uuid.UUID) (bool, error)
	HasAnyRole(ctx context.Context, userID uuid.UUID, roleIDs []uuid.UUID, tenantID uuid.UUID) (bool, error)
	GetUserPermissions(ctx context.Context, userID, tenantID uuid.UUID) ([]*domain.Permission, error)

	// Bulk operations
	BulkAssignRoles(ctx context.Context, userRoles []*domain.UserRole) error
	BulkRevokeRoles(ctx context.Context, userRoleIDs []uuid.UUID) error
	BulkRevokeUserRoles(ctx context.Context, userID uuid.UUID, tenantID *uuid.UUID) error

	// User role statistics
	GetUserRoleCount(ctx context.Context, userID uuid.UUID, tenantID *uuid.UUID) (int64, error)
	GetRoleUserCount(ctx context.Context, roleID uuid.UUID) (int64, error)
}
