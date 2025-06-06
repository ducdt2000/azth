package repository

import (
	"context"

	"github.com/ducdt2000/azth/backend/internal/domain"
	"github.com/ducdt2000/azth/backend/internal/modules/permission/dto"
	"github.com/google/uuid"
)

// PermissionRepository defines the interface for permission data access
type PermissionRepository interface {
	// Create creates a new permission
	Create(ctx context.Context, permission *domain.Permission) error

	// GetByID retrieves a permission by ID
	GetByID(ctx context.Context, id uuid.UUID) (*domain.Permission, error)

	// GetByCode retrieves a permission by code
	GetByCode(ctx context.Context, code string) (*domain.Permission, error)

	// Update updates an existing permission
	Update(ctx context.Context, permission *domain.Permission) error

	// Delete soft deletes a permission
	Delete(ctx context.Context, id uuid.UUID) error

	// List retrieves permissions with filtering and pagination
	List(ctx context.Context, req *dto.PermissionListRequest) ([]*domain.Permission, int64, error)

	// GetByModule retrieves permissions by module
	GetByModule(ctx context.Context, module string) ([]*domain.Permission, error)

	// GetByResource retrieves permissions by module and resource
	GetByResource(ctx context.Context, module, resource string) ([]*domain.Permission, error)

	// GetByAction retrieves permissions by module, resource, and action
	GetByAction(ctx context.Context, module, resource, action string) (*domain.Permission, error)

	// GetDefaultPermissions retrieves all default permissions
	GetDefaultPermissions(ctx context.Context) ([]*domain.Permission, error)

	// GetSystemPermissions retrieves all system permissions
	GetSystemPermissions(ctx context.Context) ([]*domain.Permission, error)

	// GetModules retrieves available modules and their resources
	GetModules(ctx context.Context) (map[string]map[string][]string, error)

	// BulkCreate creates multiple permissions
	BulkCreate(ctx context.Context, permissions []*domain.Permission) error

	// BulkDelete deletes multiple permissions by IDs
	BulkDelete(ctx context.Context, ids []uuid.UUID) error

	// ExistsByCode checks if a permission with the given code exists
	ExistsByCode(ctx context.Context, code string) (bool, error)

	// ExistsByModuleResourceAction checks if a permission exists for the given combination
	ExistsByModuleResourceAction(ctx context.Context, module, resource, action string) (bool, error)

	// GetPermissionsByIDs retrieves permissions by their IDs
	GetPermissionsByIDs(ctx context.Context, ids []uuid.UUID) ([]*domain.Permission, error)
}
