package fx

import (
	"go.uber.org/fx"

	"github.com/ducdt2000/azth/backend/internal/db"
	permissionRepo "github.com/ducdt2000/azth/backend/internal/modules/permission/repository"
	roleRepo "github.com/ducdt2000/azth/backend/internal/modules/role/repository"
	tenantRepo "github.com/ducdt2000/azth/backend/internal/modules/tenant/repository"
	userRepo "github.com/ducdt2000/azth/backend/internal/modules/user/repository"
	"github.com/ducdt2000/azth/backend/pkg/logger"
)

// RepositoryModule provides data access layer dependencies
var RepositoryModule = fx.Module("repositories",
	fx.Provide(NewUserRepository),
	fx.Provide(NewTenantRepository),
	fx.Provide(NewRoleRepository),
	fx.Provide(NewPermissionRepository),
	// TODO: Add more repository providers here
	// fx.Provide(NewAuditRepository),
)

// NewUserRepository creates a new user repository
func NewUserRepository(db *db.DB, logger *logger.Logger) userRepo.UserRepository {
	return userRepo.NewPostgresUserRepository(db, logger)
}

// NewTenantRepository creates a placeholder tenant repository
func NewTenantRepository(db *db.DB, logger *logger.Logger) tenantRepo.TenantRepository {
	// TODO: Implement proper tenant repository once the concrete implementation is available
	// For now, return nil since tenant service uses CQRS pattern
	logger.Info("Tenant repository placeholder created (using CQRS)")
	return nil
}

// NewRoleRepository creates a new role repository
func NewRoleRepository(db *db.DB, logger *logger.Logger) roleRepo.RoleRepository {
	return roleRepo.NewRoleRepository(db.DB)
}

// NewPermissionRepository creates a new permission repository
func NewPermissionRepository(db *db.DB, logger *logger.Logger) permissionRepo.PermissionRepository {
	return permissionRepo.NewPermissionRepository(db.DB)
}
