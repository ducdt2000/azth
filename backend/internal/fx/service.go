package fx

import (
	"go.uber.org/fx"

	"github.com/ducdt2000/azth/backend/internal/config"
	"github.com/ducdt2000/azth/backend/internal/db"
	authRepo "github.com/ducdt2000/azth/backend/internal/modules/auth/repository"
	authSvc "github.com/ducdt2000/azth/backend/internal/modules/auth/service"
	permissionRepo "github.com/ducdt2000/azth/backend/internal/modules/permission/repository"
	permissionSvc "github.com/ducdt2000/azth/backend/internal/modules/permission/service"
	roleRepo "github.com/ducdt2000/azth/backend/internal/modules/role/repository"
	roleSvc "github.com/ducdt2000/azth/backend/internal/modules/role/service"
	tenantCQRS "github.com/ducdt2000/azth/backend/internal/modules/tenant/cqrs"
	tenantSvc "github.com/ducdt2000/azth/backend/internal/modules/tenant/service"
	userRepo "github.com/ducdt2000/azth/backend/internal/modules/user/repository"
	userSvc "github.com/ducdt2000/azth/backend/internal/modules/user/service"
	"github.com/ducdt2000/azth/backend/pkg/logger"
)

// ServiceModule provides business logic service dependencies
var ServiceModule = fx.Module("services",
	// Core services
	fx.Provide(NewUserService),
	fx.Provide(NewPermissionService),
	fx.Provide(NewRoleService),
	fx.Provide(NewAuthService),

	// CQRS components for tenant service
	fx.Provide(NewTenantEventStore),
	fx.Provide(NewTenantQueryHandler),
	fx.Provide(NewTenantCommandHandler),
	fx.Provide(NewTenantService),
)

// NewUserService creates a new user service
func NewUserService(userRepo userRepo.UserRepository, logger *logger.Logger) userSvc.UserService {
	return userSvc.NewUserService(userRepo, logger)
}

// NewTenantService creates a new tenant service using CQRS
func NewTenantService(
	commandHandler *tenantCQRS.TenantCommandHandler,
	queryHandler tenantCQRS.TenantQueryHandler,
	logger *logger.Logger,
) *tenantSvc.TenantCQRSService {
	return tenantSvc.NewTenantCQRSService(commandHandler, queryHandler, logger)
}

// NewPermissionService creates a new permission service
func NewPermissionService(permissionRepo permissionRepo.PermissionRepository, logger *logger.Logger) permissionSvc.PermissionService {
	return permissionSvc.NewPermissionService(permissionRepo)
}

// NewRoleService creates a new role service
func NewRoleService(
	roleRepo roleRepo.RoleRepository,
	rolePermissionRepo roleRepo.RolePermissionRepository,
	userRoleRepo roleRepo.UserRoleRepository,
	permissionRepo permissionRepo.PermissionRepository,
	logger *logger.Logger,
) roleSvc.RoleService {
	return roleSvc.NewRoleService(roleRepo, rolePermissionRepo, userRoleRepo, permissionRepo, logger)
}

// CQRS Handlers

// NewTenantEventStore creates a new tenant event store
func NewTenantEventStore(db *db.DB, logger *logger.Logger) tenantCQRS.EventStore {
	return tenantCQRS.NewPostgreSQLEventStore(db.DB)
}

// NewTenantQueryHandler creates a placeholder tenant query handler
func NewTenantQueryHandler(db *db.DB, logger *logger.Logger) tenantCQRS.TenantQueryHandler {
	// TODO: Implement proper query handler
	logger.Info("Tenant query handler placeholder created")
	return nil
}

// NewTenantCommandHandler creates a placeholder tenant command handler
func NewTenantCommandHandler(
	eventStore tenantCQRS.EventStore,
	logger *logger.Logger,
) *tenantCQRS.TenantCommandHandler {
	// TODO: Implement proper read model repository
	logger.Info("Tenant command handler placeholder created")
	return tenantCQRS.NewTenantCommandHandler(eventStore, nil, logger)
}

// NewAuthService creates a new authentication service
func NewAuthService(
	userRepo userRepo.UserRepository,
	sessionRepo authRepo.SessionRepository,
	roleService roleSvc.RoleService,
	logger *logger.Logger,
	cfg *config.Config,
) authSvc.AuthService {
	authConfig := &authSvc.AuthConfig{
		JWTSecret:           cfg.JWT.Secret,
		JWTIssuer:           cfg.JWT.Issuer,
		JWTAudience:         cfg.JWT.Audience[0],
		JWTAccessTokenTTL:   cfg.JWT.AccessTokenTTL,
		JWTRefreshTokenTTL:  cfg.JWT.RefreshTokenTTL,
		JWTAlgorithms:       cfg.JWT.Algorithms,
		JWTValidateIssuer:   cfg.JWT.ValidateIssuer,
		JWTValidateIAT:      cfg.JWT.ValidateIAT,
		JWTBlacklistEnabled: cfg.JWT.Blacklist.Enabled,
		Mode:                authSvc.AuthModeStateless,
	}

	return authSvc.NewAuthService(
		userRepo,
		sessionRepo,
		roleService,
		logger,
		authConfig,
		// TODO: Add JWT blacklist service implementation when available
	)
}
