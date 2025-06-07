package fx

import (
	"go.uber.org/fx"

	permissionHandlers "github.com/ducdt2000/azth/backend/internal/modules/permission/handlers"
	permissionSvc "github.com/ducdt2000/azth/backend/internal/modules/permission/service"
	roleHandlers "github.com/ducdt2000/azth/backend/internal/modules/role/handlers"
	roleSvc "github.com/ducdt2000/azth/backend/internal/modules/role/service"
	tenantHandlers "github.com/ducdt2000/azth/backend/internal/modules/tenant/handlers"
	tenantSvc "github.com/ducdt2000/azth/backend/internal/modules/tenant/service"
	userHandlers "github.com/ducdt2000/azth/backend/internal/modules/user/handlers"
	userSvc "github.com/ducdt2000/azth/backend/internal/modules/user/service"
	"github.com/ducdt2000/azth/backend/pkg/logger"
)

// HandlerModule provides HTTP handler dependencies
var HandlerModule = fx.Module("handlers",
	fx.Provide(NewUserHandler),
	fx.Provide(NewTenantHandler),
	fx.Provide(NewRoleHandler),
	fx.Provide(NewPermissionHandler),
	// TODO: Add more handler providers here
	// fx.Provide(NewAuthHandler),
	// fx.Provide(NewOIDCHandler),
)

// NewUserHandler creates a new user handler
func NewUserHandler(userService userSvc.UserService, logger *logger.Logger) *userHandlers.UserHandler {
	return userHandlers.NewUserHandler(userService, logger)
}

// NewTenantHandler creates a new tenant handler
func NewTenantHandler(tenantService *tenantSvc.TenantCQRSService, logger *logger.Logger) *tenantHandlers.TenantHandler {
	return tenantHandlers.NewTenantHandler(tenantService, logger)
}

// NewRoleHandler creates a new role handler
func NewRoleHandler(roleService roleSvc.RoleService, logger *logger.Logger) *roleHandlers.RoleHandler {
	return roleHandlers.NewRoleHandler(roleService, logger)
}

// NewPermissionHandler creates a new permission handler
func NewPermissionHandler(permissionService permissionSvc.PermissionService, logger *logger.Logger) *permissionHandlers.PermissionHandler {
	return permissionHandlers.NewPermissionHandler(permissionService, logger)
}
