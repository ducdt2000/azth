package fx

import (
	"go.uber.org/fx"

	authHandlers "github.com/ducdt2000/azth/backend/internal/modules/auth/handlers"
	authSvc "github.com/ducdt2000/azth/backend/internal/modules/auth/service"
	permissionHandlers "github.com/ducdt2000/azth/backend/internal/modules/permission/handlers"
	permissionSvc "github.com/ducdt2000/azth/backend/internal/modules/permission/service"
	roleHandlers "github.com/ducdt2000/azth/backend/internal/modules/role/handlers"
	roleSvc "github.com/ducdt2000/azth/backend/internal/modules/role/service"
	tenantHandlers "github.com/ducdt2000/azth/backend/internal/modules/tenant/handlers"
	tenantSvc "github.com/ducdt2000/azth/backend/internal/modules/tenant/service"
	userHandlers "github.com/ducdt2000/azth/backend/internal/modules/user/handlers"
	userSvc "github.com/ducdt2000/azth/backend/internal/modules/user/service"
	"github.com/ducdt2000/azth/backend/pkg/logger"
	"github.com/ducdt2000/azth/backend/pkg/response"
	"github.com/ducdt2000/azth/backend/pkg/validator"
)

// HandlerModule provides HTTP handler dependencies
var HandlerModule = fx.Module("handlers",
	fx.Provide(NewUserHandler),
	fx.Provide(NewTenantHandler),
	fx.Provide(NewRoleHandler),
	fx.Provide(NewPermissionHandler),
	fx.Provide(NewAuthHandler),
	// TODO: Add more handler providers here
	// fx.Provide(NewOIDCHandler),
)

// NewUserHandler creates a new user handler
func NewUserHandler(userService userSvc.UserService, logger *logger.Logger, responseBuilder *response.ResponseBuilder) *userHandlers.UserHandlerV2 {
	return userHandlers.NewUserHandlerV2(userService, logger, responseBuilder)
}

// NewTenantHandler creates a new tenant handler
func NewTenantHandler(tenantService *tenantSvc.TenantCQRSService, logger *logger.Logger, responseBuilder *response.ResponseBuilder) *tenantHandlers.TenantHandler {
	return tenantHandlers.NewTenantHandler(tenantService, logger, responseBuilder)
}

// NewRoleHandler creates a new role handler
func NewRoleHandler(roleService roleSvc.RoleService, logger *logger.Logger, responseBuilder *response.ResponseBuilder) *roleHandlers.RoleHandler {
	return roleHandlers.NewRoleHandler(roleService, logger, responseBuilder)
}

// NewPermissionHandler creates a new permission handler
func NewPermissionHandler(permissionService permissionSvc.PermissionService, logger *logger.Logger, responseBuilder *response.ResponseBuilder) *permissionHandlers.PermissionHandler {
	return permissionHandlers.NewPermissionHandler(permissionService, logger, responseBuilder)
}

// NewAuthHandler creates a new authentication handler
func NewAuthHandler(authService authSvc.AuthService, validator *validator.CustomValidator, responseBuilder *response.ResponseBuilder) *authHandlers.AuthHandler {
	return authHandlers.NewAuthHandler(authService, validator, responseBuilder)
}
