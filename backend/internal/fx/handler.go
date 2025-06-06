package fx

import (
	"go.uber.org/fx"

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
