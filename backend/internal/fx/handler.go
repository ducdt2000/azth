package fx

import (
	"go.uber.org/fx"

	userHandlers "github.com/ducdt2000/azth/backend/internal/modules/user/handlers"
	userSvc "github.com/ducdt2000/azth/backend/internal/modules/user/service"
	"github.com/ducdt2000/azth/backend/pkg/logger"
)

// HandlerModule provides HTTP handler dependencies
var HandlerModule = fx.Module("handlers",
	fx.Provide(NewUserHandler),
	// TODO: Add more handler providers here
	// fx.Provide(NewTenantHandler),
	// fx.Provide(NewAuthHandler),
	// fx.Provide(NewOIDCHandler),
)

// NewUserHandler creates a new user handler
func NewUserHandler(userService userSvc.UserService, logger *logger.Logger) *userHandlers.UserHandler {
	return userHandlers.NewUserHandler(userService, logger)
}
