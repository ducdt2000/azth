package fx

import (
	"go.uber.org/fx"

	"github.com/ducdt2000/azth/backend/internal/config"
	permissionHandlers "github.com/ducdt2000/azth/backend/internal/modules/permission/handlers"
	roleHandlers "github.com/ducdt2000/azth/backend/internal/modules/role/handlers"
	tenantHandlers "github.com/ducdt2000/azth/backend/internal/modules/tenant/handlers"
	userHandlers "github.com/ducdt2000/azth/backend/internal/modules/user/handlers"
	"github.com/ducdt2000/azth/backend/internal/server"
	"github.com/ducdt2000/azth/backend/pkg/logger"
)

// ServerModule provides server dependencies
var ServerModule = fx.Module("server",
	fx.Provide(NewRouter),
	fx.Provide(NewServer),
)

// NewRouter creates a new router with injected handlers
func NewRouter(
	userHandler *userHandlers.UserHandler,
	tenantHandler *tenantHandlers.TenantHandler,
	roleHandler *roleHandlers.RoleHandler,
	permissionHandler *permissionHandlers.PermissionHandler,
	logger *logger.Logger,
) *server.Router {
	return server.NewRouter(userHandler, tenantHandler, roleHandler, permissionHandler, logger)
}

// NewServer creates a new HTTP server instance
func NewServer(
	cfg *config.Config,
	router *server.Router,
	logger *logger.Logger,
) *server.Server {
	return server.New(cfg.Server, router, logger)
}
