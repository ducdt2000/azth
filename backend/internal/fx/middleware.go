package fx

import (
	"go.uber.org/fx"

	"github.com/ducdt2000/azth/backend/internal/kv"
	authSvc "github.com/ducdt2000/azth/backend/internal/modules/auth/service"
	roleSvc "github.com/ducdt2000/azth/backend/internal/modules/role/service"
	"github.com/ducdt2000/azth/backend/pkg/logger"
	"github.com/ducdt2000/azth/backend/pkg/middleware"
)

// MiddlewareModule provides middleware dependencies
var MiddlewareModule = fx.Module("middleware",
	fx.Provide(NewAuthMiddleware),
	fx.Provide(NewEnhancedAuthMiddleware),
	fx.Provide(NewRBACMiddleware),
	fx.Provide(NewAuthorizationMiddleware),
	fx.Provide(NewAuthHelpers),
)

// NewAuthMiddleware creates a new authentication middleware
func NewAuthMiddleware(authService authSvc.AuthService, logger *logger.Logger) *middleware.AuthMiddleware {
	return middleware.NewAuthMiddleware(authService, logger)
}

// NewEnhancedAuthMiddleware creates a new enhanced authentication middleware
func NewEnhancedAuthMiddleware(
	authService authSvc.AuthService,
	roleService roleSvc.RoleService,
	kvStore kv.KVStore,
	logger *logger.Logger,
) *middleware.EnhancedAuthMiddleware {
	return middleware.NewEnhancedAuthMiddleware(authService, roleService, kvStore, logger)
}

// NewRBACMiddleware creates a new RBAC middleware
func NewRBACMiddleware(roleService roleSvc.RoleService, logger *logger.Logger) *middleware.RBACMiddleware {
	return middleware.NewRBACMiddleware(roleService, logger)
}

// NewAuthorizationMiddleware creates a new authorization middleware
func NewAuthorizationMiddleware() *middleware.AuthorizationMiddleware {
	return middleware.NewAuthorizationMiddleware(nil) // ResourceOwnership can be injected later if needed
}

// NewAuthHelpers creates a new auth helpers instance
func NewAuthHelpers(enhancedAuth *middleware.EnhancedAuthMiddleware) *middleware.AuthHelpers {
	return middleware.NewAuthHelpers(enhancedAuth)
}
