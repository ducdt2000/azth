package fx

import (
	"go.uber.org/fx"

	userRepo "github.com/ducdt2000/azth/backend/internal/modules/user/repository"
	userSvc "github.com/ducdt2000/azth/backend/internal/modules/user/service"
	"github.com/ducdt2000/azth/backend/pkg/logger"
)

// ServiceModule provides business logic service dependencies
var ServiceModule = fx.Module("services",
	fx.Provide(NewUserService),
	// TODO: Add more service providers here
	// fx.Provide(NewTenantService),
	// fx.Provide(NewAuthService),
	// fx.Provide(NewOIDCService),
)

// NewUserService creates a new user service
func NewUserService(userRepo userRepo.UserRepository, logger *logger.Logger) userSvc.UserService {
	return userSvc.NewUserService(userRepo, logger)
}
