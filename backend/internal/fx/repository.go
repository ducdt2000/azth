package fx

import (
	"go.uber.org/fx"

	"github.com/ducdt2000/azth/backend/internal/db"
	userRepo "github.com/ducdt2000/azth/backend/internal/modules/user/repository"
	"github.com/ducdt2000/azth/backend/pkg/logger"
)

// RepositoryModule provides data access layer dependencies
var RepositoryModule = fx.Module("repositories",
	fx.Provide(NewUserRepository),
	// TODO: Add more repository providers here
	// fx.Provide(NewTenantRepository),
	// fx.Provide(NewAuditRepository),
)

// NewUserRepository creates a new user repository
func NewUserRepository(db *db.DB, logger *logger.Logger) userRepo.UserRepository {
	return userRepo.NewPostgresUserRepository(db, logger)
}
