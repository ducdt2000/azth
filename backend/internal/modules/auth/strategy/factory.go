package strategy

import (
	"fmt"

	authRepo "github.com/ducdt2000/azth/backend/internal/modules/auth/repository"
	permRepo "github.com/ducdt2000/azth/backend/internal/modules/permission/repository"
	roleRepo "github.com/ducdt2000/azth/backend/internal/modules/role/repository"
	roleSvc "github.com/ducdt2000/azth/backend/internal/modules/role/service"
	userRepo "github.com/ducdt2000/azth/backend/internal/modules/user/repository"
	"github.com/ducdt2000/azth/backend/pkg/logger"
)

// StrategyFactory creates authentication strategies
type StrategyFactory struct {
	userRepo    userRepo.UserRepository
	sessionRepo authRepo.SessionRepository
	roleRepo    roleRepo.RoleRepository
	permRepo    permRepo.PermissionRepository
	logger      *logger.Logger
}

// NewStrategyFactory creates a new strategy factory
func NewStrategyFactory(
	userRepo userRepo.UserRepository,
	sessionRepo authRepo.SessionRepository,
	roleRepo roleRepo.RoleRepository,
	permRepo permRepo.PermissionRepository,
	logger *logger.Logger,
) *StrategyFactory {
	return &StrategyFactory{
		userRepo:    userRepo,
		sessionRepo: sessionRepo,
		roleRepo:    roleRepo,
		permRepo:    permRepo,
		logger:      logger,
	}
}

// StrategyBuilder helps build authentication strategies with dependencies
type StrategyBuilder struct {
	sessionRepo authRepo.SessionRepository
	userRepo    userRepo.UserRepository
	roleService roleSvc.RoleService
	logger      *logger.Logger
}

// NewStrategyBuilder creates a new strategy builder
func NewStrategyBuilder(
	sessionRepo authRepo.SessionRepository,
	userRepo userRepo.UserRepository,
	roleService roleSvc.RoleService,
	logger *logger.Logger,
) *StrategyBuilder {
	return &StrategyBuilder{
		sessionRepo: sessionRepo,
		userRepo:    userRepo,
		roleService: roleService,
		logger:      logger,
	}
}

// BuildSessionStrategy builds a session-based authentication strategy
func (sb *StrategyBuilder) BuildSessionStrategy(config *SessionConfig) AuthStrategy {
	return NewSessionStrategy(sb.userRepo, sb.sessionRepo, sb.roleService, sb.logger, config)
}

// BuildJWTStrategy builds a JWT-based authentication strategy
func (sb *StrategyBuilder) BuildJWTStrategy(config *JWTConfig) AuthStrategy {
	return NewJWTStrategy(sb.userRepo, sb.roleService, sb.logger, config)
}

// CreateAuthStrategyWithDependencies creates an authentication strategy with injected dependencies
func (sb *StrategyBuilder) CreateAuthStrategyWithDependencies(strategyType StrategyType, config interface{}) (AuthStrategy, error) {
	switch strategyType {
	case StrategyTypeSession:
		sessionConfig, ok := config.(*SessionConfig)
		if !ok && config != nil {
			return nil, fmt.Errorf("invalid config type for session strategy")
		}
		return sb.BuildSessionStrategy(sessionConfig), nil

	case StrategyTypeJWT:
		jwtConfig, ok := config.(*JWTConfig)
		if !ok && config != nil {
			return nil, fmt.Errorf("invalid config type for JWT strategy")
		}
		return sb.BuildJWTStrategy(jwtConfig), nil

	case StrategyTypeOAuth:
		return nil, fmt.Errorf("OAuth strategy not yet implemented")

	case StrategyTypeSAML:
		return nil, fmt.Errorf("SAML strategy not yet implemented")

	default:
		return nil, fmt.Errorf("unknown strategy type: %s", strategyType)
	}
}

// ConfigurableStrategyManager extends the basic strategy management with more features
type ConfigurableStrategyManager struct {
	factory         *AuthStrategyFactory
	builder         *StrategyBuilder
	defaultStrategy AuthStrategy
	strategies      map[string]AuthStrategy
}

// NewConfigurableStrategyManager creates a new configurable strategy manager
func NewConfigurableStrategyManager(factory *AuthStrategyFactory, builder *StrategyBuilder) *ConfigurableStrategyManager {
	return &ConfigurableStrategyManager{
		factory:    factory,
		builder:    builder,
		strategies: make(map[string]AuthStrategy),
	}
}

// SetDefaultStrategy sets the default authentication strategy
func (csm *ConfigurableStrategyManager) SetDefaultStrategy(strategy AuthStrategy) {
	csm.defaultStrategy = strategy
}

// RegisterStrategy registers a named authentication strategy
func (csm *ConfigurableStrategyManager) RegisterStrategy(name string, strategy AuthStrategy) {
	csm.strategies[name] = strategy
}

// GetStrategy returns a strategy by name, or the default strategy if name is empty
func (csm *ConfigurableStrategyManager) GetStrategy(name string) (AuthStrategy, error) {
	if name == "" {
		if csm.defaultStrategy == nil {
			return nil, fmt.Errorf("no default strategy configured")
		}
		return csm.defaultStrategy, nil
	}

	strategy, exists := csm.strategies[name]
	if !exists {
		return nil, fmt.Errorf("strategy not found: %s", name)
	}

	return strategy, nil
}

// GetDefaultStrategy returns the default authentication strategy
func (csm *ConfigurableStrategyManager) GetDefaultStrategy() AuthStrategy {
	return csm.defaultStrategy
}

// ListStrategies returns all registered strategy names
func (csm *ConfigurableStrategyManager) ListStrategies() []string {
	names := make([]string, 0, len(csm.strategies))
	for name := range csm.strategies {
		names = append(names, name)
	}
	return names
}

// CreateTenantAwareStrategy creates a strategy based on tenant configuration
func (csm *ConfigurableStrategyManager) CreateTenantAwareStrategy(tenantID *string) (AuthStrategy, error) {
	// Use the existing factory's tenant-aware logic
	strategy := csm.factory.GetStrategy(nil) // TODO: Convert string to uuid.UUID if needed
	if strategy == nil {
		return nil, fmt.Errorf("no strategy configured for tenant")
	}
	return strategy, nil
}
