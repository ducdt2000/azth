package service

import (
	"context"
	"fmt"
	"time"

	"github.com/ducdt2000/azth/backend/internal/domain"
	"github.com/ducdt2000/azth/backend/internal/modules/tenant/cqrs"
	"github.com/ducdt2000/azth/backend/internal/modules/tenant/dto"
	"github.com/ducdt2000/azth/backend/pkg/logger"
	"github.com/google/uuid"
)

// TenantCQRSService implements the TenantService interface using CQRS pattern
type TenantCQRSService struct {
	commandHandler *cqrs.TenantCommandHandler
	queryHandler   cqrs.TenantQueryHandler
	logger         *logger.Logger
}

// NewTenantCQRSService creates a new CQRS-based tenant service
func NewTenantCQRSService(
	commandHandler *cqrs.TenantCommandHandler,
	queryHandler cqrs.TenantQueryHandler,
	logger *logger.Logger,
) *TenantCQRSService {
	return &TenantCQRSService{
		commandHandler: commandHandler,
		queryHandler:   queryHandler,
		logger:         logger,
	}
}

// CreateTenant creates a new tenant with validation and business rules
func (s *TenantCQRSService) CreateTenant(ctx context.Context, req *dto.CreateTenantRequest) (*dto.TenantResponse, error) {
	tenantID := uuid.New()
	userID := s.getUserIDFromContext(ctx)

	// Create command
	cmd := cqrs.NewCreateTenantCommand(tenantID, userID, req.Name, req.Slug, req.Plan, req.MaxUsers)
	cmd.Domain = req.Domain
	cmd.LogoURL = req.LogoURL
	cmd.PrimaryColor = req.PrimaryColor
	cmd.SecondaryColor = req.SecondaryColor
	cmd.Settings = req.Settings
	cmd.Metadata = req.Metadata

	// Execute command
	_, err := s.commandHandler.HandleCreateTenant(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to create tenant: %w", err)
	}

	// Query the created tenant
	query := cqrs.NewGetTenantQuery(userID, tenantID)
	tenant, err := s.queryHandler.HandleGetTenant(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve created tenant: %w", err)
	}

	return tenant, nil
}

// GetTenant retrieves a tenant by ID
func (s *TenantCQRSService) GetTenant(ctx context.Context, id uuid.UUID) (*dto.TenantResponse, error) {
	userID := s.getUserIDFromContext(ctx)
	query := cqrs.NewGetTenantQuery(userID, id)
	return s.queryHandler.HandleGetTenant(ctx, query)
}

// GetTenantBySlug retrieves a tenant by slug
func (s *TenantCQRSService) GetTenantBySlug(ctx context.Context, slug string) (*dto.TenantResponse, error) {
	userID := s.getUserIDFromContext(ctx)
	query := cqrs.NewGetTenantBySlugQuery(userID, slug)
	return s.queryHandler.HandleGetTenantBySlug(ctx, query)
}

// GetTenantByDomain retrieves a tenant by domain
func (s *TenantCQRSService) GetTenantByDomain(ctx context.Context, domain string) (*dto.TenantResponse, error) {
	userID := s.getUserIDFromContext(ctx)
	query := cqrs.NewGetTenantByDomainQuery(userID, domain)
	return s.queryHandler.HandleGetTenantByDomain(ctx, query)
}

// UpdateTenant updates an existing tenant with validation
func (s *TenantCQRSService) UpdateTenant(ctx context.Context, id uuid.UUID, req *dto.UpdateTenantRequest) (*dto.TenantResponse, error) {
	userID := s.getUserIDFromContext(ctx)

	// Create command
	cmd := cqrs.NewUpdateTenantCommand(id, userID)
	cmd.Name = req.Name
	cmd.Domain = req.Domain
	cmd.LogoURL = req.LogoURL
	cmd.PrimaryColor = req.PrimaryColor
	cmd.SecondaryColor = req.SecondaryColor
	if req.Status != nil {
		status := domain.TenantStatus(*req.Status)
		cmd.Status = &status
	}
	cmd.Plan = req.Plan
	cmd.MaxUsers = req.MaxUsers
	cmd.Settings = req.Settings
	cmd.Metadata = req.Metadata

	// Execute command
	_, err := s.commandHandler.HandleUpdateTenant(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to update tenant: %w", err)
	}

	// Query updated tenant
	query := cqrs.NewGetTenantQuery(userID, id)
	tenant, err := s.queryHandler.HandleGetTenant(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve updated tenant: %w", err)
	}

	return tenant, nil
}

// DeleteTenant soft deletes a tenant and handles cleanup
func (s *TenantCQRSService) DeleteTenant(ctx context.Context, id uuid.UUID) error {
	userID := s.getUserIDFromContext(ctx)
	cmd := cqrs.NewDeleteTenantCommand(id, userID, "Deleted via API")

	_, err := s.commandHandler.HandleDeleteTenant(ctx, cmd)
	if err != nil {
		return fmt.Errorf("failed to delete tenant: %w", err)
	}

	return nil
}

// ListTenants retrieves tenants with pagination and filtering
func (s *TenantCQRSService) ListTenants(ctx context.Context, req *dto.TenantListRequest) (*dto.TenantListResponse, error) {
	userID := s.getUserIDFromContext(ctx)
	query := cqrs.NewListTenantsQuery(userID, req)
	return s.queryHandler.HandleListTenants(ctx, query)
}

// GetTenantStats retrieves tenant statistics
func (s *TenantCQRSService) GetTenantStats(ctx context.Context, req *dto.TenantStatsRequest) (*dto.TenantStatsResponse, error) {
	userID := s.getUserIDFromContext(ctx)
	query := cqrs.NewGetTenantStatsQuery(userID, req)
	return s.queryHandler.HandleGetTenantStats(ctx, query)
}

// GetTenantUserStats retrieves user statistics for a specific tenant
func (s *TenantCQRSService) GetTenantUserStats(ctx context.Context, tenantID uuid.UUID) (*dto.TenantUserStatsResponse, error) {
	userID := s.getUserIDFromContext(ctx)
	query := &cqrs.GetTenantUserStatsQuery{
		BaseQuery: cqrs.BaseQuery{
			QueryType: cqrs.GetTenantUserStatsQueryType,
			Timestamp: time.Now(),
			UserID:    userID,
			TenantID:  tenantID,
		},
		TenantID: tenantID,
	}
	return s.queryHandler.HandleGetTenantUserStats(ctx, query)
}

// BulkUpdateTenants performs bulk operations on tenants
func (s *TenantCQRSService) BulkUpdateTenants(ctx context.Context, req *dto.BulkTenantRequest) (*dto.BulkOperationResponse, error) {
	userID := s.getUserIDFromContext(ctx)
	results := make([]*dto.BulkOperationResult, 0, len(req.TenantIDs))

	for _, tenantID := range req.TenantIDs {
		result := &dto.BulkOperationResult{
			TenantID: tenantID,
			Success:  false,
		}

		var cmd cqrs.Command
		switch req.Action {
		case "activate":
			cmd = cqrs.NewActivateTenantCommand(tenantID, userID, "Bulk activation")
		case "deactivate":
			cmd = cqrs.NewDeactivateTenantCommand(tenantID, userID, "Bulk deactivation")
		case "suspend":
			cmd = cqrs.NewSuspendTenantCommand(tenantID, userID, "Bulk suspension")
		case "delete":
			cmd = cqrs.NewDeleteTenantCommand(tenantID, userID, "Bulk deletion")
		default:
			result.Error = "Unknown action: " + req.Action
			results = append(results, result)
			continue
		}

		_, err := s.commandHandler.Handle(ctx, cmd)
		if err != nil {
			result.Error = err.Error()
		} else {
			result.Success = true
		}

		results = append(results, result)
	}

	successCount := 0
	for _, result := range results {
		if result.Success {
			successCount++
		}
	}

	return &dto.BulkOperationResponse{
		TotalProcessed: len(req.TenantIDs),
		SuccessCount:   successCount,
		ErrorCount:     len(req.TenantIDs) - successCount,
		Results:        results,
	}, nil
}

// ActivateTenant activates a tenant and all related services
func (s *TenantCQRSService) ActivateTenant(ctx context.Context, tenantID uuid.UUID) error {
	userID := s.getUserIDFromContext(ctx)
	cmd := cqrs.NewActivateTenantCommand(tenantID, userID, "Activated via API")

	_, err := s.commandHandler.HandleActivateTenant(ctx, cmd)
	if err != nil {
		return fmt.Errorf("failed to activate tenant: %w", err)
	}

	return nil
}

// DeactivateTenant deactivates a tenant and suspends services
func (s *TenantCQRSService) DeactivateTenant(ctx context.Context, tenantID uuid.UUID) error {
	userID := s.getUserIDFromContext(ctx)
	cmd := cqrs.NewDeactivateTenantCommand(tenantID, userID, "Deactivated via API")

	_, err := s.commandHandler.HandleDeactivateTenant(ctx, cmd)
	if err != nil {
		return fmt.Errorf("failed to deactivate tenant: %w", err)
	}

	return nil
}

// SuspendTenant suspends a tenant and blocks access
func (s *TenantCQRSService) SuspendTenant(ctx context.Context, tenantID uuid.UUID) error {
	userID := s.getUserIDFromContext(ctx)
	cmd := cqrs.NewSuspendTenantCommand(tenantID, userID, "Suspended via API")

	_, err := s.commandHandler.HandleSuspendTenant(ctx, cmd)
	if err != nil {
		return fmt.Errorf("failed to suspend tenant: %w", err)
	}

	return nil
}

// UpgradePlan upgrades a tenant's subscription plan
func (s *TenantCQRSService) UpgradePlan(ctx context.Context, tenantID uuid.UUID, plan string, maxUsers int) (*dto.TenantResponse, error) {
	// First get current tenant to determine old plan
	currentTenant, err := s.GetTenant(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get current tenant: %w", err)
	}

	userID := s.getUserIDFromContext(ctx)
	cmd := cqrs.NewChangeTenantPlanCommand(
		tenantID, userID,
		plan, currentTenant.Plan,
		maxUsers, currentTenant.MaxUsers,
		"Plan upgraded via API",
	)

	_, err = s.commandHandler.HandleChangeTenantPlan(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to upgrade plan: %w", err)
	}

	// Return updated tenant
	return s.GetTenant(ctx, tenantID)
}

// DowngradePlan downgrades a tenant's subscription plan
func (s *TenantCQRSService) DowngradePlan(ctx context.Context, tenantID uuid.UUID, plan string, maxUsers int) (*dto.TenantResponse, error) {
	// First get current tenant to determine old plan
	currentTenant, err := s.GetTenant(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get current tenant: %w", err)
	}

	userID := s.getUserIDFromContext(ctx)
	cmd := cqrs.NewChangeTenantPlanCommand(
		tenantID, userID,
		plan, currentTenant.Plan,
		maxUsers, currentTenant.MaxUsers,
		"Plan downgraded via API",
	)

	_, err = s.commandHandler.HandleChangeTenantPlan(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to downgrade plan: %w", err)
	}

	// Return updated tenant
	return s.GetTenant(ctx, tenantID)
}

// UpdateTenantSettings updates tenant configuration settings
func (s *TenantCQRSService) UpdateTenantSettings(ctx context.Context, tenantID uuid.UUID, settings map[string]interface{}) (*dto.TenantResponse, error) {
	userID := s.getUserIDFromContext(ctx)
	cmd := &cqrs.UpdateTenantSettingsCommand{
		BaseCommand: cqrs.BaseCommand{
			AggregateID: tenantID,
			CommandType: cqrs.UpdateTenantSettingsCommandType,
			Timestamp:   time.Now(),
			UserID:      userID,
			TenantID:    tenantID,
		},
		Settings: settings,
	}

	_, err := s.commandHandler.HandleUpdateTenantSettings(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to update tenant settings: %w", err)
	}

	// Return updated tenant
	return s.GetTenant(ctx, tenantID)
}

// UpdateTenantMetadata updates tenant metadata
func (s *TenantCQRSService) UpdateTenantMetadata(ctx context.Context, tenantID uuid.UUID, metadata map[string]interface{}) (*dto.TenantResponse, error) {
	userID := s.getUserIDFromContext(ctx)
	cmd := &cqrs.UpdateTenantMetadataCommand{
		BaseCommand: cqrs.BaseCommand{
			AggregateID: tenantID,
			CommandType: cqrs.UpdateTenantMetadataCommandType,
			Timestamp:   time.Now(),
			UserID:      userID,
			TenantID:    tenantID,
		},
		Metadata: metadata,
	}

	_, err := s.commandHandler.HandleUpdateTenantMetadata(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to update tenant metadata: %w", err)
	}

	// Return updated tenant
	return s.GetTenant(ctx, tenantID)
}

// ValidateTenantAccess validates if a tenant can be accessed
func (s *TenantCQRSService) ValidateTenantAccess(ctx context.Context, tenantID uuid.UUID) error {
	userID := s.getUserIDFromContext(ctx)
	query := &cqrs.ValidateTenantAccessQuery{
		BaseQuery: cqrs.BaseQuery{
			QueryType: cqrs.ValidateTenantAccessQueryType,
			Timestamp: time.Now(),
			UserID:    userID,
			TenantID:  tenantID,
		},
		TenantID: tenantID,
	}
	return s.queryHandler.HandleValidateTenantAccess(ctx, query)
}

// CheckUserLimit checks if tenant has reached user limit
func (s *TenantCQRSService) CheckUserLimit(ctx context.Context, tenantID uuid.UUID) (bool, error) {
	userID := s.getUserIDFromContext(ctx)
	query := &cqrs.CheckUserLimitQuery{
		BaseQuery: cqrs.BaseQuery{
			QueryType: cqrs.CheckUserLimitQueryType,
			Timestamp: time.Now(),
			UserID:    userID,
			TenantID:  tenantID,
		},
		TenantID: tenantID,
	}
	return s.queryHandler.HandleCheckUserLimit(ctx, query)
}

// Remaining interface methods that need query handler implementation

// GetTenantUsers retrieves users for a specific tenant
func (s *TenantCQRSService) GetTenantUsers(ctx context.Context, tenantID uuid.UUID, req *dto.TenantUserRequest) (*dto.TenantListResponse, error) {
	userID := s.getUserIDFromContext(ctx)
	query := &cqrs.GetTenantUsersQuery{
		BaseQuery: cqrs.BaseQuery{
			QueryType: cqrs.GetTenantUsersQueryType,
			Timestamp: time.Now(),
			UserID:    userID,
			TenantID:  tenantID,
		},
		TenantID: tenantID,
		Page:     req.Page,
		Limit:    req.Limit,
		Sort:     req.Sort,
		Order:    req.Order,
		Search:   req.Search,
		Status:   &req.Status,
	}
	return s.queryHandler.HandleGetTenantUsers(ctx, query)
}

// GetTenantsByPlan retrieves tenants by subscription plan
func (s *TenantCQRSService) GetTenantsByPlan(ctx context.Context, plan string) ([]*dto.TenantResponse, error) {
	userID := s.getUserIDFromContext(ctx)
	query := &cqrs.GetTenantsByPlanQuery{
		BaseQuery: cqrs.BaseQuery{
			QueryType: cqrs.GetTenantsByPlanQueryType,
			Timestamp: time.Now(),
			UserID:    userID,
		},
		Plan: plan,
	}
	return s.queryHandler.HandleGetTenantsByPlan(ctx, query)
}

// GetTenantsByStatus retrieves tenants by status
func (s *TenantCQRSService) GetTenantsByStatus(ctx context.Context, status domain.TenantStatus) ([]*dto.TenantResponse, error) {
	userID := s.getUserIDFromContext(ctx)
	query := &cqrs.GetTenantsByStatusQuery{
		BaseQuery: cqrs.BaseQuery{
			QueryType: cqrs.GetTenantsByStatusQueryType,
			Timestamp: time.Now(),
			UserID:    userID,
		},
		Status: status,
	}
	return s.queryHandler.HandleGetTenantsByStatus(ctx, query)
}

// HandleTrialExpiration handles expired trial tenants
func (s *TenantCQRSService) HandleTrialExpiration(ctx context.Context) error {
	// This would typically involve querying for expired trial tenants and updating their status
	// Implementation depends on business requirements
	return fmt.Errorf("not implemented in CQRS version")
}

// HandleUserLimitExceeded handles tenants exceeding user limits
func (s *TenantCQRSService) HandleUserLimitExceeded(ctx context.Context) error {
	// This would typically involve querying for tenants over limit and taking action
	// Implementation depends on business requirements
	return fmt.Errorf("not implemented in CQRS version")
}

// GenerateSlug generates a unique slug for a tenant name
func (s *TenantCQRSService) GenerateSlug(ctx context.Context, name string) (string, error) {
	// This is typically a pure function that doesn't need CQRS
	// Implementation would be similar to the original service
	return "", fmt.Errorf("not implemented in CQRS version")
}

// ValidateDomain validates and checks domain availability
func (s *TenantCQRSService) ValidateDomain(ctx context.Context, domain string, excludeTenantID *uuid.UUID) error {
	// This would use the read model repository to check domain uniqueness
	// Implementation depends on query handler
	return fmt.Errorf("not implemented in CQRS version")
}

// SetupDefaultTenantData sets up default data for a new tenant
func (s *TenantCQRSService) SetupDefaultTenantData(ctx context.Context, tenantID uuid.UUID) error {
	// This might involve creating default roles, settings, etc.
	// Could be implemented as additional commands or side effects
	return fmt.Errorf("not implemented in CQRS version")
}

// Helper methods

func (s *TenantCQRSService) getUserIDFromContext(ctx context.Context) uuid.UUID {
	// Extract user ID from context (should be set by authentication middleware)
	if userID, ok := ctx.Value("user_id").(uuid.UUID); ok {
		return userID
	}
	// Return system user as fallback
	return uuid.MustParse("00000000-0000-0000-0000-000000000000")
}
