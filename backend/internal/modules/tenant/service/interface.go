package service

import (
	"context"

	"github.com/ducdt2000/azth/backend/internal/domain"
	"github.com/ducdt2000/azth/backend/internal/modules/tenant/dto"
	"github.com/google/uuid"
)

// TenantService defines the interface for tenant business logic
type TenantService interface {
	// CreateTenant creates a new tenant with validation and business rules
	CreateTenant(ctx context.Context, req *dto.CreateTenantRequest) (*dto.TenantResponse, error)

	// GetTenant retrieves a tenant by ID
	GetTenant(ctx context.Context, id uuid.UUID) (*dto.TenantResponse, error)

	// GetTenantBySlug retrieves a tenant by slug
	GetTenantBySlug(ctx context.Context, slug string) (*dto.TenantResponse, error)

	// GetTenantByDomain retrieves a tenant by domain
	GetTenantByDomain(ctx context.Context, domain string) (*dto.TenantResponse, error)

	// UpdateTenant updates an existing tenant with validation
	UpdateTenant(ctx context.Context, id uuid.UUID, req *dto.UpdateTenantRequest) (*dto.TenantResponse, error)

	// DeleteTenant soft deletes a tenant and handles cleanup
	DeleteTenant(ctx context.Context, id uuid.UUID) error

	// ListTenants retrieves tenants with pagination and filtering
	ListTenants(ctx context.Context, req *dto.TenantListRequest) (*dto.TenantListResponse, error)

	// GetTenantStats retrieves tenant statistics
	GetTenantStats(ctx context.Context, req *dto.TenantStatsRequest) (*dto.TenantStatsResponse, error)

	// GetTenantUserStats retrieves user statistics for a specific tenant
	GetTenantUserStats(ctx context.Context, tenantID uuid.UUID) (*dto.TenantUserStatsResponse, error)

	// BulkUpdateTenants performs bulk operations on tenants
	BulkUpdateTenants(ctx context.Context, req *dto.BulkTenantRequest) (*dto.BulkOperationResponse, error)

	// ActivateTenant activates a tenant and all related services
	ActivateTenant(ctx context.Context, tenantID uuid.UUID) error

	// DeactivateTenant deactivates a tenant and suspends services
	DeactivateTenant(ctx context.Context, tenantID uuid.UUID) error

	// SuspendTenant suspends a tenant and blocks access
	SuspendTenant(ctx context.Context, tenantID uuid.UUID) error

	// UpgradePlan upgrades a tenant's subscription plan
	UpgradePlan(ctx context.Context, tenantID uuid.UUID, plan string, maxUsers int) (*dto.TenantResponse, error)

	// DowngradePlan downgrades a tenant's subscription plan
	DowngradePlan(ctx context.Context, tenantID uuid.UUID, plan string, maxUsers int) (*dto.TenantResponse, error)

	// UpdateTenantSettings updates tenant configuration settings
	UpdateTenantSettings(ctx context.Context, tenantID uuid.UUID, settings map[string]interface{}) (*dto.TenantResponse, error)

	// UpdateTenantMetadata updates tenant metadata
	UpdateTenantMetadata(ctx context.Context, tenantID uuid.UUID, metadata map[string]interface{}) (*dto.TenantResponse, error)

	// ValidateTenantAccess validates if a tenant can be accessed
	ValidateTenantAccess(ctx context.Context, tenantID uuid.UUID) error

	// CheckUserLimit checks if tenant has reached user limit
	CheckUserLimit(ctx context.Context, tenantID uuid.UUID) (bool, error)

	// GetTenantUsers retrieves users for a specific tenant
	GetTenantUsers(ctx context.Context, tenantID uuid.UUID, req *dto.TenantUserRequest) (*dto.TenantListResponse, error)

	// GetTenantsByPlan retrieves tenants by subscription plan
	GetTenantsByPlan(ctx context.Context, plan string) ([]*dto.TenantResponse, error)

	// GetTenantsByStatus retrieves tenants by status
	GetTenantsByStatus(ctx context.Context, status domain.TenantStatus) ([]*dto.TenantResponse, error)

	// HandleTrialExpiration handles expired trial tenants
	HandleTrialExpiration(ctx context.Context) error

	// HandleUserLimitExceeded handles tenants exceeding user limits
	HandleUserLimitExceeded(ctx context.Context) error

	// GenerateSlug generates a unique slug for a tenant name
	GenerateSlug(ctx context.Context, name string) (string, error)

	// ValidateDomain validates and checks domain availability
	ValidateDomain(ctx context.Context, domain string, excludeTenantID *uuid.UUID) error

	// SetupDefaultTenantData sets up default data for a new tenant
	SetupDefaultTenantData(ctx context.Context, tenantID uuid.UUID) error
}
