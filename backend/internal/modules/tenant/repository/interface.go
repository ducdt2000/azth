package repository

import (
	"context"

	"github.com/ducdt2000/azth/backend/internal/domain"
	"github.com/ducdt2000/azth/backend/internal/modules/tenant/dto"
	"github.com/google/uuid"
)

// TenantRepository defines the interface for tenant data access
type TenantRepository interface {
	// Create creates a new tenant
	Create(ctx context.Context, tenant *domain.Tenant) error

	// GetByID retrieves a tenant by ID
	GetByID(ctx context.Context, id uuid.UUID) (*domain.Tenant, error)

	// GetBySlug retrieves a tenant by slug
	GetBySlug(ctx context.Context, slug string) (*domain.Tenant, error)

	// GetByDomain retrieves a tenant by domain
	GetByDomain(ctx context.Context, domain string) (*domain.Tenant, error)

	// Update updates an existing tenant
	Update(ctx context.Context, tenant *domain.Tenant) error

	// Delete soft deletes a tenant
	Delete(ctx context.Context, id uuid.UUID) error

	// List retrieves tenants with pagination and filtering
	List(ctx context.Context, req *dto.TenantListRequest) ([]*domain.Tenant, int, error)

	// GetTenantStats retrieves tenant statistics
	GetTenantStats(ctx context.Context, req *dto.TenantStatsRequest) (*dto.TenantStatsResponse, error)

	// GetTenantUserStats retrieves user statistics for a specific tenant
	GetTenantUserStats(ctx context.Context, tenantID uuid.UUID) (*dto.TenantUserStatsResponse, error)

	// BulkUpdate performs bulk updates on tenants
	BulkUpdate(ctx context.Context, tenantIDs []uuid.UUID, action string) (int, []error)

	// SlugExists checks if a slug already exists
	SlugExists(ctx context.Context, slug string, excludeTenantID *uuid.UUID) (bool, error)

	// DomainExists checks if a domain already exists
	DomainExists(ctx context.Context, domain string, excludeTenantID *uuid.UUID) (bool, error)

	// GetUserCount retrieves the current user count for a tenant
	GetUserCount(ctx context.Context, tenantID uuid.UUID) (int, error)

	// GetActiveUserCount retrieves the active user count for a tenant
	GetActiveUserCount(ctx context.Context, tenantID uuid.UUID) (int, error)

	// GetSessionCount retrieves the session count for a tenant
	GetSessionCount(ctx context.Context, tenantID uuid.UUID) (int, error)

	// GetActiveSessionCount retrieves the active session count for a tenant
	GetActiveSessionCount(ctx context.Context, tenantID uuid.UUID) (int, error)

	// GetOIDCClientCount retrieves the OIDC client count for a tenant
	GetOIDCClientCount(ctx context.Context, tenantID uuid.UUID) (int, error)

	// GetActiveOIDCClientCount retrieves the active OIDC client count for a tenant
	GetActiveOIDCClientCount(ctx context.Context, tenantID uuid.UUID) (int, error)

	// ActivateTenant activates a tenant
	ActivateTenant(ctx context.Context, tenantID uuid.UUID) error

	// DeactivateTenant deactivates a tenant
	DeactivateTenant(ctx context.Context, tenantID uuid.UUID) error

	// SuspendTenant suspends a tenant
	SuspendTenant(ctx context.Context, tenantID uuid.UUID) error

	// UpgradePlan upgrades a tenant's plan
	UpgradePlan(ctx context.Context, tenantID uuid.UUID, plan string, maxUsers int) error

	// DowngradePlan downgrades a tenant's plan
	DowngradePlan(ctx context.Context, tenantID uuid.UUID, plan string, maxUsers int) error

	// UpdateSettings updates tenant settings
	UpdateSettings(ctx context.Context, tenantID uuid.UUID, settings domain.JSONMap) error

	// UpdateMetadata updates tenant metadata
	UpdateMetadata(ctx context.Context, tenantID uuid.UUID, metadata domain.JSONMap) error

	// GetTenantsByPlan retrieves tenants by plan
	GetTenantsByPlan(ctx context.Context, plan string) ([]*domain.Tenant, error)

	// GetTenantsByStatus retrieves tenants by status
	GetTenantsByStatus(ctx context.Context, status domain.TenantStatus) ([]*domain.Tenant, error)

	// GetExpiredTrialTenants retrieves tenants with expired trial periods
	GetExpiredTrialTenants(ctx context.Context) ([]*domain.Tenant, error)

	// GetTenantsExceedingUserLimit retrieves tenants exceeding their user limit
	GetTenantsExceedingUserLimit(ctx context.Context) ([]*domain.Tenant, error)
}
