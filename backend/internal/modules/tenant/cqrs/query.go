package cqrs

import (
	"context"
	"time"

	"github.com/ducdt2000/azth/backend/internal/domain"
	"github.com/ducdt2000/azth/backend/internal/modules/tenant/dto"
	"github.com/google/uuid"
)

// Query represents a query in the CQRS pattern
type Query interface {
	GetQueryType() string
	GetTimestamp() time.Time
}

// QueryHandler handles queries and returns read models
type QueryHandler interface {
	Handle(ctx context.Context, query Query) (interface{}, error)
}

// BaseQuery provides common query functionality
type BaseQuery struct {
	QueryType string    `json:"query_type"`
	Timestamp time.Time `json:"timestamp"`
	UserID    uuid.UUID `json:"user_id"`
	TenantID  uuid.UUID `json:"tenant_id"`
}

func (q BaseQuery) GetQueryType() string {
	return q.QueryType
}

func (q BaseQuery) GetTimestamp() time.Time {
	return q.Timestamp
}

// Tenant Queries

// GetTenantQuery represents a query to get a tenant by ID
type GetTenantQuery struct {
	BaseQuery
	TenantID uuid.UUID `json:"tenant_id"`
}

// GetTenantBySlugQuery represents a query to get a tenant by slug
type GetTenantBySlugQuery struct {
	BaseQuery
	Slug string `json:"slug"`
}

// GetTenantByDomainQuery represents a query to get a tenant by domain
type GetTenantByDomainQuery struct {
	BaseQuery
	Domain string `json:"domain"`
}

// ListTenantsQuery represents a query to list tenants with pagination
type ListTenantsQuery struct {
	BaseQuery
	Page   int                    `json:"page"`
	Limit  int                    `json:"limit"`
	Sort   string                 `json:"sort"`
	Order  string                 `json:"order"`
	Search string                 `json:"search"`
	Status *domain.TenantStatus   `json:"status,omitempty"`
	Plan   *string                `json:"plan,omitempty"`
	Filter map[string]interface{} `json:"filter,omitempty"`
}

// GetTenantStatsQuery represents a query to get tenant statistics
type GetTenantStatsQuery struct {
	BaseQuery
	DateFrom *time.Time `json:"date_from,omitempty"`
	DateTo   *time.Time `json:"date_to,omitempty"`
}

// GetTenantUserStatsQuery represents a query to get tenant user statistics
type GetTenantUserStatsQuery struct {
	BaseQuery
	TenantID uuid.UUID `json:"tenant_id"`
}

// GetTenantUsersQuery represents a query to get tenant users
type GetTenantUsersQuery struct {
	BaseQuery
	TenantID uuid.UUID `json:"tenant_id"`
	Page     int       `json:"page"`
	Limit    int       `json:"limit"`
	Sort     string    `json:"sort"`
	Order    string    `json:"order"`
	Search   string    `json:"search"`
	Status   *string   `json:"status,omitempty"`
}

// GetTenantsByPlanQuery represents a query to get tenants by plan
type GetTenantsByPlanQuery struct {
	BaseQuery
	Plan string `json:"plan"`
}

// GetTenantsByStatusQuery represents a query to get tenants by status
type GetTenantsByStatusQuery struct {
	BaseQuery
	Status domain.TenantStatus `json:"status"`
}

// ValidateTenantAccessQuery represents a query to validate tenant access
type ValidateTenantAccessQuery struct {
	BaseQuery
	TenantID uuid.UUID `json:"tenant_id"`
}

// CheckUserLimitQuery represents a query to check user limit
type CheckUserLimitQuery struct {
	BaseQuery
	TenantID uuid.UUID `json:"tenant_id"`
}

// GetTenantHistoryQuery represents a query to get tenant event history
type GetTenantHistoryQuery struct {
	BaseQuery
	TenantID  uuid.UUID  `json:"tenant_id"`
	FromDate  *time.Time `json:"from_date,omitempty"`
	ToDate    *time.Time `json:"to_date,omitempty"`
	EventType *string    `json:"event_type,omitempty"`
}

// Query type constants
const (
	GetTenantQueryType            = "tenant.get"
	GetTenantBySlugQueryType      = "tenant.get_by_slug"
	GetTenantByDomainQueryType    = "tenant.get_by_domain"
	ListTenantsQueryType          = "tenant.list"
	GetTenantStatsQueryType       = "tenant.get_stats"
	GetTenantUserStatsQueryType   = "tenant.get_user_stats"
	GetTenantUsersQueryType       = "tenant.get_users"
	GetTenantsByPlanQueryType     = "tenant.get_by_plan"
	GetTenantsByStatusQueryType   = "tenant.get_by_status"
	ValidateTenantAccessQueryType = "tenant.validate_access"
	CheckUserLimitQueryType       = "tenant.check_user_limit"
	GetTenantHistoryQueryType     = "tenant.get_history"
)

// NewGetTenantQuery creates a new GetTenantQuery
func NewGetTenantQuery(userID, tenantID uuid.UUID) *GetTenantQuery {
	return &GetTenantQuery{
		BaseQuery: BaseQuery{
			QueryType: GetTenantQueryType,
			Timestamp: time.Now(),
			UserID:    userID,
			TenantID:  tenantID,
		},
		TenantID: tenantID,
	}
}

// NewGetTenantBySlugQuery creates a new GetTenantBySlugQuery
func NewGetTenantBySlugQuery(userID uuid.UUID, slug string) *GetTenantBySlugQuery {
	return &GetTenantBySlugQuery{
		BaseQuery: BaseQuery{
			QueryType: GetTenantBySlugQueryType,
			Timestamp: time.Now(),
			UserID:    userID,
		},
		Slug: slug,
	}
}

// NewGetTenantByDomainQuery creates a new GetTenantByDomainQuery
func NewGetTenantByDomainQuery(userID uuid.UUID, domain string) *GetTenantByDomainQuery {
	return &GetTenantByDomainQuery{
		BaseQuery: BaseQuery{
			QueryType: GetTenantByDomainQueryType,
			Timestamp: time.Now(),
			UserID:    userID,
		},
		Domain: domain,
	}
}

// NewListTenantsQuery creates a new ListTenantsQuery
func NewListTenantsQuery(userID uuid.UUID, req *dto.TenantListRequest) *ListTenantsQuery {
	query := &ListTenantsQuery{
		BaseQuery: BaseQuery{
			QueryType: ListTenantsQueryType,
			Timestamp: time.Now(),
			UserID:    userID,
		},
		Page:   req.Page,
		Limit:  req.Limit,
		Sort:   req.Sort,
		Order:  req.Order,
		Search: req.Search,
	}

	if req.Status != "" {
		status := domain.TenantStatus(req.Status)
		query.Status = &status
	}

	if req.Plan != "" {
		query.Plan = &req.Plan
	}

	return query
}

// NewGetTenantStatsQuery creates a new GetTenantStatsQuery
func NewGetTenantStatsQuery(userID uuid.UUID, req *dto.TenantStatsRequest) *GetTenantStatsQuery {
	query := &GetTenantStatsQuery{
		BaseQuery: BaseQuery{
			QueryType: GetTenantStatsQueryType,
			Timestamp: time.Now(),
			UserID:    userID,
		},
	}

	if req.DateFrom != nil {
		if t, err := time.Parse("2006-01-02", *req.DateFrom); err == nil {
			query.DateFrom = &t
		}
	}

	if req.DateTo != nil {
		if t, err := time.Parse("2006-01-02", *req.DateTo); err == nil {
			query.DateTo = &t
		}
	}

	return query
}

// TenantQueryHandler handles all tenant-related queries
type TenantQueryHandler interface {
	HandleGetTenant(ctx context.Context, query *GetTenantQuery) (*dto.TenantResponse, error)
	HandleGetTenantBySlug(ctx context.Context, query *GetTenantBySlugQuery) (*dto.TenantResponse, error)
	HandleGetTenantByDomain(ctx context.Context, query *GetTenantByDomainQuery) (*dto.TenantResponse, error)
	HandleListTenants(ctx context.Context, query *ListTenantsQuery) (*dto.TenantListResponse, error)
	HandleGetTenantStats(ctx context.Context, query *GetTenantStatsQuery) (*dto.TenantStatsResponse, error)
	HandleGetTenantUserStats(ctx context.Context, query *GetTenantUserStatsQuery) (*dto.TenantUserStatsResponse, error)
	HandleGetTenantUsers(ctx context.Context, query *GetTenantUsersQuery) (*dto.TenantListResponse, error)
	HandleGetTenantsByPlan(ctx context.Context, query *GetTenantsByPlanQuery) ([]*dto.TenantResponse, error)
	HandleGetTenantsByStatus(ctx context.Context, query *GetTenantsByStatusQuery) ([]*dto.TenantResponse, error)
	HandleValidateTenantAccess(ctx context.Context, query *ValidateTenantAccessQuery) error
	HandleCheckUserLimit(ctx context.Context, query *CheckUserLimitQuery) (bool, error)
	HandleGetTenantHistory(ctx context.Context, query *GetTenantHistoryQuery) ([]*Event, error)
}
