package dto

import (
	"time"

	"github.com/ducdt2000/azth/backend/internal/domain"
	"github.com/google/uuid"
)

// TenantResponse represents a tenant in API responses
type TenantResponse struct {
	ID             uuid.UUID           `json:"id" example:"550e8400-e29b-41d4-a716-446655440001"`
	Name           string              `json:"name" example:"Acme Corporation"`
	Slug           string              `json:"slug" example:"acme-corp"`
	Domain         *string             `json:"domain" example:"acme.com"`
	LogoURL        *string             `json:"logo_url" example:"https://example.com/logo.png"`
	PrimaryColor   *string             `json:"primary_color" example:"#007bff"`
	SecondaryColor *string             `json:"secondary_color" example:"#6c757d"`
	Status         domain.TenantStatus `json:"status" example:"active"`
	Plan           string              `json:"plan" example:"enterprise"`
	MaxUsers       int                 `json:"max_users" example:"100"`
	CurrentUsers   int                 `json:"current_users" example:"45"`
	Settings       domain.JSONMap      `json:"settings"`
	Metadata       domain.JSONMap      `json:"metadata"`
	CreatedAt      time.Time           `json:"created_at" example:"2023-01-15T10:30:00Z"`
	UpdatedAt      time.Time           `json:"updated_at" example:"2023-12-01T08:15:30Z"`
}

// TenantListResponse represents a paginated list of tenants
type TenantListResponse struct {
	Tenants    []TenantResponse   `json:"tenants"`
	Pagination PaginationResponse `json:"pagination"`
}

// TenantStatsResponse represents tenant statistics
type TenantStatsResponse struct {
	TotalTenants      int `json:"total_tenants" example:"25"`
	ActiveTenants     int `json:"active_tenants" example:"22"`
	InactiveTenants   int `json:"inactive_tenants" example:"1"`
	SuspendedTenants  int `json:"suspended_tenants" example:"1"`
	TrialTenants      int `json:"trial_tenants" example:"1"`
	TotalUsers        int `json:"total_users" example:"1250"`
	TotalSessions     int `json:"total_sessions" example:"456"`
	TotalOIDCClients  int `json:"total_oidc_clients" example:"89"`
	ActiveOIDCClients int `json:"active_oidc_clients" example:"78"`
}

// TenantUserStatsResponse represents user statistics for a specific tenant
type TenantUserStatsResponse struct {
	TenantID       uuid.UUID `json:"tenant_id" example:"550e8400-e29b-41d4-a716-446655440001"`
	TotalUsers     int       `json:"total_users" example:"45"`
	ActiveUsers    int       `json:"active_users" example:"42"`
	InactiveUsers  int       `json:"inactive_users" example:"2"`
	SuspendedUsers int       `json:"suspended_users" example:"1"`
	PendingUsers   int       `json:"pending_users" example:"0"`
	VerifiedEmails int       `json:"verified_emails" example:"40"`
	VerifiedPhones int       `json:"verified_phones" example:"25"`
	MFAEnabled     int       `json:"mfa_enabled" example:"15"`
	RecentLogins   int       `json:"recent_logins_24h" example:"12"`
	ActiveSessions int       `json:"active_sessions" example:"8"`
}

// BulkOperationResponse represents the result of a bulk operation
type BulkOperationResponse struct {
	SuccessCount int         `json:"success_count" example:"5"`
	FailureCount int         `json:"failure_count" example:"1"`
	Failures     []BulkError `json:"failures,omitempty"`
}

// BulkError represents an error in bulk operations
type BulkError struct {
	ID    uuid.UUID `json:"id" example:"550e8400-e29b-41d4-a716-446655440001"`
	Error string    `json:"error" example:"Tenant not found"`
}

// Common response structures
type APIResponse struct {
	Success bool        `json:"success" example:"true"`
	Message string      `json:"message" example:"Operation completed successfully"`
	Data    interface{} `json:"data,omitempty"`
	Error   *APIError   `json:"error,omitempty"`
}

// APIError represents an API error
type APIError struct {
	Code    string `json:"code" example:"VALIDATION_ERROR"`
	Message string `json:"message" example:"Invalid input data"`
	Details string `json:"details,omitempty" example:"Field 'name' is required"`
}

// PaginationResponse represents pagination metadata
type PaginationResponse struct {
	Page       int `json:"page" example:"1"`
	Limit      int `json:"limit" example:"20"`
	Total      int `json:"total" example:"150"`
	TotalPages int `json:"total_pages" example:"8"`
}
