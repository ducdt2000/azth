package dto

import (
	"github.com/google/uuid"
)

// CreateTenantRequest represents the request to create a new tenant
type CreateTenantRequest struct {
	Name           string                 `json:"name" binding:"required,min=1,max=100" example:"Acme Corporation" validate:"required,min=1,max=100"`
	Slug           string                 `json:"slug" binding:"required,min=3,max=50,alphanum" example:"acme-corp" validate:"required,min=3,max=50"`
	Domain         *string                `json:"domain,omitempty" example:"acme.com"`
	LogoURL        *string                `json:"logo_url,omitempty" example:"https://example.com/logo.png"`
	PrimaryColor   *string                `json:"primary_color,omitempty" example:"#007bff"`
	SecondaryColor *string                `json:"secondary_color,omitempty" example:"#6c757d"`
	Plan           string                 `json:"plan" binding:"required" example:"enterprise" enums:"free,pro,enterprise" validate:"required"`
	MaxUsers       int                    `json:"max_users" binding:"min=1" example:"100" validate:"min=1"`
	Settings       map[string]interface{} `json:"settings,omitempty"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
}

// UpdateTenantRequest represents the request to update an existing tenant
type UpdateTenantRequest struct {
	Name           *string                `json:"name,omitempty" binding:"omitempty,min=1,max=100" example:"Acme Corporation" validate:"omitempty,min=1,max=100"`
	Domain         *string                `json:"domain,omitempty" example:"acme.com"`
	LogoURL        *string                `json:"logo_url,omitempty" example:"https://example.com/logo.png"`
	PrimaryColor   *string                `json:"primary_color,omitempty" example:"#007bff"`
	SecondaryColor *string                `json:"secondary_color,omitempty" example:"#6c757d"`
	Status         *string                `json:"status,omitempty" enums:"active,inactive,suspended,trial" example:"active"`
	Plan           *string                `json:"plan,omitempty" example:"enterprise" enums:"free,pro,enterprise"`
	MaxUsers       *int                   `json:"max_users,omitempty" binding:"omitempty,min=1" example:"100" validate:"omitempty,min=1"`
	Settings       map[string]interface{} `json:"settings,omitempty"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
}

// TenantListRequest represents the request for listing tenants with pagination and filtering
type TenantListRequest struct {
	Page   int    `query:"page" example:"1" minimum:"1" default:"1"`
	Limit  int    `query:"limit" example:"20" minimum:"1" maximum:"100" default:"20"`
	Sort   string `query:"sort" example:"created_at" enums:"created_at,updated_at,name,slug" default:"created_at"`
	Order  string `query:"order" example:"desc" enums:"asc,desc" default:"desc"`
	Search string `query:"search" example:"acme"`
	Status string `query:"status" example:"active" enums:"active,inactive,suspended,trial"`
	Plan   string `query:"plan" example:"enterprise" enums:"free,pro,enterprise"`
}

// BulkTenantRequest represents the request for bulk tenant operations
type BulkTenantRequest struct {
	TenantIDs []uuid.UUID `json:"tenant_ids" binding:"required,min=1" example:"[\"550e8400-e29b-41d4-a716-446655440001\"]" validate:"required,min=1"`
	Action    string      `json:"action" binding:"required" example:"activate" enums:"activate,deactivate,suspend,delete" validate:"required"`
}

// TenantStatsRequest represents the request for tenant statistics
type TenantStatsRequest struct {
	DateFrom *string `query:"date_from" example:"2023-01-01"`
	DateTo   *string `query:"date_to" example:"2023-12-31"`
}

// TenantUserRequest represents the request for tenant user operations
type TenantUserRequest struct {
	Page   int    `query:"page" example:"1" minimum:"1" default:"1"`
	Limit  int    `query:"limit" example:"20" minimum:"1" maximum:"100" default:"20"`
	Sort   string `query:"sort" example:"created_at" enums:"created_at,updated_at,email,username" default:"created_at"`
	Order  string `query:"order" example:"desc" enums:"asc,desc" default:"desc"`
	Search string `query:"search" example:"john@example.com"`
	Status string `query:"status" example:"active" enums:"active,inactive,suspended,pending"`
}
