package service

import (
	"context"

	"github.com/ducdt2000/azth/backend/internal/domain"
	"github.com/ducdt2000/azth/backend/internal/modules/auth/dto"
	"github.com/google/uuid"
)

// NotificationService defines the interface for notification services
type NotificationService interface {
	// Email services
	SendEmail(ctx context.Context, req *SendEmailRequest) error
	SendEmailWithTemplate(ctx context.Context, req *SendEmailWithTemplateRequest) error

	// SMS services
	SendSMS(ctx context.Context, req *SendSMSRequest) error
	SendSMSWithTemplate(ctx context.Context, req *SendSMSWithTemplateRequest) error

	// Template management
	CreateTemplate(ctx context.Context, req *dto.NotificationTemplateRequest) (*dto.NotificationTemplateResponse, error)
	UpdateTemplate(ctx context.Context, id uuid.UUID, req *dto.NotificationTemplateRequest) (*dto.NotificationTemplateResponse, error)
	GetTemplate(ctx context.Context, id uuid.UUID) (*dto.NotificationTemplateResponse, error)
	ListTemplates(ctx context.Context, tenantID *uuid.UUID, filters *TemplateFilters) (*dto.ListResponse, error)
	DeleteTemplate(ctx context.Context, id uuid.UUID) error
	GetTemplateByPurpose(ctx context.Context, tenantID *uuid.UUID, purpose domain.OTPPurpose, templateType domain.TemplateType, language string) (*domain.NotificationTemplate, error)

	// Notification logs
	GetNotificationLogs(ctx context.Context, tenantID uuid.UUID, filters *NotificationLogFilters) (*dto.ListResponse, error)
	UpdateNotificationStatus(ctx context.Context, id uuid.UUID, status domain.NotificationStatus, errorMsg *string) error
}

// EmailService defines the interface for email providers
type EmailService interface {
	SendEmail(ctx context.Context, to, subject, body, bodyHTML string) (externalID string, err error)
	ValidateConfig() error
}

// SMSService defines the interface for SMS providers
type SMSService interface {
	SendSMS(ctx context.Context, to, message string) (externalID string, err error)
	ValidateConfig() error
}

// TemplateService defines the interface for template processing
type TemplateService interface {
	ProcessTemplate(template string, variables map[string]interface{}) (string, error)
	ValidateTemplate(template string, requiredVars []string) error
}

// SendEmailRequest represents a direct email sending request
type SendEmailRequest struct {
	TenantID uuid.UUID `validate:"required"`
	UserID   *uuid.UUID
	To       string `validate:"required,email"`
	Subject  string `validate:"required"`
	Body     string `validate:"required"`
	BodyHTML *string
	Purpose  domain.OTPPurpose
	Metadata map[string]interface{}
}

// SendEmailWithTemplateRequest represents an email sending request using a template
type SendEmailWithTemplateRequest struct {
	TenantID   uuid.UUID `validate:"required"`
	UserID     *uuid.UUID
	To         string `validate:"required,email"`
	TemplateID *uuid.UUID
	Purpose    domain.OTPPurpose `validate:"required"`
	Language   string            `validate:"required"`
	Variables  map[string]interface{}
	Metadata   map[string]interface{}
}

// SendSMSRequest represents a direct SMS sending request
type SendSMSRequest struct {
	TenantID uuid.UUID `validate:"required"`
	UserID   *uuid.UUID
	To       string `validate:"required"`
	Message  string `validate:"required"`
	Purpose  domain.OTPPurpose
	Metadata map[string]interface{}
}

// SendSMSWithTemplateRequest represents an SMS sending request using a template
type SendSMSWithTemplateRequest struct {
	TenantID   uuid.UUID `validate:"required"`
	UserID     *uuid.UUID
	To         string `validate:"required"`
	TemplateID *uuid.UUID
	Purpose    domain.OTPPurpose `validate:"required"`
	Language   string            `validate:"required"`
	Variables  map[string]interface{}
	Metadata   map[string]interface{}
}

// TemplateFilters represents filters for template listing
type TemplateFilters struct {
	Type     *domain.TemplateType
	Purpose  *domain.OTPPurpose
	Language *string
	IsActive *bool
	Page     int
	PageSize int
}

// NotificationLogFilters represents filters for notification log listing
type NotificationLogFilters struct {
	UserID    *uuid.UUID
	Type      *domain.TemplateType
	Purpose   *domain.OTPPurpose
	Status    *domain.NotificationStatus
	StartDate *string
	EndDate   *string
	Page      int
	PageSize  int
}
