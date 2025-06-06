package cqrs

import (
	"context"
	"time"

	"github.com/ducdt2000/azth/backend/internal/domain"
	"github.com/google/uuid"
)

// Command represents a command in the CQRS pattern
type Command interface {
	GetAggregateID() uuid.UUID
	GetCommandType() string
	GetTimestamp() time.Time
}

// CommandHandler handles commands and produces events
type CommandHandler interface {
	Handle(ctx context.Context, cmd Command) ([]Event, error)
}

// BaseCommand provides common command functionality
type BaseCommand struct {
	AggregateID uuid.UUID `json:"aggregate_id"`
	CommandType string    `json:"command_type"`
	Timestamp   time.Time `json:"timestamp"`
	UserID      uuid.UUID `json:"user_id"`
	TenantID    uuid.UUID `json:"tenant_id"`
}

func (c BaseCommand) GetAggregateID() uuid.UUID {
	return c.AggregateID
}

func (c BaseCommand) GetCommandType() string {
	return c.CommandType
}

func (c BaseCommand) GetTimestamp() time.Time {
	return c.Timestamp
}

// Tenant Commands

// CreateTenantCommand represents a command to create a new tenant
type CreateTenantCommand struct {
	BaseCommand
	Name           string                 `json:"name"`
	Slug           string                 `json:"slug"`
	Domain         *string                `json:"domain"`
	LogoURL        *string                `json:"logo_url"`
	PrimaryColor   *string                `json:"primary_color"`
	SecondaryColor *string                `json:"secondary_color"`
	Plan           string                 `json:"plan"`
	MaxUsers       int                    `json:"max_users"`
	Settings       map[string]interface{} `json:"settings"`
	Metadata       map[string]interface{} `json:"metadata"`
}

// UpdateTenantCommand represents a command to update a tenant
type UpdateTenantCommand struct {
	BaseCommand
	Name           *string                `json:"name,omitempty"`
	Domain         *string                `json:"domain,omitempty"`
	LogoURL        *string                `json:"logo_url,omitempty"`
	PrimaryColor   *string                `json:"primary_color,omitempty"`
	SecondaryColor *string                `json:"secondary_color,omitempty"`
	Status         *domain.TenantStatus   `json:"status,omitempty"`
	Plan           *string                `json:"plan,omitempty"`
	MaxUsers       *int                   `json:"max_users,omitempty"`
	Settings       map[string]interface{} `json:"settings,omitempty"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
}

// DeleteTenantCommand represents a command to delete a tenant
type DeleteTenantCommand struct {
	BaseCommand
	Reason string `json:"reason,omitempty"`
}

// ActivateTenantCommand represents a command to activate a tenant
type ActivateTenantCommand struct {
	BaseCommand
	Reason string `json:"reason,omitempty"`
}

// DeactivateTenantCommand represents a command to deactivate a tenant
type DeactivateTenantCommand struct {
	BaseCommand
	Reason string `json:"reason,omitempty"`
}

// SuspendTenantCommand represents a command to suspend a tenant
type SuspendTenantCommand struct {
	BaseCommand
	Reason string `json:"reason"`
}

// ChangeTenantPlanCommand represents a command to change a tenant's plan
type ChangeTenantPlanCommand struct {
	BaseCommand
	NewPlan     string `json:"new_plan"`
	OldPlan     string `json:"old_plan"`
	NewMaxUsers int    `json:"new_max_users"`
	OldMaxUsers int    `json:"old_max_users"`
	Reason      string `json:"reason,omitempty"`
}

// UpdateTenantSettingsCommand represents a command to update tenant settings
type UpdateTenantSettingsCommand struct {
	BaseCommand
	Settings map[string]interface{} `json:"settings"`
}

// UpdateTenantMetadataCommand represents a command to update tenant metadata
type UpdateTenantMetadataCommand struct {
	BaseCommand
	Metadata map[string]interface{} `json:"metadata"`
}

// Command type constants
const (
	CreateTenantCommandType         = "tenant.create"
	UpdateTenantCommandType         = "tenant.update"
	DeleteTenantCommandType         = "tenant.delete"
	ActivateTenantCommandType       = "tenant.activate"
	DeactivateTenantCommandType     = "tenant.deactivate"
	SuspendTenantCommandType        = "tenant.suspend"
	ChangeTenantPlanCommandType     = "tenant.change_plan"
	UpdateTenantSettingsCommandType = "tenant.update_settings"
	UpdateTenantMetadataCommandType = "tenant.update_metadata"
)

// NewCreateTenantCommand creates a new CreateTenantCommand
func NewCreateTenantCommand(tenantID, userID uuid.UUID, name, slug, plan string, maxUsers int) *CreateTenantCommand {
	return &CreateTenantCommand{
		BaseCommand: BaseCommand{
			AggregateID: tenantID,
			CommandType: CreateTenantCommandType,
			Timestamp:   time.Now(),
			UserID:      userID,
			TenantID:    tenantID,
		},
		Name:     name,
		Slug:     slug,
		Plan:     plan,
		MaxUsers: maxUsers,
	}
}

// NewUpdateTenantCommand creates a new UpdateTenantCommand
func NewUpdateTenantCommand(tenantID, userID uuid.UUID) *UpdateTenantCommand {
	return &UpdateTenantCommand{
		BaseCommand: BaseCommand{
			AggregateID: tenantID,
			CommandType: UpdateTenantCommandType,
			Timestamp:   time.Now(),
			UserID:      userID,
			TenantID:    tenantID,
		},
	}
}

// NewDeleteTenantCommand creates a new DeleteTenantCommand
func NewDeleteTenantCommand(tenantID, userID uuid.UUID, reason string) *DeleteTenantCommand {
	return &DeleteTenantCommand{
		BaseCommand: BaseCommand{
			AggregateID: tenantID,
			CommandType: DeleteTenantCommandType,
			Timestamp:   time.Now(),
			UserID:      userID,
			TenantID:    tenantID,
		},
		Reason: reason,
	}
}

// NewActivateTenantCommand creates a new ActivateTenantCommand
func NewActivateTenantCommand(tenantID, userID uuid.UUID, reason string) *ActivateTenantCommand {
	return &ActivateTenantCommand{
		BaseCommand: BaseCommand{
			AggregateID: tenantID,
			CommandType: ActivateTenantCommandType,
			Timestamp:   time.Now(),
			UserID:      userID,
			TenantID:    tenantID,
		},
		Reason: reason,
	}
}

// NewDeactivateTenantCommand creates a new DeactivateTenantCommand
func NewDeactivateTenantCommand(tenantID, userID uuid.UUID, reason string) *DeactivateTenantCommand {
	return &DeactivateTenantCommand{
		BaseCommand: BaseCommand{
			AggregateID: tenantID,
			CommandType: DeactivateTenantCommandType,
			Timestamp:   time.Now(),
			UserID:      userID,
			TenantID:    tenantID,
		},
		Reason: reason,
	}
}

// NewSuspendTenantCommand creates a new SuspendTenantCommand
func NewSuspendTenantCommand(tenantID, userID uuid.UUID, reason string) *SuspendTenantCommand {
	return &SuspendTenantCommand{
		BaseCommand: BaseCommand{
			AggregateID: tenantID,
			CommandType: SuspendTenantCommandType,
			Timestamp:   time.Now(),
			UserID:      userID,
			TenantID:    tenantID,
		},
		Reason: reason,
	}
}

// NewChangeTenantPlanCommand creates a new ChangeTenantPlanCommand
func NewChangeTenantPlanCommand(tenantID, userID uuid.UUID, newPlan, oldPlan string, newMaxUsers, oldMaxUsers int, reason string) *ChangeTenantPlanCommand {
	return &ChangeTenantPlanCommand{
		BaseCommand: BaseCommand{
			AggregateID: tenantID,
			CommandType: ChangeTenantPlanCommandType,
			Timestamp:   time.Now(),
			UserID:      userID,
			TenantID:    tenantID,
		},
		NewPlan:     newPlan,
		OldPlan:     oldPlan,
		NewMaxUsers: newMaxUsers,
		OldMaxUsers: oldMaxUsers,
		Reason:      reason,
	}
}
