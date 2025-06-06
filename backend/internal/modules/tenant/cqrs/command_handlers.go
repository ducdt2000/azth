package cqrs

import (
	"context"
	"fmt"

	"github.com/ducdt2000/azth/backend/internal/modules/tenant/dto"
	"github.com/ducdt2000/azth/backend/pkg/logger"
	"github.com/google/uuid"
)

// TenantCommandHandler handles tenant commands
type TenantCommandHandler struct {
	eventStore    EventStore
	readModelRepo TenantReadModelRepository
	logger        *logger.Logger
}

// TenantReadModelRepository defines the interface for read model access during command processing
type TenantReadModelRepository interface {
	// ExistsBySlug checks if a tenant with the given slug exists
	ExistsBySlug(ctx context.Context, slug string, excludeID *uuid.UUID) (bool, error)

	// ExistsByDomain checks if a tenant with the given domain exists
	ExistsByDomain(ctx context.Context, domain string, excludeID *uuid.UUID) (bool, error)

	// GetTenantByID retrieves a tenant by ID for validation purposes
	GetTenantByID(ctx context.Context, id uuid.UUID) (*dto.TenantResponse, error)

	// CountUsersByTenantID counts users for a specific tenant
	CountUsersByTenantID(ctx context.Context, tenantID uuid.UUID) (int, error)
}

// NewTenantCommandHandler creates a new tenant command handler
func NewTenantCommandHandler(
	eventStore EventStore,
	readModelRepo TenantReadModelRepository,
	logger *logger.Logger,
) *TenantCommandHandler {
	return &TenantCommandHandler{
		eventStore:    eventStore,
		readModelRepo: readModelRepo,
		logger:        logger,
	}
}

// Handle processes a command and returns generated events
func (h *TenantCommandHandler) Handle(ctx context.Context, cmd Command) ([]Event, error) {
	switch c := cmd.(type) {
	case *CreateTenantCommand:
		return h.HandleCreateTenant(ctx, c)
	case *UpdateTenantCommand:
		return h.HandleUpdateTenant(ctx, c)
	case *DeleteTenantCommand:
		return h.HandleDeleteTenant(ctx, c)
	case *ActivateTenantCommand:
		return h.HandleActivateTenant(ctx, c)
	case *DeactivateTenantCommand:
		return h.HandleDeactivateTenant(ctx, c)
	case *SuspendTenantCommand:
		return h.HandleSuspendTenant(ctx, c)
	case *ChangeTenantPlanCommand:
		return h.HandleChangeTenantPlan(ctx, c)
	case *UpdateTenantSettingsCommand:
		return h.HandleUpdateTenantSettings(ctx, c)
	case *UpdateTenantMetadataCommand:
		return h.HandleUpdateTenantMetadata(ctx, c)
	default:
		return nil, fmt.Errorf("unknown command type: %T", cmd)
	}
}

// HandleCreateTenant handles tenant creation commands
func (h *TenantCommandHandler) HandleCreateTenant(ctx context.Context, cmd *CreateTenantCommand) ([]Event, error) {
	h.logger.Info("Handling create tenant command", "tenant_id", cmd.AggregateID, "name", cmd.Name)

	// Validate business rules
	if err := h.validateCreateTenant(ctx, cmd); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	// Load aggregate
	aggregate := NewTenantAggregate(cmd.AggregateID)
	events, err := h.eventStore.GetEvents(ctx, cmd.AggregateID)
	if err != nil {
		return nil, fmt.Errorf("failed to load aggregate: %w", err)
	}

	if len(events) > 0 {
		return nil, fmt.Errorf("tenant already exists")
	}

	// Execute command
	err = aggregate.CreateTenant(
		cmd.UserID,
		cmd.Name,
		cmd.Slug,
		cmd.Plan,
		cmd.MaxUsers,
		cmd.Domain,
		cmd.LogoURL,
		cmd.PrimaryColor,
		cmd.SecondaryColor,
		cmd.Settings,
		cmd.Metadata,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create tenant: %w", err)
	}

	// Save events
	uncommittedEvents := aggregate.GetUncommittedEvents()
	err = h.eventStore.SaveEvents(ctx, cmd.AggregateID, uncommittedEvents, aggregate.GetVersion()-int64(len(uncommittedEvents)))
	if err != nil {
		return nil, fmt.Errorf("failed to save events: %w", err)
	}

	h.logger.Info("Tenant created successfully", "tenant_id", cmd.AggregateID)
	return uncommittedEvents, nil
}

// HandleUpdateTenant handles tenant update commands
func (h *TenantCommandHandler) HandleUpdateTenant(ctx context.Context, cmd *UpdateTenantCommand) ([]Event, error) {
	h.logger.Info("Handling update tenant command", "tenant_id", cmd.AggregateID)

	// Validate business rules
	if err := h.validateUpdateTenant(ctx, cmd); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	// Load aggregate
	aggregate, err := h.loadAggregate(ctx, cmd.AggregateID)
	if err != nil {
		return nil, err
	}

	// Execute command
	changes := h.buildChangesMap(cmd)
	err = aggregate.UpdateTenant(cmd.UserID, changes)
	if err != nil {
		return nil, fmt.Errorf("failed to update tenant: %w", err)
	}

	// Save events
	uncommittedEvents := aggregate.GetUncommittedEvents()
	if len(uncommittedEvents) == 0 {
		return nil, nil // No changes made
	}

	err = h.eventStore.SaveEvents(ctx, cmd.AggregateID, uncommittedEvents, aggregate.GetVersion()-int64(len(uncommittedEvents)))
	if err != nil {
		return nil, fmt.Errorf("failed to save events: %w", err)
	}

	h.logger.Info("Tenant updated successfully", "tenant_id", cmd.AggregateID)
	return uncommittedEvents, nil
}

// HandleDeleteTenant handles tenant deletion commands
func (h *TenantCommandHandler) HandleDeleteTenant(ctx context.Context, cmd *DeleteTenantCommand) ([]Event, error) {
	h.logger.Info("Handling delete tenant command", "tenant_id", cmd.AggregateID)

	// Load aggregate
	aggregate, err := h.loadAggregate(ctx, cmd.AggregateID)
	if err != nil {
		return nil, err
	}

	// Execute command
	err = aggregate.DeleteTenant(cmd.UserID, cmd.Reason)
	if err != nil {
		return nil, fmt.Errorf("failed to delete tenant: %w", err)
	}

	// Save events
	uncommittedEvents := aggregate.GetUncommittedEvents()
	err = h.eventStore.SaveEvents(ctx, cmd.AggregateID, uncommittedEvents, aggregate.GetVersion()-int64(len(uncommittedEvents)))
	if err != nil {
		return nil, fmt.Errorf("failed to save events: %w", err)
	}

	h.logger.Info("Tenant deleted successfully", "tenant_id", cmd.AggregateID)
	return uncommittedEvents, nil
}

// HandleActivateTenant handles tenant activation commands
func (h *TenantCommandHandler) HandleActivateTenant(ctx context.Context, cmd *ActivateTenantCommand) ([]Event, error) {
	return h.handleStatusChange(ctx, cmd.AggregateID, cmd.UserID, "activate", cmd.Reason, func(agg *TenantAggregate) error {
		return agg.ActivateTenant(cmd.UserID, cmd.Reason)
	})
}

// HandleDeactivateTenant handles tenant deactivation commands
func (h *TenantCommandHandler) HandleDeactivateTenant(ctx context.Context, cmd *DeactivateTenantCommand) ([]Event, error) {
	return h.handleStatusChange(ctx, cmd.AggregateID, cmd.UserID, "deactivate", cmd.Reason, func(agg *TenantAggregate) error {
		return agg.DeactivateTenant(cmd.UserID, cmd.Reason)
	})
}

// HandleSuspendTenant handles tenant suspension commands
func (h *TenantCommandHandler) HandleSuspendTenant(ctx context.Context, cmd *SuspendTenantCommand) ([]Event, error) {
	return h.handleStatusChange(ctx, cmd.AggregateID, cmd.UserID, "suspend", cmd.Reason, func(agg *TenantAggregate) error {
		return agg.SuspendTenant(cmd.UserID, cmd.Reason)
	})
}

// HandleChangeTenantPlan handles tenant plan change commands
func (h *TenantCommandHandler) HandleChangeTenantPlan(ctx context.Context, cmd *ChangeTenantPlanCommand) ([]Event, error) {
	h.logger.Info("Handling change tenant plan command", "tenant_id", cmd.AggregateID, "new_plan", cmd.NewPlan)

	// Validate plan change
	if err := h.validatePlanChange(ctx, cmd); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	// Load aggregate
	aggregate, err := h.loadAggregate(ctx, cmd.AggregateID)
	if err != nil {
		return nil, err
	}

	// Execute command
	err = aggregate.ChangePlan(cmd.UserID, cmd.NewPlan, cmd.NewMaxUsers, cmd.Reason)
	if err != nil {
		return nil, fmt.Errorf("failed to change plan: %w", err)
	}

	// Save events
	uncommittedEvents := aggregate.GetUncommittedEvents()
	err = h.eventStore.SaveEvents(ctx, cmd.AggregateID, uncommittedEvents, aggregate.GetVersion()-int64(len(uncommittedEvents)))
	if err != nil {
		return nil, fmt.Errorf("failed to save events: %w", err)
	}

	h.logger.Info("Tenant plan changed successfully", "tenant_id", cmd.AggregateID)
	return uncommittedEvents, nil
}

// HandleUpdateTenantSettings handles tenant settings update commands
func (h *TenantCommandHandler) HandleUpdateTenantSettings(ctx context.Context, cmd *UpdateTenantSettingsCommand) ([]Event, error) {
	h.logger.Info("Handling update tenant settings command", "tenant_id", cmd.AggregateID)

	// Load aggregate
	aggregate, err := h.loadAggregate(ctx, cmd.AggregateID)
	if err != nil {
		return nil, err
	}

	// Get current state for comparison
	tenant := aggregate.GetTenant()
	if tenant == nil {
		return nil, fmt.Errorf("tenant not found")
	}

	// Create settings updated event
	event := &TenantSettingsUpdatedEvent{
		BaseEvent: BaseEvent{
			AggregateID: cmd.AggregateID,
			EventType:   TenantSettingsUpdatedEventType,
			Timestamp:   cmd.Timestamp,
			Version:     aggregate.GetVersion() + 1,
			UserID:      cmd.UserID,
			TenantID:    cmd.TenantID,
		},
		OldSettings: tenant.Settings,
		NewSettings: cmd.Settings,
	}

	// Apply and save event
	events := []Event{event}
	err = h.eventStore.SaveEvents(ctx, cmd.AggregateID, events, aggregate.GetVersion())
	if err != nil {
		return nil, fmt.Errorf("failed to save events: %w", err)
	}

	h.logger.Info("Tenant settings updated successfully", "tenant_id", cmd.AggregateID)
	return events, nil
}

// HandleUpdateTenantMetadata handles tenant metadata update commands
func (h *TenantCommandHandler) HandleUpdateTenantMetadata(ctx context.Context, cmd *UpdateTenantMetadataCommand) ([]Event, error) {
	h.logger.Info("Handling update tenant metadata command", "tenant_id", cmd.AggregateID)

	// Load aggregate
	aggregate, err := h.loadAggregate(ctx, cmd.AggregateID)
	if err != nil {
		return nil, err
	}

	// Get current state for comparison
	tenant := aggregate.GetTenant()
	if tenant == nil {
		return nil, fmt.Errorf("tenant not found")
	}

	// Create metadata updated event
	event := &TenantMetadataUpdatedEvent{
		BaseEvent: BaseEvent{
			AggregateID: cmd.AggregateID,
			EventType:   TenantMetadataUpdatedEventType,
			Timestamp:   cmd.Timestamp,
			Version:     aggregate.GetVersion() + 1,
			UserID:      cmd.UserID,
			TenantID:    cmd.TenantID,
		},
		OldMetadata: tenant.Metadata,
		NewMetadata: cmd.Metadata,
	}

	// Apply and save event
	events := []Event{event}
	err = h.eventStore.SaveEvents(ctx, cmd.AggregateID, events, aggregate.GetVersion())
	if err != nil {
		return nil, fmt.Errorf("failed to save events: %w", err)
	}

	h.logger.Info("Tenant metadata updated successfully", "tenant_id", cmd.AggregateID)
	return events, nil
}

// Helper methods

func (h *TenantCommandHandler) loadAggregate(ctx context.Context, aggregateID uuid.UUID) (*TenantAggregate, error) {
	aggregate := NewTenantAggregate(aggregateID)
	events, err := h.eventStore.GetEvents(ctx, aggregateID)
	if err != nil {
		return nil, fmt.Errorf("failed to load events: %w", err)
	}

	if len(events) == 0 {
		return nil, fmt.Errorf("tenant not found")
	}

	err = aggregate.LoadFromHistory(events)
	if err != nil {
		return nil, fmt.Errorf("failed to load aggregate from history: %w", err)
	}

	return aggregate, nil
}

func (h *TenantCommandHandler) handleStatusChange(ctx context.Context, aggregateID, userID uuid.UUID, action, reason string, fn func(*TenantAggregate) error) ([]Event, error) {
	h.logger.Info("Handling tenant status change", "tenant_id", aggregateID, "action", action)

	// Load aggregate
	aggregate, err := h.loadAggregate(ctx, aggregateID)
	if err != nil {
		return nil, err
	}

	// Execute command
	err = fn(aggregate)
	if err != nil {
		return nil, fmt.Errorf("failed to %s tenant: %w", action, err)
	}

	// Save events
	uncommittedEvents := aggregate.GetUncommittedEvents()
	err = h.eventStore.SaveEvents(ctx, aggregateID, uncommittedEvents, aggregate.GetVersion()-int64(len(uncommittedEvents)))
	if err != nil {
		return nil, fmt.Errorf("failed to save events: %w", err)
	}

	h.logger.Info("Tenant status changed successfully", "tenant_id", aggregateID, "action", action)
	return uncommittedEvents, nil
}

func (h *TenantCommandHandler) validateCreateTenant(ctx context.Context, cmd *CreateTenantCommand) error {
	// Validate slug uniqueness
	exists, err := h.readModelRepo.ExistsBySlug(ctx, cmd.Slug, nil)
	if err != nil {
		return fmt.Errorf("failed to check slug uniqueness: %w", err)
	}
	if exists {
		return fmt.Errorf("tenant slug already exists")
	}

	// Validate domain uniqueness if provided
	if cmd.Domain != nil && *cmd.Domain != "" {
		exists, err := h.readModelRepo.ExistsByDomain(ctx, *cmd.Domain, nil)
		if err != nil {
			return fmt.Errorf("failed to check domain uniqueness: %w", err)
		}
		if exists {
			return fmt.Errorf("tenant domain already exists")
		}
	}

	return nil
}

func (h *TenantCommandHandler) validateUpdateTenant(ctx context.Context, cmd *UpdateTenantCommand) error {
	// Validate domain uniqueness if being updated
	if cmd.Domain != nil && *cmd.Domain != "" {
		exists, err := h.readModelRepo.ExistsByDomain(ctx, *cmd.Domain, &cmd.AggregateID)
		if err != nil {
			return fmt.Errorf("failed to check domain uniqueness: %w", err)
		}
		if exists {
			return fmt.Errorf("tenant domain already exists")
		}
	}

	return nil
}

func (h *TenantCommandHandler) validatePlanChange(ctx context.Context, cmd *ChangeTenantPlanCommand) error {
	// If reducing max users, check current user count
	if cmd.NewMaxUsers < cmd.OldMaxUsers {
		userCount, err := h.readModelRepo.CountUsersByTenantID(ctx, cmd.AggregateID)
		if err != nil {
			return fmt.Errorf("failed to count users: %w", err)
		}
		if userCount > cmd.NewMaxUsers {
			return fmt.Errorf("cannot reduce max users below current user count (%d)", userCount)
		}
	}

	return nil
}

func (h *TenantCommandHandler) buildChangesMap(cmd *UpdateTenantCommand) map[string]interface{} {
	changes := make(map[string]interface{})

	if cmd.Name != nil {
		changes["name"] = *cmd.Name
	}
	if cmd.Domain != nil {
		changes["domain"] = *cmd.Domain
	}
	if cmd.LogoURL != nil {
		changes["logo_url"] = *cmd.LogoURL
	}
	if cmd.PrimaryColor != nil {
		changes["primary_color"] = *cmd.PrimaryColor
	}
	if cmd.SecondaryColor != nil {
		changes["secondary_color"] = *cmd.SecondaryColor
	}
	if cmd.Status != nil {
		changes["status"] = string(*cmd.Status)
	}
	if cmd.Plan != nil {
		changes["plan"] = *cmd.Plan
	}
	if cmd.MaxUsers != nil {
		changes["max_users"] = *cmd.MaxUsers
	}
	if cmd.Settings != nil {
		changes["settings"] = cmd.Settings
	}
	if cmd.Metadata != nil {
		changes["metadata"] = cmd.Metadata
	}

	return changes
}
