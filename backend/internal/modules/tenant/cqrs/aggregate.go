package cqrs

import (
	"fmt"
	"time"

	"github.com/ducdt2000/azth/backend/internal/domain"
	"github.com/google/uuid"
)

// TenantAggregate represents the tenant aggregate root
type TenantAggregate struct {
	// Aggregate identity
	id      uuid.UUID
	version int64

	// Aggregate state
	tenant *domain.Tenant

	// Uncommitted events
	uncommittedEvents []Event
}

// NewTenantAggregate creates a new tenant aggregate
func NewTenantAggregate(id uuid.UUID) *TenantAggregate {
	return &TenantAggregate{
		id:                id,
		version:           0,
		uncommittedEvents: make([]Event, 0),
	}
}

// LoadFromHistory loads aggregate from event history
func (a *TenantAggregate) LoadFromHistory(events []Event) error {
	for _, event := range events {
		if err := a.apply(event); err != nil {
			return fmt.Errorf("failed to apply event: %w", err)
		}
		a.version = event.GetVersion()
	}
	return nil
}

// GetID returns the aggregate ID
func (a *TenantAggregate) GetID() uuid.UUID {
	return a.id
}

// GetVersion returns the current version
func (a *TenantAggregate) GetVersion() int64 {
	return a.version
}

// GetTenant returns the current tenant state
func (a *TenantAggregate) GetTenant() *domain.Tenant {
	if a.tenant == nil {
		return nil
	}
	// Return a copy to prevent external modification
	tenantCopy := *a.tenant
	return &tenantCopy
}

// GetUncommittedEvents returns uncommitted events
func (a *TenantAggregate) GetUncommittedEvents() []Event {
	return a.uncommittedEvents
}

// MarkEventsAsCommitted clears uncommitted events
func (a *TenantAggregate) MarkEventsAsCommitted() {
	a.uncommittedEvents = make([]Event, 0)
}

// CreateTenant handles tenant creation
func (a *TenantAggregate) CreateTenant(userID uuid.UUID, name, slug, plan string, maxUsers int, dm, logoURL, primaryColor, secondaryColor *string, settings, metadata map[string]interface{}) error {
	if a.tenant != nil {
		return fmt.Errorf("tenant already exists")
	}

	newTenant := &domain.Tenant{
		ID:             a.id,
		Name:           name,
		Slug:           slug,
		Domain:         dm,
		LogoURL:        logoURL,
		PrimaryColor:   primaryColor,
		SecondaryColor: secondaryColor,
		Status:         domain.TenantStatusActive,
		Plan:           plan,
		MaxUsers:       maxUsers,
		Settings:       settings,
		Metadata:       metadata,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}

	event := NewTenantCreatedEvent(a.id, userID, a.version+1, newTenant)
	return a.raiseEvent(event)
}

// UpdateTenant handles tenant updates
func (a *TenantAggregate) UpdateTenant(userID uuid.UUID, changes map[string]interface{}) error {
	if a.tenant == nil {
		return fmt.Errorf("tenant does not exist")
	}

	if len(changes) == 0 {
		return fmt.Errorf("no changes provided")
	}

	event := NewTenantUpdatedEvent(a.id, userID, a.version+1, changes)
	return a.raiseEvent(event)
}

// DeleteTenant handles tenant deletion
func (a *TenantAggregate) DeleteTenant(userID uuid.UUID, reason string) error {
	if a.tenant == nil {
		return fmt.Errorf("tenant does not exist")
	}

	if a.tenant.DeletedAt != nil {
		return fmt.Errorf("tenant already deleted")
	}

	event := NewTenantDeletedEvent(a.id, userID, a.version+1, reason)
	return a.raiseEvent(event)
}

// ActivateTenant handles tenant activation
func (a *TenantAggregate) ActivateTenant(userID uuid.UUID, reason string) error {
	if a.tenant == nil {
		return fmt.Errorf("tenant does not exist")
	}

	if a.tenant.Status == domain.TenantStatusActive {
		return fmt.Errorf("tenant is already active")
	}

	previousStatus := a.tenant.Status
	event := NewTenantActivatedEvent(a.id, userID, a.version+1, previousStatus, reason)
	return a.raiseEvent(event)
}

// DeactivateTenant handles tenant deactivation
func (a *TenantAggregate) DeactivateTenant(userID uuid.UUID, reason string) error {
	if a.tenant == nil {
		return fmt.Errorf("tenant does not exist")
	}

	if a.tenant.Status == domain.TenantStatusInactive {
		return fmt.Errorf("tenant is already inactive")
	}

	previousStatus := a.tenant.Status
	event := NewTenantDeactivatedEvent(a.id, userID, a.version+1, previousStatus, reason)
	return a.raiseEvent(event)
}

// SuspendTenant handles tenant suspension
func (a *TenantAggregate) SuspendTenant(userID uuid.UUID, reason string) error {
	if a.tenant == nil {
		return fmt.Errorf("tenant does not exist")
	}

	if a.tenant.Status == domain.TenantStatusSuspended {
		return fmt.Errorf("tenant is already suspended")
	}

	previousStatus := a.tenant.Status
	event := NewTenantSuspendedEvent(a.id, userID, a.version+1, previousStatus, reason)
	return a.raiseEvent(event)
}

// ChangePlan handles tenant plan changes
func (a *TenantAggregate) ChangePlan(userID uuid.UUID, newPlan string, newMaxUsers int, reason string) error {
	if a.tenant == nil {
		return fmt.Errorf("tenant does not exist")
	}

	if a.tenant.Plan == newPlan && a.tenant.MaxUsers == newMaxUsers {
		return fmt.Errorf("plan is already set to the requested values")
	}

	oldPlan := a.tenant.Plan
	oldMaxUsers := a.tenant.MaxUsers

	event := NewTenantPlanChangedEvent(a.id, userID, a.version+1, oldPlan, newPlan, oldMaxUsers, newMaxUsers, reason)
	return a.raiseEvent(event)
}

// raiseEvent adds an event to the uncommitted events list and applies it
func (a *TenantAggregate) raiseEvent(event Event) error {
	if err := a.apply(event); err != nil {
		return err
	}
	a.uncommittedEvents = append(a.uncommittedEvents, event)
	return nil
}

// apply applies an event to the aggregate state
func (a *TenantAggregate) apply(event Event) error {
	switch e := event.(type) {
	case *TenantCreatedEvent:
		return a.applyTenantCreated(e)
	case *TenantUpdatedEvent:
		return a.applyTenantUpdated(e)
	case *TenantDeletedEvent:
		return a.applyTenantDeleted(e)
	case *TenantActivatedEvent:
		return a.applyTenantActivated(e)
	case *TenantDeactivatedEvent:
		return a.applyTenantDeactivated(e)
	case *TenantSuspendedEvent:
		return a.applyTenantSuspended(e)
	case *TenantPlanChangedEvent:
		return a.applyTenantPlanChanged(e)
	case *TenantSettingsUpdatedEvent:
		return a.applyTenantSettingsUpdated(e)
	case *TenantMetadataUpdatedEvent:
		return a.applyTenantMetadataUpdated(e)
	default:
		return fmt.Errorf("unknown event type: %T", event)
	}
}

func (a *TenantAggregate) applyTenantCreated(event *TenantCreatedEvent) error {
	a.tenant = &domain.Tenant{
		ID:             event.AggregateID,
		Name:           event.Name,
		Slug:           event.Slug,
		Domain:         event.Domain,
		LogoURL:        event.LogoURL,
		PrimaryColor:   event.PrimaryColor,
		SecondaryColor: event.SecondaryColor,
		Status:         event.Status,
		Plan:           event.Plan,
		MaxUsers:       event.MaxUsers,
		Settings:       event.Settings,
		Metadata:       event.Metadata,
		CreatedAt:      event.Timestamp,
		UpdatedAt:      event.Timestamp,
	}
	a.version = event.Version
	return nil
}

func (a *TenantAggregate) applyTenantUpdated(event *TenantUpdatedEvent) error {
	if a.tenant == nil {
		return fmt.Errorf("cannot update non-existent tenant")
	}

	// Apply changes to tenant
	for field, value := range event.Changes {
		switch field {
		case "name":
			if name, ok := value.(string); ok {
				a.tenant.Name = name
			}
		case "domain":
			if domain, ok := value.(string); ok {
				a.tenant.Domain = &domain
			} else if value == nil {
				a.tenant.Domain = nil
			}
		case "logo_url":
			if logoURL, ok := value.(string); ok {
				a.tenant.LogoURL = &logoURL
			} else if value == nil {
				a.tenant.LogoURL = nil
			}
		case "primary_color":
			if color, ok := value.(string); ok {
				a.tenant.PrimaryColor = &color
			} else if value == nil {
				a.tenant.PrimaryColor = nil
			}
		case "secondary_color":
			if color, ok := value.(string); ok {
				a.tenant.SecondaryColor = &color
			} else if value == nil {
				a.tenant.SecondaryColor = nil
			}
		case "status":
			if status, ok := value.(string); ok {
				a.tenant.Status = domain.TenantStatus(status)
			}
		case "plan":
			if plan, ok := value.(string); ok {
				a.tenant.Plan = plan
			}
		case "max_users":
			if maxUsers, ok := value.(float64); ok {
				a.tenant.MaxUsers = int(maxUsers)
			}
		case "settings":
			if settings, ok := value.(map[string]interface{}); ok {
				a.tenant.Settings = settings
			}
		case "metadata":
			if metadata, ok := value.(map[string]interface{}); ok {
				a.tenant.Metadata = metadata
			}
		}
	}

	a.tenant.UpdatedAt = event.Timestamp
	a.version = event.Version
	return nil
}

func (a *TenantAggregate) applyTenantDeleted(event *TenantDeletedEvent) error {
	if a.tenant == nil {
		return fmt.Errorf("cannot delete non-existent tenant")
	}

	a.tenant.DeletedAt = &event.DeletedAt
	a.tenant.UpdatedAt = event.Timestamp
	a.version = event.Version
	return nil
}

func (a *TenantAggregate) applyTenantActivated(event *TenantActivatedEvent) error {
	if a.tenant == nil {
		return fmt.Errorf("cannot activate non-existent tenant")
	}

	a.tenant.Status = domain.TenantStatusActive
	a.tenant.UpdatedAt = event.Timestamp
	a.version = event.Version
	return nil
}

func (a *TenantAggregate) applyTenantDeactivated(event *TenantDeactivatedEvent) error {
	if a.tenant == nil {
		return fmt.Errorf("cannot deactivate non-existent tenant")
	}

	a.tenant.Status = domain.TenantStatusInactive
	a.tenant.UpdatedAt = event.Timestamp
	a.version = event.Version
	return nil
}

func (a *TenantAggregate) applyTenantSuspended(event *TenantSuspendedEvent) error {
	if a.tenant == nil {
		return fmt.Errorf("cannot suspend non-existent tenant")
	}

	a.tenant.Status = domain.TenantStatusSuspended
	a.tenant.UpdatedAt = event.Timestamp
	a.version = event.Version
	return nil
}

func (a *TenantAggregate) applyTenantPlanChanged(event *TenantPlanChangedEvent) error {
	if a.tenant == nil {
		return fmt.Errorf("cannot change plan for non-existent tenant")
	}

	a.tenant.Plan = event.NewPlan
	a.tenant.MaxUsers = event.NewMaxUsers
	a.tenant.UpdatedAt = event.Timestamp
	a.version = event.Version
	return nil
}

func (a *TenantAggregate) applyTenantSettingsUpdated(event *TenantSettingsUpdatedEvent) error {
	if a.tenant == nil {
		return fmt.Errorf("cannot update settings for non-existent tenant")
	}

	a.tenant.Settings = event.NewSettings
	a.tenant.UpdatedAt = event.Timestamp
	a.version = event.Version
	return nil
}

func (a *TenantAggregate) applyTenantMetadataUpdated(event *TenantMetadataUpdatedEvent) error {
	if a.tenant == nil {
		return fmt.Errorf("cannot update metadata for non-existent tenant")
	}

	a.tenant.Metadata = event.NewMetadata
	a.tenant.UpdatedAt = event.Timestamp
	a.version = event.Version
	return nil
}
