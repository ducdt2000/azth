package cqrs

import (
	"time"

	"github.com/ducdt2000/azth/backend/internal/domain"
	"github.com/google/uuid"
)

// Event represents an event in the event sourcing pattern
type Event interface {
	GetAggregateID() uuid.UUID
	GetEventType() string
	GetTimestamp() time.Time
	GetVersion() int64
}

// BaseEvent provides common event functionality
type BaseEvent struct {
	AggregateID uuid.UUID `json:"aggregate_id"`
	EventType   string    `json:"event_type"`
	Timestamp   time.Time `json:"timestamp"`
	Version     int64     `json:"version"`
	UserID      uuid.UUID `json:"user_id"`
	TenantID    uuid.UUID `json:"tenant_id"`
}

func (e BaseEvent) GetAggregateID() uuid.UUID {
	return e.AggregateID
}

func (e BaseEvent) GetEventType() string {
	return e.EventType
}

func (e BaseEvent) GetTimestamp() time.Time {
	return e.Timestamp
}

func (e BaseEvent) GetVersion() int64 {
	return e.Version
}

func (e BaseEvent) GetUserID() uuid.UUID {
	return e.UserID
}

func (e BaseEvent) GetTenantID() uuid.UUID {
	return e.TenantID
}

// Tenant Events

// TenantCreatedEvent represents a tenant creation event
type TenantCreatedEvent struct {
	BaseEvent
	Name           string                 `json:"name"`
	Slug           string                 `json:"slug"`
	Domain         *string                `json:"domain"`
	LogoURL        *string                `json:"logo_url"`
	PrimaryColor   *string                `json:"primary_color"`
	SecondaryColor *string                `json:"secondary_color"`
	Status         domain.TenantStatus    `json:"status"`
	Plan           string                 `json:"plan"`
	MaxUsers       int                    `json:"max_users"`
	Settings       map[string]interface{} `json:"settings"`
	Metadata       map[string]interface{} `json:"metadata"`
}

// TenantUpdatedEvent represents a tenant update event
type TenantUpdatedEvent struct {
	BaseEvent
	Changes map[string]interface{} `json:"changes"`
}

// TenantDeletedEvent represents a tenant deletion event
type TenantDeletedEvent struct {
	BaseEvent
	Reason    string    `json:"reason"`
	DeletedAt time.Time `json:"deleted_at"`
}

// TenantActivatedEvent represents a tenant activation event
type TenantActivatedEvent struct {
	BaseEvent
	PreviousStatus domain.TenantStatus `json:"previous_status"`
	Reason         string              `json:"reason"`
}

// TenantDeactivatedEvent represents a tenant deactivation event
type TenantDeactivatedEvent struct {
	BaseEvent
	PreviousStatus domain.TenantStatus `json:"previous_status"`
	Reason         string              `json:"reason"`
}

// TenantSuspendedEvent represents a tenant suspension event
type TenantSuspendedEvent struct {
	BaseEvent
	PreviousStatus domain.TenantStatus `json:"previous_status"`
	Reason         string              `json:"reason"`
	SuspendedAt    time.Time           `json:"suspended_at"`
}

// TenantPlanChangedEvent represents a tenant plan change event
type TenantPlanChangedEvent struct {
	BaseEvent
	OldPlan     string `json:"old_plan"`
	NewPlan     string `json:"new_plan"`
	OldMaxUsers int    `json:"old_max_users"`
	NewMaxUsers int    `json:"new_max_users"`
	Reason      string `json:"reason"`
}

// TenantSettingsUpdatedEvent represents a tenant settings update event
type TenantSettingsUpdatedEvent struct {
	BaseEvent
	OldSettings map[string]interface{} `json:"old_settings"`
	NewSettings map[string]interface{} `json:"new_settings"`
}

// TenantMetadataUpdatedEvent represents a tenant metadata update event
type TenantMetadataUpdatedEvent struct {
	BaseEvent
	OldMetadata map[string]interface{} `json:"old_metadata"`
	NewMetadata map[string]interface{} `json:"new_metadata"`
}

// Event type constants
const (
	TenantCreatedEventType         = "tenant.created"
	TenantUpdatedEventType         = "tenant.updated"
	TenantDeletedEventType         = "tenant.deleted"
	TenantActivatedEventType       = "tenant.activated"
	TenantDeactivatedEventType     = "tenant.deactivated"
	TenantSuspendedEventType       = "tenant.suspended"
	TenantPlanChangedEventType     = "tenant.plan_changed"
	TenantSettingsUpdatedEventType = "tenant.settings_updated"
	TenantMetadataUpdatedEventType = "tenant.metadata_updated"
)

// NewTenantCreatedEvent creates a new TenantCreatedEvent
func NewTenantCreatedEvent(tenantID, userID uuid.UUID, version int64, tenant *domain.Tenant) *TenantCreatedEvent {
	return &TenantCreatedEvent{
		BaseEvent: BaseEvent{
			AggregateID: tenantID,
			EventType:   TenantCreatedEventType,
			Timestamp:   time.Now(),
			Version:     version,
			UserID:      userID,
			TenantID:    tenantID,
		},
		Name:           tenant.Name,
		Slug:           tenant.Slug,
		Domain:         tenant.Domain,
		LogoURL:        tenant.LogoURL,
		PrimaryColor:   tenant.PrimaryColor,
		SecondaryColor: tenant.SecondaryColor,
		Status:         tenant.Status,
		Plan:           tenant.Plan,
		MaxUsers:       tenant.MaxUsers,
		Settings:       tenant.Settings,
		Metadata:       tenant.Metadata,
	}
}

// NewTenantUpdatedEvent creates a new TenantUpdatedEvent
func NewTenantUpdatedEvent(tenantID, userID uuid.UUID, version int64, changes map[string]interface{}) *TenantUpdatedEvent {
	return &TenantUpdatedEvent{
		BaseEvent: BaseEvent{
			AggregateID: tenantID,
			EventType:   TenantUpdatedEventType,
			Timestamp:   time.Now(),
			Version:     version,
			UserID:      userID,
			TenantID:    tenantID,
		},
		Changes: changes,
	}
}

// NewTenantDeletedEvent creates a new TenantDeletedEvent
func NewTenantDeletedEvent(tenantID, userID uuid.UUID, version int64, reason string) *TenantDeletedEvent {
	return &TenantDeletedEvent{
		BaseEvent: BaseEvent{
			AggregateID: tenantID,
			EventType:   TenantDeletedEventType,
			Timestamp:   time.Now(),
			Version:     version,
			UserID:      userID,
			TenantID:    tenantID,
		},
		Reason:    reason,
		DeletedAt: time.Now(),
	}
}

// NewTenantActivatedEvent creates a new TenantActivatedEvent
func NewTenantActivatedEvent(tenantID, userID uuid.UUID, version int64, previousStatus domain.TenantStatus, reason string) *TenantActivatedEvent {
	return &TenantActivatedEvent{
		BaseEvent: BaseEvent{
			AggregateID: tenantID,
			EventType:   TenantActivatedEventType,
			Timestamp:   time.Now(),
			Version:     version,
			UserID:      userID,
			TenantID:    tenantID,
		},
		PreviousStatus: previousStatus,
		Reason:         reason,
	}
}

// NewTenantDeactivatedEvent creates a new TenantDeactivatedEvent
func NewTenantDeactivatedEvent(tenantID, userID uuid.UUID, version int64, previousStatus domain.TenantStatus, reason string) *TenantDeactivatedEvent {
	return &TenantDeactivatedEvent{
		BaseEvent: BaseEvent{
			AggregateID: tenantID,
			EventType:   TenantDeactivatedEventType,
			Timestamp:   time.Now(),
			Version:     version,
			UserID:      userID,
			TenantID:    tenantID,
		},
		PreviousStatus: previousStatus,
		Reason:         reason,
	}
}

// NewTenantSuspendedEvent creates a new TenantSuspendedEvent
func NewTenantSuspendedEvent(tenantID, userID uuid.UUID, version int64, previousStatus domain.TenantStatus, reason string) *TenantSuspendedEvent {
	return &TenantSuspendedEvent{
		BaseEvent: BaseEvent{
			AggregateID: tenantID,
			EventType:   TenantSuspendedEventType,
			Timestamp:   time.Now(),
			Version:     version,
			UserID:      userID,
			TenantID:    tenantID,
		},
		PreviousStatus: previousStatus,
		Reason:         reason,
		SuspendedAt:    time.Now(),
	}
}

// NewTenantPlanChangedEvent creates a new TenantPlanChangedEvent
func NewTenantPlanChangedEvent(tenantID, userID uuid.UUID, version int64, oldPlan, newPlan string, oldMaxUsers, newMaxUsers int, reason string) *TenantPlanChangedEvent {
	return &TenantPlanChangedEvent{
		BaseEvent: BaseEvent{
			AggregateID: tenantID,
			EventType:   TenantPlanChangedEventType,
			Timestamp:   time.Now(),
			Version:     version,
			UserID:      userID,
			TenantID:    tenantID,
		},
		OldPlan:     oldPlan,
		NewPlan:     newPlan,
		OldMaxUsers: oldMaxUsers,
		NewMaxUsers: newMaxUsers,
		Reason:      reason,
	}
}
