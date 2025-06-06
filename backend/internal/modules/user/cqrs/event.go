package cqrs

import (
	"encoding/json"
	"time"

	"github.com/ducdt2000/azth/backend/internal/domain"
	"github.com/google/uuid"
)

// EventType represents the type of event
type EventType string

const (
	UserCreatedEventType     EventType = "UserCreated"
	UserUpdatedEventType     EventType = "UserUpdated"
	UserDeletedEventType     EventType = "UserDeleted"
	UserActivatedEventType   EventType = "UserActivated"
	UserDeactivatedEventType EventType = "UserDeactivated"
	UserSuspendedEventType   EventType = "UserSuspended"
	PasswordChangedEventType EventType = "PasswordChanged"
	EmailVerifiedEventType   EventType = "EmailVerified"
	PhoneVerifiedEventType   EventType = "PhoneVerified"
	MFAEnabledEventType      EventType = "MFAEnabled"
	MFADisabledEventType     EventType = "MFADisabled"
	ProfileUpdatedEventType  EventType = "ProfileUpdated"
	RoleAssignedEventType    EventType = "RoleAssigned"
	RoleRevokedEventType     EventType = "RoleRevoked"
	LoginAttemptEventType    EventType = "LoginAttempt"
	LoginSuccessEventType    EventType = "LoginSuccess"
	LoginFailureEventType    EventType = "LoginFailure"
)

// Event represents an event in the CQRS pattern
type Event interface {
	GetEventType() EventType
	GetAggregateID() uuid.UUID
	GetVersion() int64
	GetTimestamp() time.Time
	GetUserID() uuid.UUID
	GetTenantID() uuid.UUID
	ToJSON() ([]byte, error)
}

// BaseEvent provides common fields for all events
type BaseEvent struct {
	AggregateID uuid.UUID `json:"aggregate_id"`
	EventType   EventType `json:"event_type"`
	Version     int64     `json:"version"`
	Timestamp   time.Time `json:"timestamp"`
	UserID      uuid.UUID `json:"user_id"`
	TenantID    uuid.UUID `json:"tenant_id"`
}

// GetEventType returns the event type
func (e BaseEvent) GetEventType() EventType {
	return e.EventType
}

// GetAggregateID returns the aggregate ID
func (e BaseEvent) GetAggregateID() uuid.UUID {
	return e.AggregateID
}

// GetVersion returns the event version
func (e BaseEvent) GetVersion() int64 {
	return e.Version
}

// GetTimestamp returns the timestamp
func (e BaseEvent) GetTimestamp() time.Time {
	return e.Timestamp
}

// GetUserID returns the user ID
func (e BaseEvent) GetUserID() uuid.UUID {
	return e.UserID
}

// GetTenantID returns the tenant ID
func (e BaseEvent) GetTenantID() uuid.UUID {
	return e.TenantID
}

// ToJSON converts the event to JSON
func (e BaseEvent) ToJSON() ([]byte, error) {
	return json.Marshal(e)
}

// UserCreatedEvent represents a user created event
type UserCreatedEvent struct {
	BaseEvent
	Email       string                 `json:"email"`
	Username    string                 `json:"username"`
	FirstName   string                 `json:"first_name"`
	LastName    string                 `json:"last_name"`
	PhoneNumber *string                `json:"phone_number,omitempty"`
	Avatar      *string                `json:"avatar,omitempty"`
	Status      domain.UserStatus      `json:"status"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// UserUpdatedEvent represents a user updated event
type UserUpdatedEvent struct {
	BaseEvent
	Changes map[string]interface{} `json:"changes"`
}

// UserDeletedEvent represents a user deleted event
type UserDeletedEvent struct {
	BaseEvent
	Reason    string    `json:"reason"`
	DeletedAt time.Time `json:"deleted_at"`
}

// UserActivatedEvent represents a user activated event
type UserActivatedEvent struct {
	BaseEvent
	PreviousStatus domain.UserStatus `json:"previous_status"`
	Reason         string            `json:"reason"`
}

// UserDeactivatedEvent represents a user deactivated event
type UserDeactivatedEvent struct {
	BaseEvent
	PreviousStatus domain.UserStatus `json:"previous_status"`
	Reason         string            `json:"reason"`
}

// UserSuspendedEvent represents a user suspended event
type UserSuspendedEvent struct {
	BaseEvent
	PreviousStatus domain.UserStatus `json:"previous_status"`
	Reason         string            `json:"reason"`
}

// PasswordChangedEvent represents a password changed event
type PasswordChangedEvent struct {
	BaseEvent
	PasswordChangedAt time.Time `json:"password_changed_at"`
}

// EmailVerifiedEvent represents an email verified event
type EmailVerifiedEvent struct {
	BaseEvent
	Email          string    `json:"email"`
	VerifiedAt     time.Time `json:"verified_at"`
	VerificationIP string    `json:"verification_ip,omitempty"`
	VerificationUA string    `json:"verification_ua,omitempty"`
}

// PhoneVerifiedEvent represents a phone verified event
type PhoneVerifiedEvent struct {
	BaseEvent
	PhoneNumber    string    `json:"phone_number"`
	VerifiedAt     time.Time `json:"verified_at"`
	VerificationIP string    `json:"verification_ip,omitempty"`
	VerificationUA string    `json:"verification_ua,omitempty"`
}

// MFAEnabledEvent represents an MFA enabled event
type MFAEnabledEvent struct {
	BaseEvent
	Secret    string    `json:"-"` // Don't include secret in JSON
	EnabledAt time.Time `json:"enabled_at"`
	EnabledIP string    `json:"enabled_ip,omitempty"`
	EnabledUA string    `json:"enabled_ua,omitempty"`
}

// MFADisabledEvent represents an MFA disabled event
type MFADisabledEvent struct {
	BaseEvent
	Reason     string    `json:"reason"`
	DisabledAt time.Time `json:"disabled_at"`
	DisabledIP string    `json:"disabled_ip,omitempty"`
	DisabledUA string    `json:"disabled_ua,omitempty"`
}

// ProfileUpdatedEvent represents a profile updated event
type ProfileUpdatedEvent struct {
	BaseEvent
	Changes map[string]interface{} `json:"changes"`
}

// RoleAssignedEvent represents a role assigned event
type RoleAssignedEvent struct {
	BaseEvent
	RoleID     uuid.UUID `json:"role_id"`
	AssignedAt time.Time `json:"assigned_at"`
}

// RoleRevokedEvent represents a role revoked event
type RoleRevokedEvent struct {
	BaseEvent
	RoleID    uuid.UUID `json:"role_id"`
	RevokedAt time.Time `json:"revoked_at"`
}

// LoginAttemptEvent represents a login attempt event
type LoginAttemptEvent struct {
	BaseEvent
	Email     string    `json:"email"`
	IPAddress string    `json:"ip_address"`
	UserAgent string    `json:"user_agent"`
	Success   bool      `json:"success"`
	Reason    string    `json:"reason,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// LoginSuccessEvent represents a successful login event
type LoginSuccessEvent struct {
	BaseEvent
	IPAddress string    `json:"ip_address"`
	UserAgent string    `json:"user_agent"`
	SessionID uuid.UUID `json:"session_id"`
	LoginAt   time.Time `json:"login_at"`
}

// LoginFailureEvent represents a failed login event
type LoginFailureEvent struct {
	BaseEvent
	Email         string     `json:"email"`
	IPAddress     string     `json:"ip_address"`
	UserAgent     string     `json:"user_agent"`
	Reason        string     `json:"reason"`
	AttemptCount  int        `json:"attempt_count"`
	AccountLocked bool       `json:"account_locked"`
	LockedUntil   *time.Time `json:"locked_until,omitempty"`
}

// Constructor functions

// NewUserCreatedEvent creates a new UserCreatedEvent
func NewUserCreatedEvent(userID, createdByUserID, tenantID uuid.UUID, version int64, user *domain.User) *UserCreatedEvent {
	return &UserCreatedEvent{
		BaseEvent: BaseEvent{
			AggregateID: userID,
			EventType:   UserCreatedEventType,
			Version:     version,
			Timestamp:   time.Now(),
			UserID:      createdByUserID,
			TenantID:    tenantID,
		},
		Email:       user.Email,
		Username:    user.Username,
		FirstName:   user.FirstName,
		LastName:    user.LastName,
		PhoneNumber: user.PhoneNumber,
		Avatar:      user.Avatar,
		Status:      user.Status,
		Metadata:    user.Metadata,
	}
}

// NewUserUpdatedEvent creates a new UserUpdatedEvent
func NewUserUpdatedEvent(userID, updatedByUserID, tenantID uuid.UUID, version int64, changes map[string]interface{}) *UserUpdatedEvent {
	return &UserUpdatedEvent{
		BaseEvent: BaseEvent{
			AggregateID: userID,
			EventType:   UserUpdatedEventType,
			Version:     version,
			Timestamp:   time.Now(),
			UserID:      updatedByUserID,
			TenantID:    tenantID,
		},
		Changes: changes,
	}
}

// NewUserDeletedEvent creates a new UserDeletedEvent
func NewUserDeletedEvent(userID, deletedByUserID, tenantID uuid.UUID, version int64, reason string) *UserDeletedEvent {
	deletedAt := time.Now()
	return &UserDeletedEvent{
		BaseEvent: BaseEvent{
			AggregateID: userID,
			EventType:   UserDeletedEventType,
			Version:     version,
			Timestamp:   deletedAt,
			UserID:      deletedByUserID,
			TenantID:    tenantID,
		},
		Reason:    reason,
		DeletedAt: deletedAt,
	}
}

// NewUserActivatedEvent creates a new UserActivatedEvent
func NewUserActivatedEvent(userID, activatedByUserID, tenantID uuid.UUID, version int64, previousStatus domain.UserStatus, reason string) *UserActivatedEvent {
	return &UserActivatedEvent{
		BaseEvent: BaseEvent{
			AggregateID: userID,
			EventType:   UserActivatedEventType,
			Version:     version,
			Timestamp:   time.Now(),
			UserID:      activatedByUserID,
			TenantID:    tenantID,
		},
		PreviousStatus: previousStatus,
		Reason:         reason,
	}
}

// NewUserDeactivatedEvent creates a new UserDeactivatedEvent
func NewUserDeactivatedEvent(userID, deactivatedByUserID, tenantID uuid.UUID, version int64, previousStatus domain.UserStatus, reason string) *UserDeactivatedEvent {
	return &UserDeactivatedEvent{
		BaseEvent: BaseEvent{
			AggregateID: userID,
			EventType:   UserDeactivatedEventType,
			Version:     version,
			Timestamp:   time.Now(),
			UserID:      deactivatedByUserID,
			TenantID:    tenantID,
		},
		PreviousStatus: previousStatus,
		Reason:         reason,
	}
}

// NewUserSuspendedEvent creates a new UserSuspendedEvent
func NewUserSuspendedEvent(userID, suspendedByUserID, tenantID uuid.UUID, version int64, previousStatus domain.UserStatus, reason string) *UserSuspendedEvent {
	return &UserSuspendedEvent{
		BaseEvent: BaseEvent{
			AggregateID: userID,
			EventType:   UserSuspendedEventType,
			Version:     version,
			Timestamp:   time.Now(),
			UserID:      suspendedByUserID,
			TenantID:    tenantID,
		},
		PreviousStatus: previousStatus,
		Reason:         reason,
	}
}

// NewPasswordChangedEvent creates a new PasswordChangedEvent
func NewPasswordChangedEvent(userID, tenantID uuid.UUID, version int64) *PasswordChangedEvent {
	changedAt := time.Now()
	return &PasswordChangedEvent{
		BaseEvent: BaseEvent{
			AggregateID: userID,
			EventType:   PasswordChangedEventType,
			Version:     version,
			Timestamp:   changedAt,
			UserID:      userID,
			TenantID:    tenantID,
		},
		PasswordChangedAt: changedAt,
	}
}

// NewEmailVerifiedEvent creates a new EmailVerifiedEvent
func NewEmailVerifiedEvent(userID, tenantID uuid.UUID, version int64, email, ip, ua string) *EmailVerifiedEvent {
	verifiedAt := time.Now()
	return &EmailVerifiedEvent{
		BaseEvent: BaseEvent{
			AggregateID: userID,
			EventType:   EmailVerifiedEventType,
			Version:     version,
			Timestamp:   verifiedAt,
			UserID:      userID,
			TenantID:    tenantID,
		},
		Email:          email,
		VerifiedAt:     verifiedAt,
		VerificationIP: ip,
		VerificationUA: ua,
	}
}

// NewPhoneVerifiedEvent creates a new PhoneVerifiedEvent
func NewPhoneVerifiedEvent(userID, tenantID uuid.UUID, version int64, phoneNumber, ip, ua string) *PhoneVerifiedEvent {
	verifiedAt := time.Now()
	return &PhoneVerifiedEvent{
		BaseEvent: BaseEvent{
			AggregateID: userID,
			EventType:   PhoneVerifiedEventType,
			Version:     version,
			Timestamp:   verifiedAt,
			UserID:      userID,
			TenantID:    tenantID,
		},
		PhoneNumber:    phoneNumber,
		VerifiedAt:     verifiedAt,
		VerificationIP: ip,
		VerificationUA: ua,
	}
}

// NewMFAEnabledEvent creates a new MFAEnabledEvent
func NewMFAEnabledEvent(userID, tenantID uuid.UUID, version int64, secret, ip, ua string) *MFAEnabledEvent {
	enabledAt := time.Now()
	return &MFAEnabledEvent{
		BaseEvent: BaseEvent{
			AggregateID: userID,
			EventType:   MFAEnabledEventType,
			Version:     version,
			Timestamp:   enabledAt,
			UserID:      userID,
			TenantID:    tenantID,
		},
		Secret:    secret,
		EnabledAt: enabledAt,
		EnabledIP: ip,
		EnabledUA: ua,
	}
}

// NewMFADisabledEvent creates a new MFADisabledEvent
func NewMFADisabledEvent(userID, tenantID uuid.UUID, version int64, reason, ip, ua string) *MFADisabledEvent {
	disabledAt := time.Now()
	return &MFADisabledEvent{
		BaseEvent: BaseEvent{
			AggregateID: userID,
			EventType:   MFADisabledEventType,
			Version:     version,
			Timestamp:   disabledAt,
			UserID:      userID,
			TenantID:    tenantID,
		},
		Reason:     reason,
		DisabledAt: disabledAt,
		DisabledIP: ip,
		DisabledUA: ua,
	}
}

// NewProfileUpdatedEvent creates a new ProfileUpdatedEvent
func NewProfileUpdatedEvent(userID, tenantID uuid.UUID, version int64, changes map[string]interface{}) *ProfileUpdatedEvent {
	return &ProfileUpdatedEvent{
		BaseEvent: BaseEvent{
			AggregateID: userID,
			EventType:   ProfileUpdatedEventType,
			Version:     version,
			Timestamp:   time.Now(),
			UserID:      userID,
			TenantID:    tenantID,
		},
		Changes: changes,
	}
}

// NewRoleAssignedEvent creates a new RoleAssignedEvent
func NewRoleAssignedEvent(userID, assignedByUserID, tenantID, roleID uuid.UUID, version int64) *RoleAssignedEvent {
	assignedAt := time.Now()
	return &RoleAssignedEvent{
		BaseEvent: BaseEvent{
			AggregateID: userID,
			EventType:   RoleAssignedEventType,
			Version:     version,
			Timestamp:   assignedAt,
			UserID:      assignedByUserID,
			TenantID:    tenantID,
		},
		RoleID:     roleID,
		AssignedAt: assignedAt,
	}
}

// NewRoleRevokedEvent creates a new RoleRevokedEvent
func NewRoleRevokedEvent(userID, revokedByUserID, tenantID, roleID uuid.UUID, version int64) *RoleRevokedEvent {
	revokedAt := time.Now()
	return &RoleRevokedEvent{
		BaseEvent: BaseEvent{
			AggregateID: userID,
			EventType:   RoleRevokedEventType,
			Version:     version,
			Timestamp:   revokedAt,
			UserID:      revokedByUserID,
			TenantID:    tenantID,
		},
		RoleID:    roleID,
		RevokedAt: revokedAt,
	}
}

// NewLoginSuccessEvent creates a new LoginSuccessEvent
func NewLoginSuccessEvent(userID, tenantID, sessionID uuid.UUID, version int64, ip, ua string) *LoginSuccessEvent {
	loginAt := time.Now()
	return &LoginSuccessEvent{
		BaseEvent: BaseEvent{
			AggregateID: userID,
			EventType:   LoginSuccessEventType,
			Version:     version,
			Timestamp:   loginAt,
			UserID:      userID,
			TenantID:    tenantID,
		},
		IPAddress: ip,
		UserAgent: ua,
		SessionID: sessionID,
		LoginAt:   loginAt,
	}
}

// NewLoginFailureEvent creates a new LoginFailureEvent
func NewLoginFailureEvent(userID, tenantID uuid.UUID, version int64, email, ip, ua, reason string, attemptCount int, accountLocked bool, lockedUntil *time.Time) *LoginFailureEvent {
	return &LoginFailureEvent{
		BaseEvent: BaseEvent{
			AggregateID: userID,
			EventType:   LoginFailureEventType,
			Version:     version,
			Timestamp:   time.Now(),
			UserID:      userID,
			TenantID:    tenantID,
		},
		Email:         email,
		IPAddress:     ip,
		UserAgent:     ua,
		Reason:        reason,
		AttemptCount:  attemptCount,
		AccountLocked: accountLocked,
		LockedUntil:   lockedUntil,
	}
}
