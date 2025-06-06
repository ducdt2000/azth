package cqrs

import (
	"time"

	"github.com/google/uuid"
)

// CommandType represents the type of command
type CommandType string

const (
	CreateUserCommandType     CommandType = "CreateUser"
	UpdateUserCommandType     CommandType = "UpdateUser"
	DeleteUserCommandType     CommandType = "DeleteUser"
	ActivateUserCommandType   CommandType = "ActivateUser"
	DeactivateUserCommandType CommandType = "DeactivateUser"
	SuspendUserCommandType    CommandType = "SuspendUser"
	ChangePasswordCommandType CommandType = "ChangePassword"
	VerifyEmailCommandType    CommandType = "VerifyEmail"
	VerifyPhoneCommandType    CommandType = "VerifyPhone"
	EnableMFACommandType      CommandType = "EnableMFA"
	DisableMFACommandType     CommandType = "DisableMFA"
	UpdateProfileCommandType  CommandType = "UpdateProfile"
	AssignRoleCommandType     CommandType = "AssignRole"
	RevokeRoleCommandType     CommandType = "RevokeRole"
)

// Command represents a command in the CQRS pattern
type Command interface {
	GetCommandType() CommandType
	GetAggregateID() uuid.UUID
	GetTimestamp() time.Time
	GetUserID() uuid.UUID
	GetTenantID() uuid.UUID
}

// BaseCommand provides common fields for all commands
type BaseCommand struct {
	AggregateID uuid.UUID   `json:"aggregate_id"`
	CommandType CommandType `json:"command_type"`
	Timestamp   time.Time   `json:"timestamp"`
	UserID      uuid.UUID   `json:"user_id"`
	TenantID    uuid.UUID   `json:"tenant_id"`
}

// GetCommandType returns the command type
func (c BaseCommand) GetCommandType() CommandType {
	return c.CommandType
}

// GetAggregateID returns the aggregate ID
func (c BaseCommand) GetAggregateID() uuid.UUID {
	return c.AggregateID
}

// GetTimestamp returns the timestamp
func (c BaseCommand) GetTimestamp() time.Time {
	return c.Timestamp
}

// GetUserID returns the user ID
func (c BaseCommand) GetUserID() uuid.UUID {
	return c.UserID
}

// GetTenantID returns the tenant ID
func (c BaseCommand) GetTenantID() uuid.UUID {
	return c.TenantID
}

// CreateUserCommand represents a command to create a new user
type CreateUserCommand struct {
	BaseCommand
	Email       string                 `json:"email"`
	Username    string                 `json:"username"`
	Password    string                 `json:"password"`
	FirstName   string                 `json:"first_name"`
	LastName    string                 `json:"last_name"`
	PhoneNumber *string                `json:"phone_number,omitempty"`
	Avatar      *string                `json:"avatar,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// UpdateUserCommand represents a command to update a user
type UpdateUserCommand struct {
	BaseCommand
	Email       *string                `json:"email,omitempty"`
	Username    *string                `json:"username,omitempty"`
	FirstName   *string                `json:"first_name,omitempty"`
	LastName    *string                `json:"last_name,omitempty"`
	PhoneNumber *string                `json:"phone_number,omitempty"`
	Avatar      *string                `json:"avatar,omitempty"`
	Status      *string                `json:"status,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// DeleteUserCommand represents a command to delete a user
type DeleteUserCommand struct {
	BaseCommand
	Reason string `json:"reason"`
}

// ActivateUserCommand represents a command to activate a user
type ActivateUserCommand struct {
	BaseCommand
	Reason string `json:"reason"`
}

// DeactivateUserCommand represents a command to deactivate a user
type DeactivateUserCommand struct {
	BaseCommand
	Reason string `json:"reason"`
}

// SuspendUserCommand represents a command to suspend a user
type SuspendUserCommand struct {
	BaseCommand
	Reason string `json:"reason"`
}

// ChangePasswordCommand represents a command to change user password
type ChangePasswordCommand struct {
	BaseCommand
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

// VerifyEmailCommand represents a command to verify user email
type VerifyEmailCommand struct {
	BaseCommand
	VerificationToken string `json:"verification_token"`
}

// VerifyPhoneCommand represents a command to verify user phone
type VerifyPhoneCommand struct {
	BaseCommand
	VerificationCode string `json:"verification_code"`
}

// EnableMFACommand represents a command to enable MFA for user
type EnableMFACommand struct {
	BaseCommand
	Secret      string   `json:"secret"`
	BackupCodes []string `json:"backup_codes"`
	TOTPCode    string   `json:"totp_code"`
}

// DisableMFACommand represents a command to disable MFA for user
type DisableMFACommand struct {
	BaseCommand
	Reason string `json:"reason"`
}

// UpdateProfileCommand represents a command to update user profile
type UpdateProfileCommand struct {
	BaseCommand
	FirstName   *string                `json:"first_name,omitempty"`
	LastName    *string                `json:"last_name,omitempty"`
	Avatar      *string                `json:"avatar,omitempty"`
	PhoneNumber *string                `json:"phone_number,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// AssignRoleCommand represents a command to assign a role to user
type AssignRoleCommand struct {
	BaseCommand
	RoleID uuid.UUID `json:"role_id"`
}

// RevokeRoleCommand represents a command to revoke a role from user
type RevokeRoleCommand struct {
	BaseCommand
	RoleID uuid.UUID `json:"role_id"`
}

// Constructor functions

// NewCreateUserCommand creates a new CreateUserCommand
func NewCreateUserCommand(userID, createdByUserID, tenantID uuid.UUID, email, username, password, firstName, lastName string) *CreateUserCommand {
	return &CreateUserCommand{
		BaseCommand: BaseCommand{
			AggregateID: userID,
			CommandType: CreateUserCommandType,
			Timestamp:   time.Now(),
			UserID:      createdByUserID,
			TenantID:    tenantID,
		},
		Email:     email,
		Username:  username,
		Password:  password,
		FirstName: firstName,
		LastName:  lastName,
	}
}

// NewUpdateUserCommand creates a new UpdateUserCommand
func NewUpdateUserCommand(userID, updatedByUserID, tenantID uuid.UUID) *UpdateUserCommand {
	return &UpdateUserCommand{
		BaseCommand: BaseCommand{
			AggregateID: userID,
			CommandType: UpdateUserCommandType,
			Timestamp:   time.Now(),
			UserID:      updatedByUserID,
			TenantID:    tenantID,
		},
	}
}

// NewDeleteUserCommand creates a new DeleteUserCommand
func NewDeleteUserCommand(userID, deletedByUserID, tenantID uuid.UUID, reason string) *DeleteUserCommand {
	return &DeleteUserCommand{
		BaseCommand: BaseCommand{
			AggregateID: userID,
			CommandType: DeleteUserCommandType,
			Timestamp:   time.Now(),
			UserID:      deletedByUserID,
			TenantID:    tenantID,
		},
		Reason: reason,
	}
}

// NewActivateUserCommand creates a new ActivateUserCommand
func NewActivateUserCommand(userID, activatedByUserID, tenantID uuid.UUID, reason string) *ActivateUserCommand {
	return &ActivateUserCommand{
		BaseCommand: BaseCommand{
			AggregateID: userID,
			CommandType: ActivateUserCommandType,
			Timestamp:   time.Now(),
			UserID:      activatedByUserID,
			TenantID:    tenantID,
		},
		Reason: reason,
	}
}

// NewDeactivateUserCommand creates a new DeactivateUserCommand
func NewDeactivateUserCommand(userID, deactivatedByUserID, tenantID uuid.UUID, reason string) *DeactivateUserCommand {
	return &DeactivateUserCommand{
		BaseCommand: BaseCommand{
			AggregateID: userID,
			CommandType: DeactivateUserCommandType,
			Timestamp:   time.Now(),
			UserID:      deactivatedByUserID,
			TenantID:    tenantID,
		},
		Reason: reason,
	}
}

// NewSuspendUserCommand creates a new SuspendUserCommand
func NewSuspendUserCommand(userID, suspendedByUserID, tenantID uuid.UUID, reason string) *SuspendUserCommand {
	return &SuspendUserCommand{
		BaseCommand: BaseCommand{
			AggregateID: userID,
			CommandType: SuspendUserCommandType,
			Timestamp:   time.Now(),
			UserID:      suspendedByUserID,
			TenantID:    tenantID,
		},
		Reason: reason,
	}
}

// NewChangePasswordCommand creates a new ChangePasswordCommand
func NewChangePasswordCommand(userID, tenantID uuid.UUID, currentPassword, newPassword string) *ChangePasswordCommand {
	return &ChangePasswordCommand{
		BaseCommand: BaseCommand{
			AggregateID: userID,
			CommandType: ChangePasswordCommandType,
			Timestamp:   time.Now(),
			UserID:      userID, // User changing their own password
			TenantID:    tenantID,
		},
		CurrentPassword: currentPassword,
		NewPassword:     newPassword,
	}
}

// NewVerifyEmailCommand creates a new VerifyEmailCommand
func NewVerifyEmailCommand(userID, tenantID uuid.UUID, verificationToken string) *VerifyEmailCommand {
	return &VerifyEmailCommand{
		BaseCommand: BaseCommand{
			AggregateID: userID,
			CommandType: VerifyEmailCommandType,
			Timestamp:   time.Now(),
			UserID:      userID,
			TenantID:    tenantID,
		},
		VerificationToken: verificationToken,
	}
}

// NewVerifyPhoneCommand creates a new VerifyPhoneCommand
func NewVerifyPhoneCommand(userID, tenantID uuid.UUID, verificationCode string) *VerifyPhoneCommand {
	return &VerifyPhoneCommand{
		BaseCommand: BaseCommand{
			AggregateID: userID,
			CommandType: VerifyPhoneCommandType,
			Timestamp:   time.Now(),
			UserID:      userID,
			TenantID:    tenantID,
		},
		VerificationCode: verificationCode,
	}
}

// NewEnableMFACommand creates a new EnableMFACommand
func NewEnableMFACommand(userID, tenantID uuid.UUID, secret string, backupCodes []string, totpCode string) *EnableMFACommand {
	return &EnableMFACommand{
		BaseCommand: BaseCommand{
			AggregateID: userID,
			CommandType: EnableMFACommandType,
			Timestamp:   time.Now(),
			UserID:      userID,
			TenantID:    tenantID,
		},
		Secret:      secret,
		BackupCodes: backupCodes,
		TOTPCode:    totpCode,
	}
}

// NewDisableMFACommand creates a new DisableMFACommand
func NewDisableMFACommand(userID, tenantID uuid.UUID, reason string) *DisableMFACommand {
	return &DisableMFACommand{
		BaseCommand: BaseCommand{
			AggregateID: userID,
			CommandType: DisableMFACommandType,
			Timestamp:   time.Now(),
			UserID:      userID,
			TenantID:    tenantID,
		},
		Reason: reason,
	}
}

// NewUpdateProfileCommand creates a new UpdateProfileCommand
func NewUpdateProfileCommand(userID, tenantID uuid.UUID) *UpdateProfileCommand {
	return &UpdateProfileCommand{
		BaseCommand: BaseCommand{
			AggregateID: userID,
			CommandType: UpdateProfileCommandType,
			Timestamp:   time.Now(),
			UserID:      userID,
			TenantID:    tenantID,
		},
	}
}

// NewAssignRoleCommand creates a new AssignRoleCommand
func NewAssignRoleCommand(userID, assignedByUserID, tenantID, roleID uuid.UUID) *AssignRoleCommand {
	return &AssignRoleCommand{
		BaseCommand: BaseCommand{
			AggregateID: userID,
			CommandType: AssignRoleCommandType,
			Timestamp:   time.Now(),
			UserID:      assignedByUserID,
			TenantID:    tenantID,
		},
		RoleID: roleID,
	}
}

// NewRevokeRoleCommand creates a new RevokeRoleCommand
func NewRevokeRoleCommand(userID, revokedByUserID, tenantID, roleID uuid.UUID) *RevokeRoleCommand {
	return &RevokeRoleCommand{
		BaseCommand: BaseCommand{
			AggregateID: userID,
			CommandType: RevokeRoleCommandType,
			Timestamp:   time.Now(),
			UserID:      revokedByUserID,
			TenantID:    tenantID,
		},
		RoleID: roleID,
	}
}
