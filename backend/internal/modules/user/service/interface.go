package service

import (
	"context"

	"github.com/ducdt2000/azth/backend/internal/domain"
	"github.com/ducdt2000/azth/backend/internal/modules/user/dto"
	"github.com/google/uuid"
)

// UserService defines the interface for user business logic
type UserService interface {
	// CreateUser creates a new user with validation and business rules
	CreateUser(ctx context.Context, req *dto.CreateUserRequest, tenantID uuid.UUID) (*dto.UserResponse, error)

	// GetUser retrieves a user by ID
	GetUser(ctx context.Context, id uuid.UUID) (*dto.UserResponse, error)

	// GetUserByEmail retrieves a user by email
	GetUserByEmail(ctx context.Context, email string) (*dto.UserResponse, error)

	// GetUserByUsername retrieves a user by username
	GetUserByUsername(ctx context.Context, username string) (*dto.UserResponse, error)

	// UpdateUser updates an existing user with validation
	UpdateUser(ctx context.Context, id uuid.UUID, req *dto.UpdateUserRequest) (*dto.UserResponse, error)

	// ChangePassword changes a user's password with validation
	ChangePassword(ctx context.Context, userID uuid.UUID, req *dto.ChangePasswordRequest) error

	// DeleteUser soft deletes a user
	DeleteUser(ctx context.Context, id uuid.UUID) error

	// ListUsers retrieves users with pagination and filtering
	ListUsers(ctx context.Context, req *dto.UserListRequest) (*dto.UserListResponse, error)

	// GetUsersByTenant retrieves users by tenant ID with pagination
	GetUsersByTenant(ctx context.Context, tenantID uuid.UUID, req *dto.UserListRequest) (*dto.UserListResponse, error)

	// GetUserStats retrieves user statistics
	GetUserStats(ctx context.Context, req *dto.UserStatsRequest) (*dto.UserStatsResponse, error)

	// BulkUpdateUsers performs bulk operations on users
	BulkUpdateUsers(ctx context.Context, req *dto.BulkUserRequest) (*dto.BulkOperationResponse, error)

	// AssignRole assigns a role to a user
	AssignRole(ctx context.Context, userID uuid.UUID, req *dto.AssignRoleRequest) (*dto.UserRoleResponse, error)

	// RevokeRole revokes a role from a user
	RevokeRole(ctx context.Context, userID uuid.UUID, req *dto.RevokeRoleRequest) error

	// GetUserRoles retrieves roles assigned to a user
	GetUserRoles(ctx context.Context, userID uuid.UUID) ([]*dto.UserRoleResponse, error)

	// ActivateUser activates a user account
	ActivateUser(ctx context.Context, userID uuid.UUID) error

	// DeactivateUser deactivates a user account
	DeactivateUser(ctx context.Context, userID uuid.UUID) error

	// SuspendUser suspends a user account
	SuspendUser(ctx context.Context, userID uuid.UUID) error

	// VerifyEmail verifies a user's email address
	VerifyEmail(ctx context.Context, userID uuid.UUID) error

	// VerifyPhone verifies a user's phone number
	VerifyPhone(ctx context.Context, userID uuid.UUID) error

	// EnableMFA enables multi-factor authentication for a user
	EnableMFA(ctx context.Context, userID uuid.UUID) (string, []string, error)

	// DisableMFA disables multi-factor authentication for a user
	DisableMFA(ctx context.Context, userID uuid.UUID) error

	// GetUserSessions retrieves active sessions for a user
	GetUserSessions(ctx context.Context, userID uuid.UUID) ([]*domain.Session, error)

	// RevokeAllSessions revokes all sessions for a user
	RevokeAllSessions(ctx context.Context, userID uuid.UUID) error

	// ValidateUserCredentials validates user credentials for authentication
	ValidateUserCredentials(ctx context.Context, email, password string) (*domain.User, error)

	// HandleLoginAttempt handles login attempt tracking and account locking
	HandleLoginAttempt(ctx context.Context, userID uuid.UUID, success bool) error
}
