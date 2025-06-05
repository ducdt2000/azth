package repository

import (
	"context"
	"time"

	"github.com/ducdt2000/azth/backend/internal/domain"
	"github.com/ducdt2000/azth/backend/internal/modules/user/dto"
	"github.com/google/uuid"
)

// UserRepository defines the interface for user data access
type UserRepository interface {
	// Create creates a new user
	Create(ctx context.Context, user *domain.User) error

	// GetByID retrieves a user by ID
	GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error)

	// GetByEmail retrieves a user by email
	GetByEmail(ctx context.Context, email string) (*domain.User, error)

	// GetByUsername retrieves a user by username
	GetByUsername(ctx context.Context, username string) (*domain.User, error)

	// Update updates an existing user
	Update(ctx context.Context, user *domain.User) error

	// Delete soft deletes a user
	Delete(ctx context.Context, id uuid.UUID) error

	// List retrieves users with pagination and filtering
	List(ctx context.Context, req *dto.UserListRequest) ([]*domain.User, int, error)

	// GetByTenantID retrieves users by tenant ID with pagination
	GetByTenantID(ctx context.Context, tenantID uuid.UUID, req *dto.UserListRequest) ([]*domain.User, int, error)

	// GetUserStats retrieves user statistics
	GetUserStats(ctx context.Context, req *dto.UserStatsRequest) (*dto.UserStatsResponse, error)

	// BulkUpdate performs bulk updates on users
	BulkUpdate(ctx context.Context, userIDs []uuid.UUID, action string) (int, []error)

	// EmailExists checks if an email already exists
	EmailExists(ctx context.Context, email string, excludeUserID *uuid.UUID) (bool, error)

	// UsernameExists checks if a username already exists
	UsernameExists(ctx context.Context, username string, excludeUserID *uuid.UUID) (bool, error)

	// GetUserRoles retrieves roles assigned to a user
	GetUserRoles(ctx context.Context, userID uuid.UUID) ([]*domain.UserRole, error)

	// AssignRole assigns a role to a user
	AssignRole(ctx context.Context, userRole *domain.UserRole) error

	// RevokeRole revokes a role from a user
	RevokeRole(ctx context.Context, userID, roleID uuid.UUID) error

	// HasRole checks if a user has a specific role
	HasRole(ctx context.Context, userID, roleID uuid.UUID) (bool, error)

	// GetUserSessions retrieves active sessions for a user
	GetUserSessions(ctx context.Context, userID uuid.UUID) ([]*domain.Session, error)

	// RevokeAllSessions revokes all sessions for a user
	RevokeAllSessions(ctx context.Context, userID uuid.UUID) error

	// UpdateLastLogin updates the last login timestamp
	UpdateLastLogin(ctx context.Context, userID uuid.UUID) error

	// IncrementLoginAttempts increments login attempts counter
	IncrementLoginAttempts(ctx context.Context, userID uuid.UUID) error

	// ResetLoginAttempts resets login attempts counter
	ResetLoginAttempts(ctx context.Context, userID uuid.UUID) error

	// LockUser locks a user account until specified time
	LockUser(ctx context.Context, userID uuid.UUID, lockedUntil *time.Time) error
}
