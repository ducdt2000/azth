package repository

import (
	"context"
	"time"

	"github.com/ducdt2000/azth/backend/internal/domain"
	"github.com/ducdt2000/azth/backend/internal/modules/user/dto"
	"github.com/google/uuid"
)

// UserRepository defines the interface for user data access
// This is the shared repository interface used by all modules
type UserRepository interface {
	// Basic CRUD operations
	Create(ctx context.Context, user *domain.User) error
	GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error)
	GetByEmail(ctx context.Context, email string) (*domain.User, error)
	GetByUsername(ctx context.Context, username string) (*domain.User, error)
	Update(ctx context.Context, user *domain.User) error
	Delete(ctx context.Context, id uuid.UUID) error

	// Query operations
	List(ctx context.Context, req *dto.UserListRequest) ([]*domain.User, int, error)
	GetByTenantID(ctx context.Context, tenantID uuid.UUID, req *dto.UserListRequest) ([]*domain.User, int, error)
	GetUserStats(ctx context.Context, req *dto.UserStatsRequest) (*dto.UserStatsResponse, error)
	BulkUpdate(ctx context.Context, userIDs []uuid.UUID, action string) (int, []error)

	// Validation operations
	EmailExists(ctx context.Context, email string, excludeUserID *uuid.UUID) (bool, error)
	UsernameExists(ctx context.Context, username string, excludeUserID *uuid.UUID) (bool, error)

	// Role management
	GetUserRoles(ctx context.Context, userID uuid.UUID) ([]*domain.UserRole, error)
	AssignRole(ctx context.Context, userRole *domain.UserRole) error
	RevokeRole(ctx context.Context, userID, roleID uuid.UUID) error
	HasRole(ctx context.Context, userID, roleID uuid.UUID) (bool, error)

	// Session management
	GetUserSessions(ctx context.Context, userID uuid.UUID) ([]*domain.Session, error)
	RevokeAllSessions(ctx context.Context, userID uuid.UUID) error

	// Authentication and security operations
	UpdateLastLogin(ctx context.Context, userID uuid.UUID, loginTime time.Time) error
	UpdateLoginAttempts(ctx context.Context, userID uuid.UUID, attempts int) error
	UpdateLockedUntil(ctx context.Context, userID uuid.UUID, lockedUntil *time.Time) error
	IncrementLoginAttempts(ctx context.Context, userID uuid.UUID) error
	ResetLoginAttempts(ctx context.Context, userID uuid.UUID) error
	LockUser(ctx context.Context, userID uuid.UUID, lockedUntil *time.Time) error

	// MFA operations
	UpdateMFASecret(ctx context.Context, userID uuid.UUID, secret string) error
	UpdateBackupCodes(ctx context.Context, userID uuid.UUID, codes []string) error

	// Password operations (for auth modules)
	VerifyPassword(password, hash string) bool
	UpdatePassword(ctx context.Context, userID uuid.UUID, hashedPassword string) error
}
