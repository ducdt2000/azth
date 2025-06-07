package service

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/ducdt2000/azth/backend/internal/domain"
	"github.com/ducdt2000/azth/backend/internal/modules/user/dto"
	"github.com/ducdt2000/azth/backend/internal/modules/user/repository"
	"github.com/ducdt2000/azth/backend/pkg/logger"
)

// userService implements UserService interface
type userService struct {
	userRepo repository.UserRepository
	logger   *logger.Logger
}

// NewUserService creates a new user service
func NewUserService(userRepo repository.UserRepository, logger *logger.Logger) UserService {
	return &userService{
		userRepo: userRepo,
		logger:   logger,
	}
}

// CreateUser creates a new user with validation and business rules
func (s *userService) CreateUser(ctx context.Context, req *dto.CreateUserRequest, tenantID uuid.UUID) (*dto.UserResponse, error) {
	// Validate email uniqueness
	emailExists, err := s.userRepo.EmailExists(ctx, req.Email, nil)
	if err != nil {
		s.logger.Error("Failed to check email existence", "error", err, "email", req.Email)
		return nil, fmt.Errorf("failed to validate email: %w", err)
	}
	if emailExists {
		return nil, fmt.Errorf("email already exists")
	}

	// Validate username uniqueness
	usernameExists, err := s.userRepo.UsernameExists(ctx, req.Username, nil)
	if err != nil {
		s.logger.Error("Failed to check username existence", "error", err, "username", req.Username)
		return nil, fmt.Errorf("failed to validate username: %w", err)
	}
	if usernameExists {
		return nil, fmt.Errorf("username already exists")
	}

	// Hash password
	hashedPassword, err := s.hashPassword(req.Password)
	if err != nil {
		s.logger.Error("Failed to hash password", "error", err)
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Create user entity
	user := &domain.User{
		ID:                uuid.New(),
		TenantID:          tenantID,
		Email:             req.Email,
		Username:          req.Username,
		PasswordHash:      hashedPassword,
		FirstName:         req.FirstName,
		LastName:          req.LastName,
		Avatar:            req.Avatar,
		PhoneNumber:       req.PhoneNumber,
		EmailVerified:     false,
		PhoneVerified:     false,
		MFAEnabled:        false,
		Status:            domain.UserStatusPending,
		LoginAttempts:     0,
		PasswordChangedAt: timePtr(time.Now()),
		Metadata:          domain.JSONMap(req.Metadata),
		CreatedAt:         time.Now(),
		UpdatedAt:         time.Now(),
	}

	// Save user
	err = s.userRepo.Create(ctx, user)
	if err != nil {
		s.logger.Error("Failed to create user", "error", err, "email", req.Email)
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// TODO: Send verification email
	// s.emailService.SendVerificationEmail(ctx, user)

	s.logger.Info("User created successfully", "user_id", user.ID, "email", user.Email)
	return s.mapUserToResponse(user), nil
}

// GetUser retrieves a user by ID
func (s *userService) GetUser(ctx context.Context, id uuid.UUID) (*dto.UserResponse, error) {
	user, err := s.userRepo.GetByID(ctx, id)
	if err != nil {
		s.logger.Error("Failed to get user", "error", err, "user_id", id)
		return nil, fmt.Errorf("user not found: %w", err)
	}

	return s.mapUserToResponse(user), nil
}

// GetUserByEmail retrieves a user by email
func (s *userService) GetUserByEmail(ctx context.Context, email string) (*dto.UserResponse, error) {
	user, err := s.userRepo.GetByEmail(ctx, email)
	if err != nil {
		s.logger.Error("Failed to get user by email", "error", err, "email", email)
		return nil, fmt.Errorf("user not found: %w", err)
	}

	return s.mapUserToResponse(user), nil
}

// GetUserByUsername retrieves a user by username
func (s *userService) GetUserByUsername(ctx context.Context, username string) (*dto.UserResponse, error) {
	user, err := s.userRepo.GetByUsername(ctx, username)
	if err != nil {
		s.logger.Error("Failed to get user by username", "error", err, "username", username)
		return nil, fmt.Errorf("user not found: %w", err)
	}

	return s.mapUserToResponse(user), nil
}

// UpdateUser updates an existing user with validation
func (s *userService) UpdateUser(ctx context.Context, id uuid.UUID, req *dto.UpdateUserRequest) (*dto.UserResponse, error) {
	// Get existing user
	user, err := s.userRepo.GetByID(ctx, id)
	if err != nil {
		s.logger.Error("Failed to get user for update", "error", err, "user_id", id)
		return nil, fmt.Errorf("user not found: %w", err)
	}

	// Validate email uniqueness if changing
	if req.Email != nil && *req.Email != user.Email {
		emailExists, err := s.userRepo.EmailExists(ctx, *req.Email, &id)
		if err != nil {
			s.logger.Error("Failed to check email existence", "error", err, "email", *req.Email)
			return nil, fmt.Errorf("failed to validate email: %w", err)
		}
		if emailExists {
			return nil, fmt.Errorf("email already exists")
		}
		user.Email = *req.Email
		user.EmailVerified = false // Reset verification when email changes
		user.EmailVerifiedAt = nil
	}

	// Validate username uniqueness if changing
	if req.Username != nil && *req.Username != user.Username {
		usernameExists, err := s.userRepo.UsernameExists(ctx, *req.Username, &id)
		if err != nil {
			s.logger.Error("Failed to check username existence", "error", err, "username", *req.Username)
			return nil, fmt.Errorf("failed to validate username: %w", err)
		}
		if usernameExists {
			return nil, fmt.Errorf("username already exists")
		}
		user.Username = *req.Username
	}

	// Update other fields
	if req.FirstName != nil {
		user.FirstName = *req.FirstName
	}
	if req.LastName != nil {
		user.LastName = *req.LastName
	}
	if req.PhoneNumber != nil {
		if *req.PhoneNumber != "" && (user.PhoneNumber == nil || *user.PhoneNumber != *req.PhoneNumber) {
			user.PhoneNumber = req.PhoneNumber
			user.PhoneVerified = false // Reset verification when phone changes
			user.PhoneVerifiedAt = nil
		} else if *req.PhoneNumber == "" {
			user.PhoneNumber = nil
			user.PhoneVerified = false
			user.PhoneVerifiedAt = nil
		}
	}
	if req.Avatar != nil {
		user.Avatar = req.Avatar
	}
	if req.Status != nil {
		user.Status = domain.UserStatus(*req.Status)
	}
	if req.Metadata != nil {
		user.Metadata = domain.JSONMap(req.Metadata)
	}

	// Save updated user
	err = s.userRepo.Update(ctx, user)
	if err != nil {
		s.logger.Error("Failed to update user", "error", err, "user_id", id)
		return nil, fmt.Errorf("failed to update user: %w", err)
	}

	s.logger.Info("User updated successfully", "user_id", id)
	return s.mapUserToResponse(user), nil
}

// ChangePassword changes a user's password with validation
func (s *userService) ChangePassword(ctx context.Context, userID uuid.UUID, req *dto.ChangePasswordRequest) error {
	// Get user
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		s.logger.Error("Failed to get user for password change", "error", err, "user_id", userID)
		return fmt.Errorf("user not found: %w", err)
	}

	// Verify current password
	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.CurrentPassword))
	if err != nil {
		s.logger.Warn("Invalid current password", "user_id", userID)
		return fmt.Errorf("current password is incorrect")
	}

	// Hash new password
	hashedPassword, err := s.hashPassword(req.NewPassword)
	if err != nil {
		s.logger.Error("Failed to hash new password", "error", err, "user_id", userID)
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// Update password
	user.PasswordHash = hashedPassword
	user.PasswordChangedAt = timePtr(time.Now())

	err = s.userRepo.Update(ctx, user)
	if err != nil {
		s.logger.Error("Failed to update password", "error", err, "user_id", userID)
		return fmt.Errorf("failed to update password: %w", err)
	}

	// Revoke all existing sessions for security
	err = s.userRepo.RevokeAllSessions(ctx, userID)
	if err != nil {
		s.logger.Warn("Failed to revoke sessions after password change", "error", err, "user_id", userID)
		// Don't fail the password change if session revocation fails
	}

	s.logger.Info("Password changed successfully", "user_id", userID)
	return nil
}

// DeleteUser soft deletes a user
func (s *userService) DeleteUser(ctx context.Context, id uuid.UUID) error {
	// Check if user exists
	_, err := s.userRepo.GetByID(ctx, id)
	if err != nil {
		s.logger.Error("Failed to get user for deletion", "error", err, "user_id", id)
		return fmt.Errorf("user not found: %w", err)
	}

	// Revoke all sessions
	err = s.userRepo.RevokeAllSessions(ctx, id)
	if err != nil {
		s.logger.Warn("Failed to revoke sessions before deletion", "error", err, "user_id", id)
		// Continue with deletion even if session revocation fails
	}

	// Soft delete user
	err = s.userRepo.Delete(ctx, id)
	if err != nil {
		s.logger.Error("Failed to delete user", "error", err, "user_id", id)
		return fmt.Errorf("failed to delete user: %w", err)
	}

	s.logger.Info("User deleted successfully", "user_id", id)
	return nil
}

// ListUsers retrieves users with pagination and filtering
func (s *userService) ListUsers(ctx context.Context, req *dto.UserListRequest) (*dto.UserListResponse, error) {
	users, total, err := s.userRepo.List(ctx, req)
	if err != nil {
		s.logger.Error("Failed to list users", "error", err)
		return nil, fmt.Errorf("failed to list users: %w", err)
	}

	// Map to response DTOs
	userResponses := make([]dto.UserResponse, len(users))
	for i, user := range users {
		userResponses[i] = *s.mapUserToResponse(user)
	}

	// Calculate pagination
	totalPages := (total + req.Limit - 1) / req.Limit

	return &dto.UserListResponse{
		Users: userResponses,
		Pagination: dto.PaginationResponse{
			Page:       req.Page,
			Limit:      req.Limit,
			Total:      total,
			TotalPages: totalPages,
		},
	}, nil
}

// GetUsersByTenant retrieves users by tenant ID with pagination
func (s *userService) GetUsersByTenant(ctx context.Context, tenantID uuid.UUID, req *dto.UserListRequest) (*dto.UserListResponse, error) {
	users, total, err := s.userRepo.GetByTenantID(ctx, tenantID, req)
	if err != nil {
		s.logger.Error("Failed to get users by tenant", "error", err, "tenant_id", tenantID)
		return nil, fmt.Errorf("failed to get users by tenant: %w", err)
	}

	// Map to response DTOs
	userResponses := make([]dto.UserResponse, len(users))
	for i, user := range users {
		userResponses[i] = *s.mapUserToResponse(user)
	}

	// Calculate pagination
	totalPages := (total + req.Limit - 1) / req.Limit

	return &dto.UserListResponse{
		Users: userResponses,
		Pagination: dto.PaginationResponse{
			Page:       req.Page,
			Limit:      req.Limit,
			Total:      total,
			TotalPages: totalPages,
		},
	}, nil
}

// GetUserStats retrieves user statistics
func (s *userService) GetUserStats(ctx context.Context, req *dto.UserStatsRequest) (*dto.UserStatsResponse, error) {
	stats, err := s.userRepo.GetUserStats(ctx, req)
	if err != nil {
		s.logger.Error("Failed to get user stats", "error", err)
		return nil, fmt.Errorf("failed to get user stats: %w", err)
	}

	return stats, nil
}

// BulkUpdateUsers performs bulk operations on users
func (s *userService) BulkUpdateUsers(ctx context.Context, req *dto.BulkUserRequest) (*dto.BulkOperationResponse, error) {
	successCount, errs := s.userRepo.BulkUpdate(ctx, req.UserIDs, req.Action)

	// Convert errors to bulk error format
	failures := make([]dto.BulkError, len(errs))
	for i, err := range errs {
		failures[i] = dto.BulkError{
			ID:    req.UserIDs[i], // This assumes errors are in same order as IDs
			Error: err.Error(),
		}
	}

	s.logger.Info("Bulk operation completed",
		"action", req.Action,
		"success_count", successCount,
		"failure_count", len(errs),
	)

	return &dto.BulkOperationResponse{
		SuccessCount: successCount,
		FailureCount: len(errs),
		Failures:     failures,
	}, nil
}

// AssignRole assigns a role to a user
func (s *userService) AssignRole(ctx context.Context, userID uuid.UUID, req *dto.AssignRoleRequest) (*dto.UserRoleResponse, error) {
	// Check if user exists
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	// Check if role is already assigned
	hasRole, err := s.userRepo.HasRole(ctx, userID, req.RoleID)
	if err != nil {
		return nil, fmt.Errorf("failed to check role assignment: %w", err)
	}
	if hasRole {
		return nil, fmt.Errorf("role already assigned to user")
	}

	// Create user role assignment
	userRole := &domain.UserRole{
		ID:        uuid.New(),
		UserID:    userID,
		RoleID:    req.RoleID,
		TenantID:  user.TenantID,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	err = s.userRepo.AssignRole(ctx, userRole)
	if err != nil {
		s.logger.Error("Failed to assign role", "error", err, "user_id", userID, "role_id", req.RoleID)
		return nil, fmt.Errorf("failed to assign role: %w", err)
	}

	s.logger.Info("Role assigned successfully", "user_id", userID, "role_id", req.RoleID)

	return &dto.UserRoleResponse{
		ID:        userRole.ID,
		UserID:    userRole.UserID,
		RoleID:    userRole.RoleID,
		TenantID:  userRole.TenantID,
		CreatedAt: userRole.CreatedAt,
	}, nil
}

// RevokeRole revokes a role from a user
func (s *userService) RevokeRole(ctx context.Context, userID uuid.UUID, req *dto.RevokeRoleRequest) error {
	// Check if role is assigned
	hasRole, err := s.userRepo.HasRole(ctx, userID, req.RoleID)
	if err != nil {
		return fmt.Errorf("failed to check role assignment: %w", err)
	}
	if !hasRole {
		return fmt.Errorf("role not assigned to user")
	}

	err = s.userRepo.RevokeRole(ctx, userID, req.RoleID)
	if err != nil {
		s.logger.Error("Failed to revoke role", "error", err, "user_id", userID, "role_id", req.RoleID)
		return fmt.Errorf("failed to revoke role: %w", err)
	}

	s.logger.Info("Role revoked successfully", "user_id", userID, "role_id", req.RoleID)
	return nil
}

// GetUserRoles retrieves roles assigned to a user
func (s *userService) GetUserRoles(ctx context.Context, userID uuid.UUID) ([]*dto.UserRoleResponse, error) {
	userRoles, err := s.userRepo.GetUserRoles(ctx, userID)
	if err != nil {
		s.logger.Error("Failed to get user roles", "error", err, "user_id", userID)
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}

	responses := make([]*dto.UserRoleResponse, len(userRoles))
	for i, ur := range userRoles {
		responses[i] = &dto.UserRoleResponse{
			ID:        ur.ID,
			UserID:    ur.UserID,
			RoleID:    ur.RoleID,
			TenantID:  ur.TenantID,
			CreatedAt: ur.CreatedAt,
		}
	}

	return responses, nil
}

// Additional methods would be implemented here...
// ActivateUser, DeactivateUser, SuspendUser, VerifyEmail, VerifyPhone,
// EnableMFA, DisableMFA, GetUserSessions, RevokeAllSessions,
// ValidateUserCredentials, HandleLoginAttempt

// Helper methods

// hashPassword hashes a password using bcrypt
func (s *userService) hashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// mapUserToResponse converts a domain user to response DTO
func (s *userService) mapUserToResponse(user *domain.User) *dto.UserResponse {
	return &dto.UserResponse{
		ID:                user.ID,
		TenantID:          user.TenantID,
		Email:             user.Email,
		Username:          user.Username,
		FirstName:         user.FirstName,
		LastName:          user.LastName,
		Avatar:            user.Avatar,
		EmailVerified:     user.EmailVerified,
		EmailVerifiedAt:   user.EmailVerifiedAt,
		PhoneNumber:       user.PhoneNumber,
		PhoneVerified:     user.PhoneVerified,
		PhoneVerifiedAt:   user.PhoneVerifiedAt,
		MFAEnabled:        user.MFAEnabled,
		Status:            user.Status,
		LastLoginAt:       user.LastLoginAt,
		PasswordChangedAt: user.PasswordChangedAt,
		Metadata:          user.Metadata,
		CreatedAt:         user.CreatedAt,
		UpdatedAt:         user.UpdatedAt,
	}
}

// timePtr returns a pointer to time.Time
func timePtr(t time.Time) *time.Time {
	return &t
}

// ActivateUser activates a user account
func (s *userService) ActivateUser(ctx context.Context, userID uuid.UUID) error {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	user.Status = domain.UserStatusActive
	err = s.userRepo.Update(ctx, user)
	if err != nil {
		s.logger.Error("Failed to activate user", "error", err, "user_id", userID)
		return fmt.Errorf("failed to activate user: %w", err)
	}

	s.logger.Info("User activated successfully", "user_id", userID)
	return nil
}

// DeactivateUser deactivates a user account
func (s *userService) DeactivateUser(ctx context.Context, userID uuid.UUID) error {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	user.Status = domain.UserStatusInactive
	err = s.userRepo.Update(ctx, user)
	if err != nil {
		s.logger.Error("Failed to deactivate user", "error", err, "user_id", userID)
		return fmt.Errorf("failed to deactivate user: %w", err)
	}

	// Revoke all sessions
	_ = s.userRepo.RevokeAllSessions(ctx, userID)

	s.logger.Info("User deactivated successfully", "user_id", userID)
	return nil
}

// SuspendUser suspends a user account
func (s *userService) SuspendUser(ctx context.Context, userID uuid.UUID) error {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	user.Status = domain.UserStatusSuspended
	err = s.userRepo.Update(ctx, user)
	if err != nil {
		s.logger.Error("Failed to suspend user", "error", err, "user_id", userID)
		return fmt.Errorf("failed to suspend user: %w", err)
	}

	// Revoke all sessions
	_ = s.userRepo.RevokeAllSessions(ctx, userID)

	s.logger.Info("User suspended successfully", "user_id", userID)
	return nil
}

// VerifyEmail verifies a user's email address
func (s *userService) VerifyEmail(ctx context.Context, userID uuid.UUID) error {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	if user.EmailVerified {
		return fmt.Errorf("email already verified")
	}

	user.EmailVerified = true
	user.EmailVerifiedAt = timePtr(time.Now())

	// Activate user if they were pending and email verification was required
	if user.Status == domain.UserStatusPending {
		user.Status = domain.UserStatusActive
	}

	err = s.userRepo.Update(ctx, user)
	if err != nil {
		s.logger.Error("Failed to verify email", "error", err, "user_id", userID)
		return fmt.Errorf("failed to verify email: %w", err)
	}

	s.logger.Info("Email verified successfully", "user_id", userID)
	return nil
}

// VerifyPhone verifies a user's phone number
func (s *userService) VerifyPhone(ctx context.Context, userID uuid.UUID) error {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	if user.PhoneVerified {
		return fmt.Errorf("phone already verified")
	}

	if user.PhoneNumber == nil {
		return fmt.Errorf("no phone number to verify")
	}

	user.PhoneVerified = true
	user.PhoneVerifiedAt = timePtr(time.Now())

	err = s.userRepo.Update(ctx, user)
	if err != nil {
		s.logger.Error("Failed to verify phone", "error", err, "user_id", userID)
		return fmt.Errorf("failed to verify phone: %w", err)
	}

	s.logger.Info("Phone verified successfully", "user_id", userID)
	return nil
}

// EnableMFA enables multi-factor authentication for a user
func (s *userService) EnableMFA(ctx context.Context, userID uuid.UUID) (string, []string, error) {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return "", nil, fmt.Errorf("user not found: %w", err)
	}

	if user.MFAEnabled {
		return "", nil, fmt.Errorf("MFA already enabled")
	}

	// TODO: Generate TOTP secret and backup codes
	// This is a simplified implementation
	secret := "MFA_SECRET_PLACEHOLDER"                                        // Replace with actual TOTP secret generation
	backupCodes := []string{"123456", "234567", "345678", "456789", "567890"} // Replace with actual backup code generation

	user.MFAEnabled = true
	user.MFASecret = &secret
	user.BackupCodes = backupCodes

	err = s.userRepo.Update(ctx, user)
	if err != nil {
		s.logger.Error("Failed to enable MFA", "error", err, "user_id", userID)
		return "", nil, fmt.Errorf("failed to enable MFA: %w", err)
	}

	s.logger.Info("MFA enabled successfully", "user_id", userID)
	return secret, backupCodes, nil
}

// DisableMFA disables multi-factor authentication for a user
func (s *userService) DisableMFA(ctx context.Context, userID uuid.UUID) error {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	if !user.MFAEnabled {
		return fmt.Errorf("MFA not enabled")
	}

	user.MFAEnabled = false
	user.MFASecret = nil
	user.BackupCodes = nil

	err = s.userRepo.Update(ctx, user)
	if err != nil {
		s.logger.Error("Failed to disable MFA", "error", err, "user_id", userID)
		return fmt.Errorf("failed to disable MFA: %w", err)
	}

	s.logger.Info("MFA disabled successfully", "user_id", userID)
	return nil
}

// GetUserSessions retrieves active sessions for a user
func (s *userService) GetUserSessions(ctx context.Context, userID uuid.UUID) ([]*domain.Session, error) {
	sessions, err := s.userRepo.GetUserSessions(ctx, userID)
	if err != nil {
		s.logger.Error("Failed to get user sessions", "error", err, "user_id", userID)
		return nil, fmt.Errorf("failed to get user sessions: %w", err)
	}

	return sessions, nil
}

// RevokeAllSessions revokes all sessions for a user
func (s *userService) RevokeAllSessions(ctx context.Context, userID uuid.UUID) error {
	err := s.userRepo.RevokeAllSessions(ctx, userID)
	if err != nil {
		s.logger.Error("Failed to revoke all sessions", "error", err, "user_id", userID)
		return fmt.Errorf("failed to revoke all sessions: %w", err)
	}

	s.logger.Info("All sessions revoked successfully", "user_id", userID)
	return nil
}

// ValidateUserCredentials validates user credentials for authentication
func (s *userService) ValidateUserCredentials(ctx context.Context, email, password string) (*domain.User, error) {
	user, err := s.userRepo.GetByEmail(ctx, email)
	if err != nil {
		s.logger.Warn("Failed to find user for authentication", "email", email)
		return nil, fmt.Errorf("invalid credentials")
	}

	// Check if user is locked
	if user.LockedUntil != nil && user.LockedUntil.After(time.Now()) {
		return nil, fmt.Errorf("account is locked")
	}

	// Check if user is active
	if user.Status != domain.UserStatusActive {
		return nil, fmt.Errorf("account is not active")
	}

	// Verify password
	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
	if err != nil {
		s.logger.Warn("Invalid password", "user_id", user.ID)
		// Increment login attempts
		_ = s.userRepo.IncrementLoginAttempts(ctx, user.ID)
		return nil, fmt.Errorf("invalid credentials")
	}

	// Reset login attempts on successful authentication
	_ = s.userRepo.ResetLoginAttempts(ctx, user.ID)
	_ = s.userRepo.UpdateLastLogin(ctx, user.ID, time.Now())

	return user, nil
}

// HandleLoginAttempt handles login attempt tracking and account locking
func (s *userService) HandleLoginAttempt(ctx context.Context, userID uuid.UUID, success bool) error {
	if success {
		return s.userRepo.ResetLoginAttempts(ctx, userID)
	}

	// Increment failed attempts
	err := s.userRepo.IncrementLoginAttempts(ctx, userID)
	if err != nil {
		return err
	}

	// Get updated user to check attempts
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return err
	}

	// Lock account if too many failed attempts (e.g., 5)
	const maxAttempts = 5
	if user.LoginAttempts >= maxAttempts {
		lockUntil := time.Now().Add(30 * time.Minute) // Lock for 30 minutes
		err = s.userRepo.LockUser(ctx, userID, &lockUntil)
		if err != nil {
			s.logger.Error("Failed to lock user account", "error", err, "user_id", userID)
		} else {
			s.logger.Warn("User account locked due to failed login attempts", "user_id", userID, "attempts", user.LoginAttempts)
		}
	}

	return nil
}
