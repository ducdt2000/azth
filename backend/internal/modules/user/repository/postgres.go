package repository

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/ducdt2000/azth/backend/internal/db"
	"github.com/ducdt2000/azth/backend/internal/domain"
	"github.com/ducdt2000/azth/backend/internal/modules/user/dto"
	"github.com/ducdt2000/azth/backend/pkg/logger"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

// postgresUserRepository implements UserRepository using PostgreSQL
type postgresUserRepository struct {
	db     *db.DB
	logger *logger.Logger
}

// NewPostgresUserRepository creates a new PostgreSQL user repository
func NewPostgresUserRepository(database *db.DB, logger *logger.Logger) UserRepository {
	return &postgresUserRepository{
		db:     database,
		logger: logger,
	}
}

// Create creates a new user
func (r *postgresUserRepository) Create(ctx context.Context, user *domain.User) error {
	query := `
		INSERT INTO users (
			id, tenant_id, email, username, password_hash, first_name, last_name,
			avatar, email_verified, email_verified_at, phone_number, phone_verified,
			phone_verified_at, mfa_enabled, mfa_secret, backup_codes, status,
			last_login_at, login_attempts, locked_until, password_changed_at,
			metadata, created_at, updated_at
		) VALUES (
			:id, :tenant_id, :email, :username, :password_hash, :first_name, :last_name,
			:avatar, :email_verified, :email_verified_at, :phone_number, :phone_verified,
			:phone_verified_at, :mfa_enabled, :mfa_secret, :backup_codes, :status,
			:last_login_at, :login_attempts, :locked_until, :password_changed_at,
			:metadata, :created_at, :updated_at
		)
	`

	_, err := r.db.NamedExecContext(ctx, query, user)
	if err != nil {
		r.logger.Error("Failed to create user", "error", err, "user_id", user.ID)
		return fmt.Errorf("failed to create user: %w", err)
	}

	r.logger.Info("User created successfully", "user_id", user.ID, "email", user.Email)
	return nil
}

// GetByID retrieves a user by ID
func (r *postgresUserRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	query := `
		SELECT * FROM users 
		WHERE id = $1 AND deleted_at IS NULL
	`

	var user domain.User
	err := r.db.GetContext(ctx, &user, query, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found: %w", err)
		}
		r.logger.Error("Failed to get user by ID", "error", err, "user_id", id)
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return &user, nil
}

// GetByEmail retrieves a user by email
func (r *postgresUserRepository) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	query := `
		SELECT * FROM users 
		WHERE LOWER(email) = LOWER($1) AND deleted_at IS NULL
	`

	var user domain.User
	err := r.db.GetContext(ctx, &user, query, email)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found: %w", err)
		}
		r.logger.Error("Failed to get user by email", "error", err, "email", email)
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return &user, nil
}

// GetByUsername retrieves a user by username
func (r *postgresUserRepository) GetByUsername(ctx context.Context, username string) (*domain.User, error) {
	query := `
		SELECT * FROM users 
		WHERE LOWER(username) = LOWER($1) AND deleted_at IS NULL
	`

	var user domain.User
	err := r.db.GetContext(ctx, &user, query, username)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found: %w", err)
		}
		r.logger.Error("Failed to get user by username", "error", err, "username", username)
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return &user, nil
}

// Update updates an existing user
func (r *postgresUserRepository) Update(ctx context.Context, user *domain.User) error {
	user.UpdatedAt = time.Now()

	query := `
		UPDATE users SET 
			email = :email, username = :username, first_name = :first_name,
			last_name = :last_name, avatar = :avatar, email_verified = :email_verified,
			email_verified_at = :email_verified_at, phone_number = :phone_number,
			phone_verified = :phone_verified, phone_verified_at = :phone_verified_at,
			mfa_enabled = :mfa_enabled, mfa_secret = :mfa_secret, backup_codes = :backup_codes,
			status = :status, last_login_at = :last_login_at, login_attempts = :login_attempts,
			locked_until = :locked_until, password_changed_at = :password_changed_at,
			metadata = :metadata, updated_at = :updated_at
		WHERE id = :id AND deleted_at IS NULL
	`

	result, err := r.db.NamedExecContext(ctx, query, user)
	if err != nil {
		r.logger.Error("Failed to update user", "error", err, "user_id", user.ID)
		return fmt.Errorf("failed to update user: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("user not found or already deleted")
	}

	r.logger.Info("User updated successfully", "user_id", user.ID)
	return nil
}

// Delete soft deletes a user
func (r *postgresUserRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `
		UPDATE users SET 
			deleted_at = NOW(),
			updated_at = NOW()
		WHERE id = $1 AND deleted_at IS NULL
	`

	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		r.logger.Error("Failed to delete user", "error", err, "user_id", id)
		return fmt.Errorf("failed to delete user: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("user not found or already deleted")
	}

	r.logger.Info("User deleted successfully", "user_id", id)
	return nil
}

// List retrieves users with pagination and filtering
func (r *postgresUserRepository) List(ctx context.Context, req *dto.UserListRequest) ([]*domain.User, int, error) {
	// Build WHERE clause
	whereConditions := []string{"deleted_at IS NULL"}
	args := []interface{}{}
	argCount := 0

	if req.Search != "" {
		argCount++
		whereConditions = append(whereConditions, fmt.Sprintf(
			"(LOWER(email) LIKE LOWER($%d) OR LOWER(username) LIKE LOWER($%d) OR LOWER(first_name || ' ' || last_name) LIKE LOWER($%d))",
			argCount, argCount, argCount,
		))
		args = append(args, "%"+req.Search+"%")
	}

	if req.Status != "" {
		argCount++
		whereConditions = append(whereConditions, fmt.Sprintf("status = $%d", argCount))
		args = append(args, req.Status)
	}

	if req.TenantID != "" {
		if tenantID, err := uuid.Parse(req.TenantID); err == nil {
			argCount++
			whereConditions = append(whereConditions, fmt.Sprintf("tenant_id = $%d", argCount))
			args = append(args, tenantID)
		}
	}

	whereClause := strings.Join(whereConditions, " AND ")

	// Count total records
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM users WHERE %s", whereClause)
	var total int
	err := r.db.GetContext(ctx, &total, countQuery, args...)
	if err != nil {
		r.logger.Error("Failed to count users", "error", err)
		return nil, 0, fmt.Errorf("failed to count users: %w", err)
	}

	// Get paginated results
	offset := (req.Page - 1) * req.Limit

	// Build ORDER BY clause with whitelist validation to prevent SQL injection
	validSortColumns := map[string]bool{
		"email":         true,
		"username":      true,
		"first_name":    true,
		"last_name":     true,
		"status":        true,
		"created_at":    true,
		"updated_at":    true,
		"last_login_at": true,
	}

	if !validSortColumns[req.Sort] {
		req.Sort = "created_at" // Default to safe column
	}

	// Validate order direction
	if req.Order != "ASC" && req.Order != "DESC" {
		req.Order = "DESC" // Default to DESC
	}

	orderClause := fmt.Sprintf("ORDER BY %s %s", req.Sort, req.Order)

	query := fmt.Sprintf(`
		SELECT * FROM users 
		WHERE %s 
		%s 
		LIMIT $%d OFFSET $%d
	`, whereClause, orderClause, argCount+1, argCount+2)

	args = append(args, req.Limit, offset)

	var users []*domain.User
	err = r.db.SelectContext(ctx, &users, query, args...)
	if err != nil {
		r.logger.Error("Failed to list users", "error", err)
		return nil, 0, fmt.Errorf("failed to list users: %w", err)
	}

	return users, total, nil
}

// GetByTenantID retrieves users by tenant ID with pagination
func (r *postgresUserRepository) GetByTenantID(ctx context.Context, tenantID uuid.UUID, req *dto.UserListRequest) ([]*domain.User, int, error) {
	// Set tenant ID in request for filtering
	req.TenantID = tenantID.String()
	return r.List(ctx, req)
}

// GetUserStats retrieves user statistics
func (r *postgresUserRepository) GetUserStats(ctx context.Context, req *dto.UserStatsRequest) (*dto.UserStatsResponse, error) {
	whereConditions := []string{"deleted_at IS NULL"}
	args := []interface{}{}
	argCount := 0

	if req.TenantID != nil {
		argCount++
		whereConditions = append(whereConditions, fmt.Sprintf("tenant_id = $%d", argCount))
		args = append(args, *req.TenantID)
	}

	whereClause := strings.Join(whereConditions, " AND ")

	query := fmt.Sprintf(`
		SELECT 
			COUNT(*) as total_users,
			COUNT(CASE WHEN status = 'active' THEN 1 END) as active_users,
			COUNT(CASE WHEN status = 'inactive' THEN 1 END) as inactive_users,
			COUNT(CASE WHEN status = 'suspended' THEN 1 END) as suspended_users,
			COUNT(CASE WHEN status = 'pending' THEN 1 END) as pending_users,
			COUNT(CASE WHEN email_verified = true THEN 1 END) as verified_emails,
			COUNT(CASE WHEN phone_verified = true THEN 1 END) as verified_phones,
			COUNT(CASE WHEN mfa_enabled = true THEN 1 END) as mfa_enabled,
			COUNT(CASE WHEN last_login_at > NOW() - INTERVAL '24 hours' THEN 1 END) as recent_logins
		FROM users 
		WHERE %s
	`, whereClause)

	var stats dto.UserStatsResponse
	err := r.db.GetContext(ctx, &stats, query, args...)
	if err != nil {
		r.logger.Error("Failed to get user stats", "error", err)
		return nil, fmt.Errorf("failed to get user stats: %w", err)
	}

	return &stats, nil
}

// EmailExists checks if an email already exists
func (r *postgresUserRepository) EmailExists(ctx context.Context, email string, excludeUserID *uuid.UUID) (bool, error) {
	query := "SELECT EXISTS(SELECT 1 FROM users WHERE LOWER(email) = LOWER($1) AND deleted_at IS NULL"
	args := []interface{}{email}

	if excludeUserID != nil {
		query += " AND id != $2"
		args = append(args, *excludeUserID)
	}
	query += ")"

	var exists bool
	err := r.db.GetContext(ctx, &exists, query, args...)
	if err != nil {
		r.logger.Error("Failed to check email existence", "error", err, "email", email)
		return false, fmt.Errorf("failed to check email existence: %w", err)
	}

	return exists, nil
}

// UsernameExists checks if a username already exists
func (r *postgresUserRepository) UsernameExists(ctx context.Context, username string, excludeUserID *uuid.UUID) (bool, error) {
	query := "SELECT EXISTS(SELECT 1 FROM users WHERE LOWER(username) = LOWER($1) AND deleted_at IS NULL"
	args := []interface{}{username}

	if excludeUserID != nil {
		query += " AND id != $2"
		args = append(args, *excludeUserID)
	}
	query += ")"

	var exists bool
	err := r.db.GetContext(ctx, &exists, query, args...)
	if err != nil {
		r.logger.Error("Failed to check username existence", "error", err, "username", username)
		return false, fmt.Errorf("failed to check username existence: %w", err)
	}

	return exists, nil
}

// GetUserRoles retrieves roles assigned to a user
func (r *postgresUserRepository) GetUserRoles(ctx context.Context, userID uuid.UUID) ([]*domain.UserRole, error) {
	query := `
		SELECT ur.id, ur.user_id, ur.role_id, ur.tenant_id, ur.created_at, ur.updated_at, ur.deleted_at, ur.created_by, ur.updated_by
		FROM user_roles ur
		JOIN roles r ON ur.role_id = r.id
		WHERE ur.user_id = $1 AND ur.deleted_at IS NULL AND r.deleted_at IS NULL
		ORDER BY ur.created_at DESC
	`

	var userRoles []*domain.UserRole
	err := r.db.SelectContext(ctx, &userRoles, query, userID)
	if err != nil {
		r.logger.Error("Failed to get user roles", "error", err, "user_id", userID)
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}

	return userRoles, nil
}

// Additional methods would be implemented here following the same pattern...
// For brevity, I'm showing key methods. The remaining methods would follow similar patterns:

// BulkUpdate, AssignRole, RevokeRole, HasRole, GetUserSessions, RevokeAllSessions,
// UpdateLastLogin, IncrementLoginAttempts, ResetLoginAttempts, LockUser

// BulkUpdate performs bulk updates on users
func (r *postgresUserRepository) BulkUpdate(ctx context.Context, userIDs []uuid.UUID, action string) (int, []error) {
	var successCount int
	var errors []error

	for _, userID := range userIDs {
		var err error
		switch action {
		case "activate":
			err = r.updateUserStatus(ctx, userID, domain.UserStatusActive)
		case "deactivate":
			err = r.updateUserStatus(ctx, userID, domain.UserStatusInactive)
		case "suspend":
			err = r.updateUserStatus(ctx, userID, domain.UserStatusSuspended)
		case "delete":
			err = r.Delete(ctx, userID)
		default:
			err = fmt.Errorf("unsupported action: %s", action)
		}

		if err != nil {
			errors = append(errors, fmt.Errorf("user %s: %w", userID, err))
		} else {
			successCount++
		}
	}

	return successCount, errors
}

// Helper method for updating user status
func (r *postgresUserRepository) updateUserStatus(ctx context.Context, userID uuid.UUID, status domain.UserStatus) error {
	query := `
		UPDATE users SET 
			status = $1,
			updated_at = NOW()
		WHERE id = $2 AND deleted_at IS NULL
	`

	result, err := r.db.ExecContext(ctx, query, status, userID)
	if err != nil {
		return fmt.Errorf("failed to update user status: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("user not found or already deleted")
	}

	return nil
}

// AssignRole assigns a role to a user
func (r *postgresUserRepository) AssignRole(ctx context.Context, userRole *domain.UserRole) error {
	query := `
		INSERT INTO user_roles (id, user_id, role_id, tenant_id, created_at, updated_at)
		VALUES (:id, :user_id, :role_id, :tenant_id, :created_at, :updated_at)
		ON CONFLICT (user_id, role_id) DO NOTHING
	`

	_, err := r.db.NamedExecContext(ctx, query, userRole)
	if err != nil {
		r.logger.Error("Failed to assign role", "error", err, "user_id", userRole.UserID, "role_id", userRole.RoleID)
		return fmt.Errorf("failed to assign role: %w", err)
	}

	return nil
}

// RevokeRole revokes a role from a user
func (r *postgresUserRepository) RevokeRole(ctx context.Context, userID, roleID uuid.UUID) error {
	query := `
		UPDATE user_roles SET 
			deleted_at = NOW(),
			updated_at = NOW()
		WHERE user_id = $1 AND role_id = $2 AND deleted_at IS NULL
	`

	result, err := r.db.ExecContext(ctx, query, userID, roleID)
	if err != nil {
		r.logger.Error("Failed to revoke role", "error", err, "user_id", userID, "role_id", roleID)
		return fmt.Errorf("failed to revoke role: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("role assignment not found")
	}

	return nil
}

// HasRole checks if a user has a specific role
func (r *postgresUserRepository) HasRole(ctx context.Context, userID, roleID uuid.UUID) (bool, error) {
	query := `
		SELECT EXISTS(
			SELECT 1 FROM user_roles 
			WHERE user_id = $1 AND role_id = $2 AND deleted_at IS NULL
		)
	`

	var exists bool
	err := r.db.GetContext(ctx, &exists, query, userID, roleID)
	if err != nil {
		r.logger.Error("Failed to check user role", "error", err, "user_id", userID, "role_id", roleID)
		return false, fmt.Errorf("failed to check user role: %w", err)
	}

	return exists, nil
}

// GetUserSessions retrieves active sessions for a user
func (r *postgresUserRepository) GetUserSessions(ctx context.Context, userID uuid.UUID) ([]*domain.Session, error) {
	query := `
		SELECT * FROM sessions 
		WHERE user_id = $1 AND revoked = false AND expires_at > NOW()
		ORDER BY last_activity DESC
	`

	var sessions []*domain.Session
	err := r.db.SelectContext(ctx, &sessions, query, userID)
	if err != nil {
		r.logger.Error("Failed to get user sessions", "error", err, "user_id", userID)
		return nil, fmt.Errorf("failed to get user sessions: %w", err)
	}

	return sessions, nil
}

// RevokeAllSessions revokes all sessions for a user
func (r *postgresUserRepository) RevokeAllSessions(ctx context.Context, userID uuid.UUID) error {
	query := `
		UPDATE sessions SET 
			revoked = true,
			revoked_at = NOW(),
			revoked_reason = 'user_request',
			updated_at = NOW()
		WHERE user_id = $1 AND revoked = false
	`

	_, err := r.db.ExecContext(ctx, query, userID)
	if err != nil {
		r.logger.Error("Failed to revoke user sessions", "error", err, "user_id", userID)
		return fmt.Errorf("failed to revoke user sessions: %w", err)
	}

	return nil
}

// UpdateLastLogin updates the last login timestamp
func (r *postgresUserRepository) UpdateLastLogin(ctx context.Context, userID uuid.UUID, loginTime time.Time) error {
	query := `
		UPDATE users SET 
			last_login_at = $1,
			updated_at = NOW()
		WHERE id = $2 AND deleted_at IS NULL
	`

	_, err := r.db.ExecContext(ctx, query, loginTime, userID)
	if err != nil {
		r.logger.Error("Failed to update last login", "error", err, "user_id", userID)
		return fmt.Errorf("failed to update last login: %w", err)
	}

	return nil
}

// UpdateLoginAttempts updates login attempts counter
func (r *postgresUserRepository) UpdateLoginAttempts(ctx context.Context, userID uuid.UUID, attempts int) error {
	query := `
		UPDATE users SET 
			login_attempts = $1,
			updated_at = NOW()
		WHERE id = $2 AND deleted_at IS NULL
	`

	_, err := r.db.ExecContext(ctx, query, attempts, userID)
	if err != nil {
		r.logger.Error("Failed to update login attempts", "error", err, "user_id", userID)
		return fmt.Errorf("failed to update login attempts: %w", err)
	}

	return nil
}

// UpdateLockedUntil updates the locked until timestamp
func (r *postgresUserRepository) UpdateLockedUntil(ctx context.Context, userID uuid.UUID, lockedUntil *time.Time) error {
	query := `
		UPDATE users SET 
			locked_until = $1,
			updated_at = NOW()
		WHERE id = $2 AND deleted_at IS NULL
	`

	_, err := r.db.ExecContext(ctx, query, lockedUntil, userID)
	if err != nil {
		r.logger.Error("Failed to update locked until", "error", err, "user_id", userID)
		return fmt.Errorf("failed to update locked until: %w", err)
	}

	return nil
}

// UpdateMFASecret updates the MFA secret for a user
func (r *postgresUserRepository) UpdateMFASecret(ctx context.Context, userID uuid.UUID, secret string) error {
	query := `
		UPDATE users SET 
			mfa_secret = $1,
			mfa_enabled = $2,
			updated_at = NOW()
		WHERE id = $3 AND deleted_at IS NULL
	`

	mfaEnabled := secret != ""
	_, err := r.db.ExecContext(ctx, query, secret, mfaEnabled, userID)
	if err != nil {
		r.logger.Error("Failed to update MFA secret", "error", err, "user_id", userID)
		return fmt.Errorf("failed to update MFA secret: %w", err)
	}

	return nil
}

// UpdateBackupCodes updates the backup codes for a user
func (r *postgresUserRepository) UpdateBackupCodes(ctx context.Context, userID uuid.UUID, codes []string) error {
	query := `
		UPDATE users SET 
			backup_codes = $1,
			updated_at = NOW()
		WHERE id = $2 AND deleted_at IS NULL
	`

	_, err := r.db.ExecContext(ctx, query, pq.Array(codes), userID)
	if err != nil {
		r.logger.Error("Failed to update backup codes", "error", err, "user_id", userID)
		return fmt.Errorf("failed to update backup codes: %w", err)
	}

	return nil
}

// IncrementLoginAttempts increments login attempts counter
func (r *postgresUserRepository) IncrementLoginAttempts(ctx context.Context, userID uuid.UUID) error {
	query := `
		UPDATE users SET 
			login_attempts = login_attempts + 1,
			updated_at = NOW()
		WHERE id = $1 AND deleted_at IS NULL
	`

	_, err := r.db.ExecContext(ctx, query, userID)
	if err != nil {
		r.logger.Error("Failed to increment login attempts", "error", err, "user_id", userID)
		return fmt.Errorf("failed to increment login attempts: %w", err)
	}

	return nil
}

// ResetLoginAttempts resets login attempts counter
func (r *postgresUserRepository) ResetLoginAttempts(ctx context.Context, userID uuid.UUID) error {
	query := `
		UPDATE users SET 
			login_attempts = 0,
			locked_until = NULL,
			updated_at = NOW()
		WHERE id = $1 AND deleted_at IS NULL
	`

	_, err := r.db.ExecContext(ctx, query, userID)
	if err != nil {
		r.logger.Error("Failed to reset login attempts", "error", err, "user_id", userID)
		return fmt.Errorf("failed to reset login attempts: %w", err)
	}

	return nil
}

// LockUser locks a user account until specified time
func (r *postgresUserRepository) LockUser(ctx context.Context, userID uuid.UUID, lockedUntil *time.Time) error {
	query := `
		UPDATE users SET 
			locked_until = $1,
			updated_at = NOW()
		WHERE id = $2 AND deleted_at IS NULL
	`

	_, err := r.db.ExecContext(ctx, query, lockedUntil, userID)
	if err != nil {
		r.logger.Error("Failed to lock user", "error", err, "user_id", userID)
		return fmt.Errorf("failed to lock user: %w", err)
	}

	return nil
}

// VerifyPassword verifies a password against its hash (supports both Argon2ID and bcrypt)
func (r *postgresUserRepository) VerifyPassword(password, hash string) bool {
	if strings.HasPrefix(hash, "$argon2id$") {
		return r.verifyArgon2IDPassword(password, hash)
	} else if strings.HasPrefix(hash, "$2a$") || strings.HasPrefix(hash, "$2b$") || strings.HasPrefix(hash, "$2y$") {
		return r.verifyBcryptPassword(password, hash)
	}

	// Unknown hash format
	r.logger.Warn("Unknown password hash format", "hash_prefix", hash[:min(10, len(hash))])
	return false
}

// verifyArgon2IDPassword verifies Argon2ID password
func (r *postgresUserRepository) verifyArgon2IDPassword(password, hash string) bool {
	// Parse Argon2ID hash: $argon2id$v=19$m=memory,t=iterations,p=parallelism$salt$hash
	parts := strings.Split(hash, "$")
	if len(parts) != 6 {
		r.logger.Warn("Invalid Argon2ID hash format")
		return false
	}

	// Parse parameters
	var memory, iterations uint32
	var parallelism uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &parallelism); err != nil {
		r.logger.Warn("Failed to parse Argon2ID parameters", "error", err)
		return false
	}

	// Decode salt and hash
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		r.logger.Warn("Failed to decode Argon2ID salt", "error", err)
		return false
	}

	expectedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		r.logger.Warn("Failed to decode Argon2ID hash", "error", err)
		return false
	}

	// Hash the provided password with the same parameters
	computedHash := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, uint32(len(expectedHash)))

	// Compare hashes using constant-time comparison
	return subtle.ConstantTimeCompare(expectedHash, computedHash) == 1
}

// verifyBcryptPassword verifies bcrypt password
func (r *postgresUserRepository) verifyBcryptPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// UpdatePassword updates a user's password hash
func (r *postgresUserRepository) UpdatePassword(ctx context.Context, userID uuid.UUID, hashedPassword string) error {
	query := `
		UPDATE users SET 
			password_hash = $1,
			password_changed_at = NOW(),
			updated_at = NOW()
		WHERE id = $2 AND deleted_at IS NULL
	`

	result, err := r.db.ExecContext(ctx, query, hashedPassword, userID)
	if err != nil {
		r.logger.Error("Failed to update user password", "error", err, "user_id", userID)
		return fmt.Errorf("failed to update password: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		r.logger.Error("Failed to check rows affected", "error", err)
		return fmt.Errorf("failed to check update result: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("user not found or already deleted")
	}

	r.logger.Info("User password updated successfully", "user_id", userID)
	return nil
}

// Helper function for min (not available in older Go versions)
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
