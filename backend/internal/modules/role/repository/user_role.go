package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/ducdt2000/azth/backend/internal/domain"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

// userRoleRepository implements UserRoleRepository interface
type userRoleRepository struct {
	db *sqlx.DB
}

// NewUserRoleRepository creates a new user role repository
func NewUserRoleRepository(db *sqlx.DB) UserRoleRepository {
	return &userRoleRepository{
		db: db,
	}
}

// AssignRole assigns a role to a user
func (r *userRoleRepository) AssignRole(ctx context.Context, userRole *domain.UserRole) error {
	query := `
		INSERT INTO user_roles (id, user_id, role_id, tenant_id, created_at, updated_at, created_by)
		VALUES (:id, :user_id, :role_id, :tenant_id, :created_at, :updated_at, :created_by)
		ON CONFLICT (user_id, role_id, tenant_id) DO NOTHING`

	_, err := r.db.NamedExecContext(ctx, query, userRole)
	if err != nil {
		return fmt.Errorf("failed to assign role to user: %w", err)
	}

	return nil
}

// RevokeRole revokes a role from a user
func (r *userRoleRepository) RevokeRole(ctx context.Context, userID, roleID, tenantID uuid.UUID) error {
	query := `DELETE FROM user_roles WHERE user_id = $1 AND role_id = $2 AND tenant_id = $3`
	result, err := r.db.ExecContext(ctx, query, userID, roleID, tenantID)
	if err != nil {
		return fmt.Errorf("failed to revoke role from user: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("user role assignment not found")
	}

	return nil
}

// GetUserRoles retrieves roles for a user in a specific tenant
func (r *userRoleRepository) GetUserRoles(ctx context.Context, userID, tenantID uuid.UUID) ([]*domain.UserRole, error) {
	query := `
		SELECT ur.id, ur.user_id, ur.role_id, ur.tenant_id, ur.created_at, ur.updated_at, ur.created_by, ur.updated_by
		FROM user_roles ur
		WHERE ur.user_id = $1 AND ur.tenant_id = $2 AND ur.deleted_at IS NULL
		ORDER BY ur.created_at`

	var userRoles []*domain.UserRole
	err := r.db.SelectContext(ctx, &userRoles, query, userID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}

	return userRoles, nil
}

// GetUserRolesByUser retrieves all roles for a user across all tenants
func (r *userRoleRepository) GetUserRolesByUser(ctx context.Context, userID uuid.UUID) ([]*domain.UserRole, error) {
	query := `
		SELECT ur.id, ur.user_id, ur.role_id, ur.tenant_id, ur.created_at, ur.updated_at, ur.created_by, ur.updated_by
		FROM user_roles ur
		WHERE ur.user_id = $1 AND ur.deleted_at IS NULL
		ORDER BY ur.tenant_id, ur.created_at`

	var userRoles []*domain.UserRole
	err := r.db.SelectContext(ctx, &userRoles, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user roles by user: %w", err)
	}

	return userRoles, nil
}

// GetRoleUsers retrieves users who have a specific role
func (r *userRoleRepository) GetRoleUsers(ctx context.Context, roleID uuid.UUID) ([]*domain.UserRole, error) {
	query := `
		SELECT ur.id, ur.user_id, ur.role_id, ur.tenant_id, ur.created_at, ur.updated_at, ur.created_by, ur.updated_by
		FROM user_roles ur
		WHERE ur.role_id = $1 AND ur.deleted_at IS NULL
		ORDER BY ur.tenant_id, ur.created_at`

	var userRoles []*domain.UserRole
	err := r.db.SelectContext(ctx, &userRoles, query, roleID)
	if err != nil {
		return nil, fmt.Errorf("failed to get role users: %w", err)
	}

	return userRoles, nil
}

// HasRole checks if a user has a specific role
func (r *userRoleRepository) HasRole(ctx context.Context, userID, roleID, tenantID uuid.UUID) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM user_roles WHERE user_id = $1 AND role_id = $2 AND tenant_id = $3 AND deleted_at IS NULL)`
	var exists bool
	err := r.db.GetContext(ctx, &exists, query, userID, roleID, tenantID)
	if err != nil {
		return false, fmt.Errorf("failed to check user role: %w", err)
	}
	return exists, nil
}

// HasAnyRole checks if a user has any of the specified roles
func (r *userRoleRepository) HasAnyRole(ctx context.Context, userID uuid.UUID, roleIDs []uuid.UUID, tenantID uuid.UUID) (bool, error) {
	if len(roleIDs) == 0 {
		return false, nil
	}

	query := `SELECT EXISTS(SELECT 1 FROM user_roles WHERE user_id = $1 AND role_id = ANY($2) AND tenant_id = $3 AND deleted_at IS NULL)`
	var exists bool
	err := r.db.GetContext(ctx, &exists, query, userID, roleIDs, tenantID)
	if err != nil {
		return false, fmt.Errorf("failed to check user roles: %w", err)
	}
	return exists, nil
}

// GetUserPermissions retrieves all permissions for a user through their roles
func (r *userRoleRepository) GetUserPermissions(ctx context.Context, userID, tenantID uuid.UUID) ([]*domain.Permission, error) {
	query := `
		SELECT DISTINCT p.id, p.name, p.code, p.description, p.module, p.resource, p.action,
			   p.is_system, p.is_default, p.metadata, p.created_at, p.updated_at
		FROM permissions p
		INNER JOIN role_permissions rp ON p.id = rp.permission_id
		INNER JOIN user_roles ur ON rp.role_id = ur.role_id
		WHERE ur.user_id = $1 AND ur.tenant_id = $2 AND ur.deleted_at IS NULL AND p.deleted_at IS NULL
		ORDER BY p.module, p.resource, p.action`

	var permissions []*domain.Permission
	err := r.db.SelectContext(ctx, &permissions, query, userID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user permissions: %w", err)
	}

	return permissions, nil
}

// BulkAssignRoles assigns roles to users in bulk
func (r *userRoleRepository) BulkAssignRoles(ctx context.Context, userRoles []*domain.UserRole) error {
	if len(userRoles) == 0 {
		return nil
	}

	query := `
		INSERT INTO user_roles (id, user_id, role_id, tenant_id, created_at, updated_at, created_by)
		VALUES (:id, :user_id, :role_id, :tenant_id, :created_at, :updated_at, :created_by)
		ON CONFLICT (user_id, role_id, tenant_id) DO NOTHING`

	_, err := r.db.NamedExecContext(ctx, query, userRoles)
	if err != nil {
		return fmt.Errorf("failed to bulk assign roles: %w", err)
	}

	return nil
}

// BulkRevokeRoles revokes roles from users in bulk
func (r *userRoleRepository) BulkRevokeRoles(ctx context.Context, userRoleIDs []uuid.UUID) error {
	if len(userRoleIDs) == 0 {
		return nil
	}

	query := `DELETE FROM user_roles WHERE id = ANY($1)`
	_, err := r.db.ExecContext(ctx, query, userRoleIDs)
	if err != nil {
		return fmt.Errorf("failed to bulk revoke roles: %w", err)
	}

	return nil
}

// BulkRevokeUserRoles revokes all roles from a user
func (r *userRoleRepository) BulkRevokeUserRoles(ctx context.Context, userID uuid.UUID, tenantID *uuid.UUID) error {
	query := `UPDATE user_roles SET deleted_at = $1, updated_at = $1 WHERE user_id = $2 AND deleted_at IS NULL`
	args := []interface{}{time.Now(), userID}

	if tenantID != nil {
		query += " AND tenant_id = $3"
		args = append(args, *tenantID)
	}

	_, err := r.db.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("failed to bulk revoke user roles: %w", err)
	}

	return nil
}

// GetUserRoleCount retrieves the count of roles for a user
func (r *userRoleRepository) GetUserRoleCount(ctx context.Context, userID uuid.UUID, tenantID *uuid.UUID) (int64, error) {
	query := `SELECT COUNT(*) FROM user_roles WHERE user_id = $1 AND deleted_at IS NULL`
	args := []interface{}{userID}

	if tenantID != nil {
		query += " AND tenant_id = $2"
		args = append(args, *tenantID)
	}

	var count int64
	err := r.db.GetContext(ctx, &count, query, args...)
	if err != nil {
		return 0, fmt.Errorf("failed to get user role count: %w", err)
	}

	return count, nil
}

// GetRoleUserCount retrieves the count of users for a role
func (r *userRoleRepository) GetRoleUserCount(ctx context.Context, roleID uuid.UUID) (int64, error) {
	query := `SELECT COUNT(*) FROM user_roles WHERE role_id = $1 AND deleted_at IS NULL`
	var count int64
	err := r.db.GetContext(ctx, &count, query, roleID)
	if err != nil {
		return 0, fmt.Errorf("failed to get role user count: %w", err)
	}

	return count, nil
}
