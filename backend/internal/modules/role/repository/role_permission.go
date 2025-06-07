package repository

import (
	"context"
	"fmt"

	"github.com/ducdt2000/azth/backend/internal/domain"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

// rolePermissionRepository implements RolePermissionRepository interface
type rolePermissionRepository struct {
	db *sqlx.DB
}

// NewRolePermissionRepository creates a new role permission repository
func NewRolePermissionRepository(db *sqlx.DB) RolePermissionRepository {
	return &rolePermissionRepository{
		db: db,
	}
}

// AssignPermissions assigns permissions to a role
func (r *rolePermissionRepository) AssignPermissions(ctx context.Context, roleID uuid.UUID, permissionIDs []uuid.UUID, createdBy uuid.UUID) error {
	if len(permissionIDs) == 0 {
		return nil
	}

	query := `
		INSERT INTO role_permissions (id, role_id, permission_id, created_at, created_by)
		VALUES ($1, $2, $3, NOW(), $4)
		ON CONFLICT (role_id, permission_id) DO NOTHING`

	for _, permissionID := range permissionIDs {
		_, err := r.db.ExecContext(ctx, query, uuid.New(), roleID, permissionID, createdBy)
		if err != nil {
			return fmt.Errorf("failed to assign permission %s to role %s: %w", permissionID, roleID, err)
		}
	}

	return nil
}

// RevokePermissions revokes permissions from a role
func (r *rolePermissionRepository) RevokePermissions(ctx context.Context, roleID uuid.UUID, permissionIDs []uuid.UUID) error {
	if len(permissionIDs) == 0 {
		return nil
	}

	query := `DELETE FROM role_permissions WHERE role_id = $1 AND permission_id = ANY($2)`
	_, err := r.db.ExecContext(ctx, query, roleID, permissionIDs)
	if err != nil {
		return fmt.Errorf("failed to revoke permissions from role: %w", err)
	}

	return nil
}

// ReplacePermissions replaces all permissions for a role
func (r *rolePermissionRepository) ReplacePermissions(ctx context.Context, roleID uuid.UUID, permissionIDs []uuid.UUID, createdBy uuid.UUID) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Delete existing permissions
	_, err = tx.ExecContext(ctx, "DELETE FROM role_permissions WHERE role_id = $1", roleID)
	if err != nil {
		return fmt.Errorf("failed to delete existing permissions: %w", err)
	}

	// Insert new permissions
	if len(permissionIDs) > 0 {
		query := `
			INSERT INTO role_permissions (id, role_id, permission_id, created_at, created_by)
			VALUES ($1, $2, $3, NOW(), $4)`

		for _, permissionID := range permissionIDs {
			_, err = tx.ExecContext(ctx, query, uuid.New(), roleID, permissionID, createdBy)
			if err != nil {
				return fmt.Errorf("failed to insert permission %s: %w", permissionID, err)
			}
		}
	}

	return tx.Commit()
}

// GetRolePermissions retrieves all permissions for a role
func (r *rolePermissionRepository) GetRolePermissions(ctx context.Context, roleID uuid.UUID) ([]*domain.Permission, error) {
	query := `
		SELECT p.id, p.name, p.code, p.description, p.module, p.resource, p.action,
			   p.is_system, p.is_default, p.metadata, p.created_at, p.updated_at
		FROM permissions p
		INNER JOIN role_permissions rp ON p.id = rp.permission_id
		WHERE rp.role_id = $1 AND p.deleted_at IS NULL
		ORDER BY p.module, p.resource, p.action`

	var permissions []*domain.Permission
	err := r.db.SelectContext(ctx, &permissions, query, roleID)
	if err != nil {
		return nil, fmt.Errorf("failed to get role permissions: %w", err)
	}

	return permissions, nil
}

// GetRolesWithPermissions retrieves permissions for multiple roles
func (r *rolePermissionRepository) GetRolesWithPermissions(ctx context.Context, roleIDs []uuid.UUID) (map[uuid.UUID][]*domain.Permission, error) {
	if len(roleIDs) == 0 {
		return make(map[uuid.UUID][]*domain.Permission), nil
	}

	query := `
		SELECT rp.role_id, p.id, p.name, p.code, p.description, p.module, p.resource, p.action,
			   p.is_system, p.is_default, p.metadata, p.created_at, p.updated_at
		FROM permissions p
		INNER JOIN role_permissions rp ON p.id = rp.permission_id
		WHERE rp.role_id = ANY($1) AND p.deleted_at IS NULL
		ORDER BY rp.role_id, p.module, p.resource, p.action`

	rows, err := r.db.QueryContext(ctx, query, roleIDs)
	if err != nil {
		return nil, fmt.Errorf("failed to get roles with permissions: %w", err)
	}
	defer rows.Close()

	result := make(map[uuid.UUID][]*domain.Permission)
	for rows.Next() {
		var roleID uuid.UUID
		var permission domain.Permission

		err := rows.Scan(
			&roleID,
			&permission.ID,
			&permission.Name,
			&permission.Code,
			&permission.Description,
			&permission.Module,
			&permission.Resource,
			&permission.Action,
			&permission.IsSystem,
			&permission.IsDefault,
			&permission.Metadata,
			&permission.CreatedAt,
			&permission.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan permission: %w", err)
		}

		result[roleID] = append(result[roleID], &permission)
	}

	return result, nil
}

// HasPermission checks if a role has a specific permission
func (r *rolePermissionRepository) HasPermission(ctx context.Context, roleID uuid.UUID, permissionID uuid.UUID) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM role_permissions WHERE role_id = $1 AND permission_id = $2)`
	var exists bool
	err := r.db.GetContext(ctx, &exists, query, roleID, permissionID)
	if err != nil {
		return false, fmt.Errorf("failed to check role permission: %w", err)
	}
	return exists, nil
}

// GetPermissionsByCode retrieves permissions by code for a role
func (r *rolePermissionRepository) GetPermissionsByCode(ctx context.Context, roleID uuid.UUID, permissionCodes []string) ([]*domain.Permission, error) {
	if len(permissionCodes) == 0 {
		return []*domain.Permission{}, nil
	}

	query := `
		SELECT p.id, p.name, p.code, p.description, p.module, p.resource, p.action,
			   p.is_system, p.is_default, p.metadata, p.created_at, p.updated_at
		FROM permissions p
		INNER JOIN role_permissions rp ON p.id = rp.permission_id
		WHERE rp.role_id = $1 AND p.code = ANY($2) AND p.deleted_at IS NULL`

	var permissions []*domain.Permission
	err := r.db.SelectContext(ctx, &permissions, query, roleID, permissionCodes)
	if err != nil {
		return nil, fmt.Errorf("failed to get permissions by code: %w", err)
	}

	return permissions, nil
}

// BulkAssignPermissions assigns permissions to roles in bulk
func (r *rolePermissionRepository) BulkAssignPermissions(ctx context.Context, assignments []domain.RolePermission) error {
	if len(assignments) == 0 {
		return nil
	}

	query := `
		INSERT INTO role_permissions (id, role_id, permission_id, created_at, created_by)
		VALUES (:id, :role_id, :permission_id, :created_at, :created_by)
		ON CONFLICT (role_id, permission_id) DO NOTHING`

	_, err := r.db.NamedExecContext(ctx, query, assignments)
	if err != nil {
		return fmt.Errorf("failed to bulk assign permissions: %w", err)
	}

	return nil
}

// BulkRevokePermissions revokes permissions from roles in bulk
func (r *rolePermissionRepository) BulkRevokePermissions(ctx context.Context, rolePermissionIDs []uuid.UUID) error {
	if len(rolePermissionIDs) == 0 {
		return nil
	}

	query := `DELETE FROM role_permissions WHERE id = ANY($1)`
	_, err := r.db.ExecContext(ctx, query, rolePermissionIDs)
	if err != nil {
		return fmt.Errorf("failed to bulk revoke permissions: %w", err)
	}

	return nil
}
