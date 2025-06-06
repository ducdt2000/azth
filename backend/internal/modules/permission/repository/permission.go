package repository

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/ducdt2000/azth/backend/internal/domain"
	"github.com/ducdt2000/azth/backend/internal/modules/permission/dto"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

// permissionRepository implements PermissionRepository interface
type permissionRepository struct {
	db *sqlx.DB
}

// NewPermissionRepository creates a new permission repository
func NewPermissionRepository(db *sqlx.DB) PermissionRepository {
	return &permissionRepository{
		db: db,
	}
}

// Create creates a new permission
func (r *permissionRepository) Create(ctx context.Context, permission *domain.Permission) error {
	query := `
		INSERT INTO permissions (
			id, name, code, description, module, resource, action, 
			is_system, is_default, metadata, created_at, updated_at
		) VALUES (
			:id, :name, :code, :description, :module, :resource, :action,
			:is_system, :is_default, :metadata, :created_at, :updated_at
		)`

	_, err := r.db.NamedExecContext(ctx, query, permission)
	if err != nil {
		return fmt.Errorf("failed to create permission: %w", err)
	}

	return nil
}

// GetByID retrieves a permission by ID
func (r *permissionRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.Permission, error) {
	query := `
		SELECT id, name, code, description, module, resource, action,
			   is_system, is_default, metadata, created_at, updated_at, deleted_at
		FROM permissions 
		WHERE id = $1 AND deleted_at IS NULL`

	var permission domain.Permission
	err := r.db.GetContext(ctx, &permission, query, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get permission by ID: %w", err)
	}

	return &permission, nil
}

// GetByCode retrieves a permission by code
func (r *permissionRepository) GetByCode(ctx context.Context, code string) (*domain.Permission, error) {
	query := `
		SELECT id, name, code, description, module, resource, action,
			   is_system, is_default, metadata, created_at, updated_at, deleted_at
		FROM permissions 
		WHERE code = $1 AND deleted_at IS NULL`

	var permission domain.Permission
	err := r.db.GetContext(ctx, &permission, query, code)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get permission by code: %w", err)
	}

	return &permission, nil
}

// Update updates an existing permission
func (r *permissionRepository) Update(ctx context.Context, permission *domain.Permission) error {
	query := `
		UPDATE permissions SET
			name = :name,
			description = :description,
			module = :module,
			resource = :resource,
			action = :action,
			is_default = :is_default,
			metadata = :metadata,
			updated_at = :updated_at
		WHERE id = :id AND deleted_at IS NULL`

	result, err := r.db.NamedExecContext(ctx, query, permission)
	if err != nil {
		return fmt.Errorf("failed to update permission: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("permission not found or already deleted")
	}

	return nil
}

// Delete soft deletes a permission
func (r *permissionRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `
		UPDATE permissions SET
			deleted_at = $1,
			updated_at = $1
		WHERE id = $2 AND deleted_at IS NULL`

	now := time.Now()
	result, err := r.db.ExecContext(ctx, query, now, id)
	if err != nil {
		return fmt.Errorf("failed to delete permission: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("permission not found or already deleted")
	}

	return nil
}

// List retrieves permissions with filtering and pagination
func (r *permissionRepository) List(ctx context.Context, req *dto.PermissionListRequest) ([]*domain.Permission, int64, error) {
	var conditions []string
	var args []interface{}
	argIndex := 1

	conditions = append(conditions, "deleted_at IS NULL")

	// Build WHERE conditions
	if req.Search != "" {
		searchPattern := "%" + req.Search + "%"
		conditions = append(conditions, fmt.Sprintf("(name ILIKE $%d OR code ILIKE $%d OR description ILIKE $%d)", argIndex, argIndex, argIndex))
		args = append(args, searchPattern)
		argIndex++
	}

	if req.Module != "" {
		conditions = append(conditions, fmt.Sprintf("module = $%d", argIndex))
		args = append(args, req.Module)
		argIndex++
	}

	if req.Resource != "" {
		conditions = append(conditions, fmt.Sprintf("resource = $%d", argIndex))
		args = append(args, req.Resource)
		argIndex++
	}

	if req.Action != "" {
		conditions = append(conditions, fmt.Sprintf("action = $%d", argIndex))
		args = append(args, req.Action)
		argIndex++
	}

	if req.IsSystem != nil {
		conditions = append(conditions, fmt.Sprintf("is_system = $%d", argIndex))
		args = append(args, *req.IsSystem)
		argIndex++
	}

	if req.IsDefault != nil {
		conditions = append(conditions, fmt.Sprintf("is_default = $%d", argIndex))
		args = append(args, *req.IsDefault)
		argIndex++
	}

	whereClause := "WHERE " + strings.Join(conditions, " AND ")

	// Count total
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM permissions %s", whereClause)
	var total int64
	err := r.db.GetContext(ctx, &total, countQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count permissions: %w", err)
	}

	// Build ORDER BY clause with whitelist validation
	orderBy := "ORDER BY created_at DESC"
	if req.SortBy != "" {
		// Validate sortBy against allowed columns to prevent SQL injection
		validSortColumns := map[string]bool{
			"name":       true,
			"code":       true,
			"module":     true,
			"resource":   true,
			"action":     true,
			"created_at": true,
			"updated_at": true,
		}

		if !validSortColumns[req.SortBy] {
			return nil, 0, fmt.Errorf("invalid sort column: %s", req.SortBy)
		}

		direction := "ASC"
		if req.SortOrder == "desc" {
			direction = "DESC"
		}
		orderBy = fmt.Sprintf("ORDER BY %s %s", req.SortBy, direction)
	}

	// Build main query with pagination
	offset := (req.Page - 1) * req.Limit
	query := fmt.Sprintf(`
		SELECT id, name, code, description, module, resource, action,
			   is_system, is_default, metadata, created_at, updated_at, deleted_at
		FROM permissions %s %s
		LIMIT $%d OFFSET $%d`,
		whereClause, orderBy, argIndex, argIndex+1)

	args = append(args, req.Limit, offset)

	var permissions []*domain.Permission
	err = r.db.SelectContext(ctx, &permissions, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list permissions: %w", err)
	}

	return permissions, total, nil
}

// GetByModule retrieves permissions by module
func (r *permissionRepository) GetByModule(ctx context.Context, module string) ([]*domain.Permission, error) {
	query := `
		SELECT id, name, code, description, module, resource, action,
			   is_system, is_default, metadata, created_at, updated_at, deleted_at
		FROM permissions 
		WHERE module = $1 AND deleted_at IS NULL
		ORDER BY resource, action`

	var permissions []*domain.Permission
	err := r.db.SelectContext(ctx, &permissions, query, module)
	if err != nil {
		return nil, fmt.Errorf("failed to get permissions by module: %w", err)
	}

	return permissions, nil
}

// GetByResource retrieves permissions by module and resource
func (r *permissionRepository) GetByResource(ctx context.Context, module, resource string) ([]*domain.Permission, error) {
	query := `
		SELECT id, name, code, description, module, resource, action,
			   is_system, is_default, metadata, created_at, updated_at, deleted_at
		FROM permissions 
		WHERE module = $1 AND resource = $2 AND deleted_at IS NULL
		ORDER BY action`

	var permissions []*domain.Permission
	err := r.db.SelectContext(ctx, &permissions, query, module, resource)
	if err != nil {
		return nil, fmt.Errorf("failed to get permissions by resource: %w", err)
	}

	return permissions, nil
}

// GetByAction retrieves permissions by module, resource, and action
func (r *permissionRepository) GetByAction(ctx context.Context, module, resource, action string) (*domain.Permission, error) {
	query := `
		SELECT id, name, code, description, module, resource, action,
			   is_system, is_default, metadata, created_at, updated_at, deleted_at
		FROM permissions 
		WHERE module = $1 AND resource = $2 AND action = $3 AND deleted_at IS NULL`

	var permission domain.Permission
	err := r.db.GetContext(ctx, &permission, query, module, resource, action)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get permission by action: %w", err)
	}

	return &permission, nil
}

// GetDefaultPermissions retrieves all default permissions
func (r *permissionRepository) GetDefaultPermissions(ctx context.Context) ([]*domain.Permission, error) {
	query := `
		SELECT id, name, code, description, module, resource, action,
			   is_system, is_default, metadata, created_at, updated_at, deleted_at
		FROM permissions 
		WHERE is_default = true AND deleted_at IS NULL
		ORDER BY module, resource, action`

	var permissions []*domain.Permission
	err := r.db.SelectContext(ctx, &permissions, query)
	if err != nil {
		return nil, fmt.Errorf("failed to get default permissions: %w", err)
	}

	return permissions, nil
}

// GetSystemPermissions retrieves all system permissions
func (r *permissionRepository) GetSystemPermissions(ctx context.Context) ([]*domain.Permission, error) {
	query := `
		SELECT id, name, code, description, module, resource, action,
			   is_system, is_default, metadata, created_at, updated_at, deleted_at
		FROM permissions 
		WHERE is_system = true AND deleted_at IS NULL
		ORDER BY module, resource, action`

	var permissions []*domain.Permission
	err := r.db.SelectContext(ctx, &permissions, query)
	if err != nil {
		return nil, fmt.Errorf("failed to get system permissions: %w", err)
	}

	return permissions, nil
}

// GetModules retrieves available modules and their resources
func (r *permissionRepository) GetModules(ctx context.Context) (map[string]map[string][]string, error) {
	query := `
		SELECT DISTINCT module, resource, action
		FROM permissions 
		WHERE deleted_at IS NULL
		ORDER BY module, resource, action`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to get modules: %w", err)
	}
	defer rows.Close()

	modules := make(map[string]map[string][]string)

	for rows.Next() {
		var module, resource, action string
		if err := rows.Scan(&module, &resource, &action); err != nil {
			return nil, fmt.Errorf("failed to scan module data: %w", err)
		}

		if modules[module] == nil {
			modules[module] = make(map[string][]string)
		}

		modules[module][resource] = append(modules[module][resource], action)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate over modules: %w", err)
	}

	return modules, nil
}

// BulkCreate creates multiple permissions
func (r *permissionRepository) BulkCreate(ctx context.Context, permissions []*domain.Permission) error {
	if len(permissions) == 0 {
		return nil
	}

	query := `
		INSERT INTO permissions (
			id, name, code, description, module, resource, action, 
			is_system, is_default, metadata, created_at, updated_at
		) VALUES (
			:id, :name, :code, :description, :module, :resource, :action,
			:is_system, :is_default, :metadata, :created_at, :updated_at
		)`

	_, err := r.db.NamedExecContext(ctx, query, permissions)
	if err != nil {
		return fmt.Errorf("failed to bulk create permissions: %w", err)
	}

	return nil
}

// BulkDelete deletes multiple permissions by IDs
func (r *permissionRepository) BulkDelete(ctx context.Context, ids []uuid.UUID) error {
	if len(ids) == 0 {
		return nil
	}

	query := `
		UPDATE permissions SET
			deleted_at = $1,
			updated_at = $1
		WHERE id = ANY($2) AND deleted_at IS NULL`

	now := time.Now()
	_, err := r.db.ExecContext(ctx, query, now, pq.Array(ids))
	if err != nil {
		return fmt.Errorf("failed to bulk delete permissions: %w", err)
	}

	return nil
}

// ExistsByCode checks if a permission with the given code exists
func (r *permissionRepository) ExistsByCode(ctx context.Context, code string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM permissions WHERE code = $1 AND deleted_at IS NULL)`

	var exists bool
	err := r.db.GetContext(ctx, &exists, query, code)
	if err != nil {
		return false, fmt.Errorf("failed to check if permission exists by code: %w", err)
	}

	return exists, nil
}

// ExistsByModuleResourceAction checks if a permission exists for the given combination
func (r *permissionRepository) ExistsByModuleResourceAction(ctx context.Context, module, resource, action string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM permissions WHERE module = $1 AND resource = $2 AND action = $3 AND deleted_at IS NULL)`

	var exists bool
	err := r.db.GetContext(ctx, &exists, query, module, resource, action)
	if err != nil {
		return false, fmt.Errorf("failed to check if permission exists by module/resource/action: %w", err)
	}

	return exists, nil
}

// GetPermissionsByIDs retrieves permissions by their IDs
func (r *permissionRepository) GetPermissionsByIDs(ctx context.Context, ids []uuid.UUID) ([]*domain.Permission, error) {
	if len(ids) == 0 {
		return []*domain.Permission{}, nil
	}

	query := `
		SELECT id, name, code, description, module, resource, action,
			   is_system, is_default, metadata, created_at, updated_at, deleted_at
		FROM permissions 
		WHERE id = ANY($1) AND deleted_at IS NULL
		ORDER BY created_at`

	var permissions []*domain.Permission
	err := r.db.SelectContext(ctx, &permissions, query, pq.Array(ids))
	if err != nil {
		return nil, fmt.Errorf("failed to get permissions by IDs: %w", err)
	}

	return permissions, nil
}
