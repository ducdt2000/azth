package repository

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/ducdt2000/azth/backend/internal/domain"
	"github.com/ducdt2000/azth/backend/internal/modules/role/dto"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

// roleRepository implements RoleRepository interface
type roleRepository struct {
	db *sqlx.DB
}

// NewRoleRepository creates a new role repository
func NewRoleRepository(db *sqlx.DB) RoleRepository {
	return &roleRepository{
		db: db,
	}
}

// Create creates a new role
func (r *roleRepository) Create(ctx context.Context, role *domain.Role) error {
	query := `
		INSERT INTO roles (
			id, tenant_id, name, slug, description, is_system, is_global, 
			is_default, priority, metadata, created_at, updated_at, created_by, updated_by
		) VALUES (
			:id, :tenant_id, :name, :slug, :description, :is_system, :is_global,
			:is_default, :priority, :metadata, :created_at, :updated_at, :created_by, :updated_by
		)`

	_, err := r.db.NamedExecContext(ctx, query, role)
	if err != nil {
		return fmt.Errorf("failed to create role: %w", err)
	}

	return nil
}

// GetByID retrieves a role by ID
func (r *roleRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.Role, error) {
	query := `
		SELECT id, tenant_id, name, slug, description, is_system, is_global,
			   is_default, priority, metadata, created_at, updated_at, 
			   deleted_at, created_by, updated_by
		FROM roles 
		WHERE id = $1 AND deleted_at IS NULL`

	var role domain.Role
	err := r.db.GetContext(ctx, &role, query, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get role by ID: %w", err)
	}

	return &role, nil
}

// GetBySlug retrieves a role by slug and tenant
func (r *roleRepository) GetBySlug(ctx context.Context, slug string, tenantID *uuid.UUID) (*domain.Role, error) {
	query := `
		SELECT id, tenant_id, name, slug, description, is_system, is_global,
			   is_default, priority, metadata, created_at, updated_at, 
			   deleted_at, created_by, updated_by
		FROM roles 
		WHERE slug = $1 AND deleted_at IS NULL`

	args := []interface{}{slug}

	if tenantID != nil {
		query += " AND (tenant_id = $2 OR is_global = true)"
		args = append(args, *tenantID)
	} else {
		query += " AND (tenant_id IS NULL OR is_global = true)"
	}

	var role domain.Role
	err := r.db.GetContext(ctx, &role, query, args...)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get role by slug: %w", err)
	}

	return &role, nil
}

// Update updates an existing role
func (r *roleRepository) Update(ctx context.Context, role *domain.Role) error {
	query := `
		UPDATE roles SET
			name = :name,
			description = :description,
			is_default = :is_default,
			priority = :priority,
			metadata = :metadata,
			updated_at = :updated_at,
			updated_by = :updated_by
		WHERE id = :id AND deleted_at IS NULL`

	result, err := r.db.NamedExecContext(ctx, query, role)
	if err != nil {
		return fmt.Errorf("failed to update role: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("role not found or already deleted")
	}

	return nil
}

// Delete soft deletes a role
func (r *roleRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `
		UPDATE roles SET
			deleted_at = $1,
			updated_at = $1
		WHERE id = $2 AND deleted_at IS NULL`

	now := time.Now()
	result, err := r.db.ExecContext(ctx, query, now, id)
	if err != nil {
		return fmt.Errorf("failed to delete role: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("role not found or already deleted")
	}

	return nil
}

// List retrieves roles with filtering and pagination
func (r *roleRepository) List(ctx context.Context, req *dto.RoleListRequest) ([]*domain.Role, int64, error) {
	var conditions []string
	var args []interface{}
	argIndex := 1

	conditions = append(conditions, "deleted_at IS NULL")

	// Build WHERE conditions
	if req.Search != "" {
		searchPattern := "%" + req.Search + "%"
		conditions = append(conditions, fmt.Sprintf("(name ILIKE $%d OR slug ILIKE $%d OR description ILIKE $%d)", argIndex, argIndex, argIndex))
		args = append(args, searchPattern)
		argIndex++
	}

	if req.TenantID != nil {
		conditions = append(conditions, fmt.Sprintf("(tenant_id = $%d OR is_global = true)", argIndex))
		args = append(args, *req.TenantID)
		argIndex++
	}

	if req.IsSystem != nil {
		conditions = append(conditions, fmt.Sprintf("is_system = $%d", argIndex))
		args = append(args, *req.IsSystem)
		argIndex++
	}

	if req.IsGlobal != nil {
		conditions = append(conditions, fmt.Sprintf("is_global = $%d", argIndex))
		args = append(args, *req.IsGlobal)
		argIndex++
	}

	if req.IsDefault != nil {
		conditions = append(conditions, fmt.Sprintf("is_default = $%d", argIndex))
		args = append(args, *req.IsDefault)
		argIndex++
	}

	whereClause := "WHERE " + strings.Join(conditions, " AND ")

	// Count total
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM roles %s", whereClause)
	var total int64
	err := r.db.GetContext(ctx, &total, countQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count roles: %w", err)
	}

	// Build ORDER BY clause with whitelist validation
	orderBy := "ORDER BY priority DESC, created_at DESC"
	if req.SortBy != "" {
		// Validate sortBy against allowed columns to prevent SQL injection
		validSortColumns := map[string]bool{
			"name":       true,
			"slug":       true,
			"priority":   true,
			"created_at": true,
			"updated_at": true,
			"is_global":  true,
			"is_system":  true,
			"is_default": true,
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
		SELECT id, tenant_id, name, slug, description, is_system, is_global,
			   is_default, priority, metadata, created_at, updated_at, 
			   deleted_at, created_by, updated_by
		FROM roles %s %s
		LIMIT $%d OFFSET $%d`,
		whereClause, orderBy, argIndex, argIndex+1)

	args = append(args, req.Limit, offset)

	var roles []*domain.Role
	err = r.db.SelectContext(ctx, &roles, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list roles: %w", err)
	}

	return roles, total, nil
}

// GetByTenant retrieves roles for a specific tenant
func (r *roleRepository) GetByTenant(ctx context.Context, tenantID uuid.UUID) ([]*domain.Role, error) {
	query := `
		SELECT id, tenant_id, name, slug, description, is_system, is_global,
			   is_default, priority, metadata, created_at, updated_at, 
			   deleted_at, created_by, updated_by
		FROM roles 
		WHERE (tenant_id = $1 OR is_global = true) AND deleted_at IS NULL
		ORDER BY priority DESC, name`

	var roles []*domain.Role
	err := r.db.SelectContext(ctx, &roles, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get roles by tenant: %w", err)
	}

	return roles, nil
}

// GetGlobalRoles retrieves all global roles
func (r *roleRepository) GetGlobalRoles(ctx context.Context) ([]*domain.Role, error) {
	query := `
		SELECT id, tenant_id, name, slug, description, is_system, is_global,
			   is_default, priority, metadata, created_at, updated_at, 
			   deleted_at, created_by, updated_by
		FROM roles 
		WHERE is_global = true AND deleted_at IS NULL
		ORDER BY priority DESC, name`

	var roles []*domain.Role
	err := r.db.SelectContext(ctx, &roles, query)
	if err != nil {
		return nil, fmt.Errorf("failed to get global roles: %w", err)
	}

	return roles, nil
}

// GetSystemRoles retrieves all system roles
func (r *roleRepository) GetSystemRoles(ctx context.Context) ([]*domain.Role, error) {
	query := `
		SELECT id, tenant_id, name, slug, description, is_system, is_global,
			   is_default, priority, metadata, created_at, updated_at, 
			   deleted_at, created_by, updated_by
		FROM roles 
		WHERE is_system = true AND deleted_at IS NULL
		ORDER BY priority DESC, name`

	var roles []*domain.Role
	err := r.db.SelectContext(ctx, &roles, query)
	if err != nil {
		return nil, fmt.Errorf("failed to get system roles: %w", err)
	}

	return roles, nil
}

// GetDefaultRoles retrieves default roles for a tenant
func (r *roleRepository) GetDefaultRoles(ctx context.Context, tenantID *uuid.UUID) ([]*domain.Role, error) {
	query := `
		SELECT id, tenant_id, name, slug, description, is_system, is_global,
			   is_default, priority, metadata, created_at, updated_at, 
			   deleted_at, created_by, updated_by
		FROM roles 
		WHERE is_default = true AND deleted_at IS NULL`

	args := []interface{}{}

	if tenantID != nil {
		query += " AND (tenant_id = $1 OR is_global = true)"
		args = append(args, *tenantID)
	} else {
		query += " AND (tenant_id IS NULL OR is_global = true)"
	}

	query += " ORDER BY priority DESC, name"

	var roles []*domain.Role
	err := r.db.SelectContext(ctx, &roles, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get default roles: %w", err)
	}

	return roles, nil
}

// GetAvailableRolesForTenant retrieves all roles available for a tenant (tenant-specific + global)
func (r *roleRepository) GetAvailableRolesForTenant(ctx context.Context, tenantID uuid.UUID) ([]*domain.Role, error) {
	query := `
		SELECT id, tenant_id, name, slug, description, is_system, is_global,
			   is_default, priority, metadata, created_at, updated_at, 
			   deleted_at, created_by, updated_by
		FROM roles 
		WHERE (tenant_id = $1 OR is_global = true) AND deleted_at IS NULL
		ORDER BY priority DESC, name`

	var roles []*domain.Role
	err := r.db.SelectContext(ctx, &roles, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get available roles for tenant: %w", err)
	}

	return roles, nil
}

// ExistsBySlug checks if a role with the given slug exists in the tenant scope
func (r *roleRepository) ExistsBySlug(ctx context.Context, slug string, tenantID *uuid.UUID) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM roles WHERE slug = $1 AND deleted_at IS NULL`
	args := []interface{}{slug}

	if tenantID != nil {
		query += " AND (tenant_id = $2 OR is_global = true))"
		args = append(args, *tenantID)
	} else {
		query += " AND (tenant_id IS NULL OR is_global = true))"
	}

	var exists bool
	err := r.db.GetContext(ctx, &exists, query, args...)
	if err != nil {
		return false, fmt.Errorf("failed to check if role exists by slug: %w", err)
	}

	return exists, nil
}

// ExistsByName checks if a role with the given name exists in the tenant scope
func (r *roleRepository) ExistsByName(ctx context.Context, name string, tenantID *uuid.UUID) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM roles WHERE name = $1 AND deleted_at IS NULL`
	args := []interface{}{name}

	if tenantID != nil {
		query += " AND (tenant_id = $2 OR is_global = true))"
		args = append(args, *tenantID)
	} else {
		query += " AND (tenant_id IS NULL OR is_global = true))"
	}

	var exists bool
	err := r.db.GetContext(ctx, &exists, query, args...)
	if err != nil {
		return false, fmt.Errorf("failed to check if role exists by name: %w", err)
	}

	return exists, nil
}

// BulkCreate creates multiple roles
func (r *roleRepository) BulkCreate(ctx context.Context, roles []*domain.Role) error {
	if len(roles) == 0 {
		return nil
	}

	query := `
		INSERT INTO roles (
			id, tenant_id, name, slug, description, is_system, is_global, 
			is_default, priority, metadata, created_at, updated_at, created_by, updated_by
		) VALUES (
			:id, :tenant_id, :name, :slug, :description, :is_system, :is_global,
			:is_default, :priority, :metadata, :created_at, :updated_at, :created_by, :updated_by
		)`

	_, err := r.db.NamedExecContext(ctx, query, roles)
	if err != nil {
		return fmt.Errorf("failed to bulk create roles: %w", err)
	}

	return nil
}

// BulkDelete deletes multiple roles by IDs
func (r *roleRepository) BulkDelete(ctx context.Context, ids []uuid.UUID) error {
	if len(ids) == 0 {
		return nil
	}

	query := `
		UPDATE roles SET
			deleted_at = $1,
			updated_at = $1
		WHERE id = ANY($2) AND deleted_at IS NULL`

	now := time.Now()
	_, err := r.db.ExecContext(ctx, query, now, pq.Array(ids))
	if err != nil {
		return fmt.Errorf("failed to bulk delete roles: %w", err)
	}

	return nil
}

// GetRolesByIDs retrieves roles by their IDs
func (r *roleRepository) GetRolesByIDs(ctx context.Context, ids []uuid.UUID) ([]*domain.Role, error) {
	if len(ids) == 0 {
		return []*domain.Role{}, nil
	}

	query := `
		SELECT id, tenant_id, name, slug, description, is_system, is_global,
			   is_default, priority, metadata, created_at, updated_at, 
			   deleted_at, created_by, updated_by
		FROM roles 
		WHERE id = ANY($1) AND deleted_at IS NULL
		ORDER BY priority DESC, created_at`

	var roles []*domain.Role
	err := r.db.SelectContext(ctx, &roles, query, pq.Array(ids))
	if err != nil {
		return nil, fmt.Errorf("failed to get roles by IDs: %w", err)
	}

	return roles, nil
}

// GetRoleStats retrieves role statistics
func (r *roleRepository) GetRoleStats(ctx context.Context, req *dto.RoleStatsRequest) (*dto.RoleStatsResponse, error) {
	// For now, return a basic implementation
	// TODO: Implement proper statistics queries
	return &dto.RoleStatsResponse{
		TotalRoles:      0,
		SystemRoles:     0,
		CustomRoles:     0,
		GlobalRoles:     0,
		TenantRoles:     0,
		DefaultRoles:    0,
		RoleAssignments: 0,
		TopRoles:        []*dto.RoleUsageResponse{},
	}, nil
}

// GetTopRolesByUsage retrieves top roles by usage
func (r *roleRepository) GetTopRolesByUsage(ctx context.Context, limit int, tenantID *uuid.UUID) ([]*dto.RoleUsageResponse, error) {
	// For now, return empty implementation
	// TODO: Implement proper usage statistics
	return []*dto.RoleUsageResponse{}, nil
}
