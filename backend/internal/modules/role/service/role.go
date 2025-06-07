package service

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/ducdt2000/azth/backend/internal/domain"
	permissionDto "github.com/ducdt2000/azth/backend/internal/modules/permission/dto"
	permissionRepo "github.com/ducdt2000/azth/backend/internal/modules/permission/repository"
	"github.com/ducdt2000/azth/backend/internal/modules/role/dto"
	"github.com/ducdt2000/azth/backend/internal/modules/role/repository"
	"github.com/ducdt2000/azth/backend/pkg/logger"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

// tracer for OpenTelemetry tracing
var tracer = otel.Tracer("role-service")

// roleService implements RoleService interface
type roleService struct {
	roleRepo           repository.RoleRepository
	rolePermissionRepo repository.RolePermissionRepository
	userRoleRepo       repository.UserRoleRepository
	permissionRepo     permissionRepo.PermissionRepository
	logger             *logger.Logger
}

// NewRoleService creates a new role service
func NewRoleService(
	roleRepo repository.RoleRepository,
	rolePermissionRepo repository.RolePermissionRepository,
	userRoleRepo repository.UserRoleRepository,
	permissionRepo permissionRepo.PermissionRepository,
	logger *logger.Logger,
) RoleService {
	return &roleService{
		roleRepo:           roleRepo,
		rolePermissionRepo: rolePermissionRepo,
		userRoleRepo:       userRoleRepo,
		permissionRepo:     permissionRepo,
		logger:             logger,
	}
}

// CreateRole creates a new role with validation and business rules
func (s *roleService) CreateRole(ctx context.Context, req *dto.RoleRequest, tenantID *uuid.UUID, createdBy uuid.UUID) (*dto.RoleResponse, error) {
	ctx, span := tracer.Start(ctx, "RoleService.CreateRole")
	defer span.End()

	span.SetAttributes(
		attribute.String("role.name", req.Name),
		attribute.String("role.slug", req.Slug),
		attribute.Bool("role.is_global", req.IsGlobal),
	)

	s.logger.Info("Creating role", "name", req.Name, "slug", req.Slug, "tenant_id", tenantID)

	// Validate role slug
	if err := s.ValidateRoleSlug(ctx, req.Slug, tenantID); err != nil {
		return nil, fmt.Errorf("invalid role slug: %w", err)
	}

	// Validate role name
	if err := s.ValidateRoleName(ctx, req.Name, tenantID); err != nil {
		return nil, fmt.Errorf("invalid role name: %w", err)
	}

	// Create role domain object
	role := &domain.Role{
		ID:          uuid.New(),
		TenantID:    tenantID,
		Name:        req.Name,
		Slug:        req.Slug,
		Description: req.Description,
		IsSystem:    false, // User-created roles are not system roles
		IsGlobal:    req.IsGlobal,
		IsDefault:   req.IsDefault,
		Priority:    req.Priority,
		Metadata:    req.Metadata,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		CreatedBy:   createdBy,
	}

	// Create role in repository
	if err := s.roleRepo.Create(ctx, role); err != nil {
		s.logger.Error("Failed to create role", "error", err, "role_name", req.Name)
		return nil, fmt.Errorf("failed to create role: %w", err)
	}

	s.logger.Info("Role created successfully", "role_id", role.ID, "role_name", role.Name)
	return dto.RoleToResponse(role), nil
}

// GetRole retrieves a role by ID
func (s *roleService) GetRole(ctx context.Context, id uuid.UUID) (*dto.RoleResponse, error) {
	ctx, span := tracer.Start(ctx, "RoleService.GetRole")
	defer span.End()

	span.SetAttributes(attribute.String("role.id", id.String()))

	role, err := s.roleRepo.GetByID(ctx, id)
	if err != nil {
		s.logger.Error("Failed to get role", "error", err, "role_id", id)
		return nil, fmt.Errorf("failed to get role: %w", err)
	}

	if role == nil {
		return nil, fmt.Errorf("role not found")
	}

	return dto.RoleToResponse(role), nil
}

// GetRoleBySlug retrieves a role by slug
func (s *roleService) GetRoleBySlug(ctx context.Context, slug string, tenantID *uuid.UUID) (*dto.RoleResponse, error) {
	ctx, span := tracer.Start(ctx, "RoleService.GetRoleBySlug")
	defer span.End()

	span.SetAttributes(attribute.String("role.slug", slug))

	role, err := s.roleRepo.GetBySlug(ctx, slug, tenantID)
	if err != nil {
		s.logger.Error("Failed to get role by slug", "error", err, "slug", slug)
		return nil, fmt.Errorf("failed to get role by slug: %w", err)
	}

	if role == nil {
		return nil, fmt.Errorf("role not found")
	}

	return dto.RoleToResponse(role), nil
}

// UpdateRole updates an existing role with validation
func (s *roleService) UpdateRole(ctx context.Context, id uuid.UUID, req *dto.UpdateRoleRequest, updatedBy uuid.UUID) (*dto.RoleResponse, error) {
	ctx, span := tracer.Start(ctx, "RoleService.UpdateRole")
	defer span.End()

	span.SetAttributes(attribute.String("role.id", id.String()))

	// Get existing role
	role, err := s.roleRepo.GetByID(ctx, id)
	if err != nil {
		s.logger.Error("Failed to get role for update", "error", err, "role_id", id)
		return nil, fmt.Errorf("failed to get role: %w", err)
	}

	if role == nil {
		return nil, fmt.Errorf("role not found")
	}

	// System roles cannot be updated
	if role.IsSystem {
		return nil, fmt.Errorf("system roles cannot be updated")
	}

	// Update fields
	if req.Name != nil {
		role.Name = *req.Name
	}
	if req.Description != nil {
		role.Description = req.Description
	}
	if req.IsDefault != nil {
		role.IsDefault = *req.IsDefault
	}
	if req.Priority != nil {
		role.Priority = *req.Priority
	}
	if req.Metadata != nil {
		role.Metadata = req.Metadata
	}

	role.UpdatedAt = time.Now()
	role.UpdatedBy = &updatedBy

	// Update role in repository
	if err := s.roleRepo.Update(ctx, role); err != nil {
		s.logger.Error("Failed to update role", "error", err, "role_id", id)
		return nil, fmt.Errorf("failed to update role: %w", err)
	}

	s.logger.Info("Role updated successfully", "role_id", id)
	return dto.RoleToResponse(role), nil
}

// DeleteRole soft deletes a role
func (s *roleService) DeleteRole(ctx context.Context, id uuid.UUID) error {
	ctx, span := tracer.Start(ctx, "RoleService.DeleteRole")
	defer span.End()

	span.SetAttributes(attribute.String("role.id", id.String()))

	// Get existing role
	role, err := s.roleRepo.GetByID(ctx, id)
	if err != nil {
		s.logger.Error("Failed to get role for deletion", "error", err, "role_id", id)
		return fmt.Errorf("failed to get role: %w", err)
	}

	if role == nil {
		return fmt.Errorf("role not found")
	}

	// System roles cannot be deleted
	if role.IsSystem {
		return fmt.Errorf("system roles cannot be deleted")
	}

	// Delete role
	if err := s.roleRepo.Delete(ctx, id); err != nil {
		s.logger.Error("Failed to delete role", "error", err, "role_id", id)
		return fmt.Errorf("failed to delete role: %w", err)
	}

	s.logger.Info("Role deleted successfully", "role_id", id)
	return nil
}

// ListRoles retrieves roles with filtering and pagination
func (s *roleService) ListRoles(ctx context.Context, req *dto.RoleListRequest) (*dto.RoleListResponse, error) {
	ctx, span := tracer.Start(ctx, "RoleService.ListRoles")
	defer span.End()

	// Set default pagination
	if req.Page <= 0 {
		req.Page = 1
	}
	if req.Limit <= 0 {
		req.Limit = 20
	}
	if req.Limit > 100 {
		req.Limit = 100
	}

	// Get roles from repository
	roles, total, err := s.roleRepo.List(ctx, req)
	if err != nil {
		s.logger.Error("Failed to list roles", "error", err)
		return nil, fmt.Errorf("failed to list roles: %w", err)
	}

	// Calculate total pages
	totalPages := int(math.Ceil(float64(total) / float64(req.Limit)))

	return &dto.RoleListResponse{
		Roles:      dto.RolesToResponse(roles),
		Total:      total,
		Page:       req.Page,
		Limit:      req.Limit,
		TotalPages: totalPages,
	}, nil
}

// GetRolesByTenant retrieves roles by tenant
func (s *roleService) GetRolesByTenant(ctx context.Context, tenantID uuid.UUID) ([]*dto.RoleResponse, error) {
	ctx, span := tracer.Start(ctx, "RoleService.GetRolesByTenant")
	defer span.End()

	span.SetAttributes(attribute.String("tenant.id", tenantID.String()))

	roles, err := s.roleRepo.GetByTenant(ctx, tenantID)
	if err != nil {
		s.logger.Error("Failed to get roles by tenant", "error", err, "tenant_id", tenantID)
		return nil, fmt.Errorf("failed to get roles by tenant: %w", err)
	}

	return dto.RolesToResponse(roles), nil
}

// GetGlobalRoles retrieves global roles
func (s *roleService) GetGlobalRoles(ctx context.Context) ([]*dto.RoleResponse, error) {
	ctx, span := tracer.Start(ctx, "RoleService.GetGlobalRoles")
	defer span.End()

	roles, err := s.roleRepo.GetGlobalRoles(ctx)
	if err != nil {
		s.logger.Error("Failed to get global roles", "error", err)
		return nil, fmt.Errorf("failed to get global roles: %w", err)
	}

	return dto.RolesToResponse(roles), nil
}

// GetSystemRoles retrieves system roles
func (s *roleService) GetSystemRoles(ctx context.Context) ([]*dto.RoleResponse, error) {
	ctx, span := tracer.Start(ctx, "RoleService.GetSystemRoles")
	defer span.End()

	roles, err := s.roleRepo.GetSystemRoles(ctx)
	if err != nil {
		s.logger.Error("Failed to get system roles", "error", err)
		return nil, fmt.Errorf("failed to get system roles: %w", err)
	}

	return dto.RolesToResponse(roles), nil
}

// GetDefaultRoles retrieves default roles
func (s *roleService) GetDefaultRoles(ctx context.Context, tenantID *uuid.UUID) (*dto.DefaultRoleResponse, error) {
	ctx, span := tracer.Start(ctx, "RoleService.GetDefaultRoles")
	defer span.End()

	roles, err := s.roleRepo.GetDefaultRoles(ctx, tenantID)
	if err != nil {
		s.logger.Error("Failed to get default roles", "error", err)
		return nil, fmt.Errorf("failed to get default roles: %w", err)
	}

	// Separate global and tenant roles
	var globalRoles, tenantRoles []*domain.Role
	for _, role := range roles {
		if role.IsGlobal {
			globalRoles = append(globalRoles, role)
		} else {
			tenantRoles = append(tenantRoles, role)
		}
	}

	// Convert to response format
	tenantRoleResponses := make([]dto.RoleResponse, len(tenantRoles))
	for i, role := range tenantRoles {
		if resp := dto.RoleToResponse(role); resp != nil {
			tenantRoleResponses[i] = *resp
		}
	}

	globalRoleResponses := make([]dto.RoleResponse, len(globalRoles))
	for i, role := range globalRoles {
		if resp := dto.RoleToResponse(role); resp != nil {
			globalRoleResponses[i] = *resp
		}
	}

	return &dto.DefaultRoleResponse{
		TenantRoles: tenantRoleResponses,
		GlobalRoles: globalRoleResponses,
	}, nil
}

// GetAvailableRolesForTenant retrieves available roles for a tenant (global + tenant-specific)
func (s *roleService) GetAvailableRolesForTenant(ctx context.Context, tenantID uuid.UUID) ([]*dto.RoleResponse, error) {
	ctx, span := tracer.Start(ctx, "RoleService.GetAvailableRolesForTenant")
	defer span.End()

	span.SetAttributes(attribute.String("tenant.id", tenantID.String()))

	roles, err := s.roleRepo.GetAvailableRolesForTenant(ctx, tenantID)
	if err != nil {
		s.logger.Error("Failed to get available roles for tenant", "error", err, "tenant_id", tenantID)
		return nil, fmt.Errorf("failed to get available roles for tenant: %w", err)
	}

	return dto.RolesToResponse(roles), nil
}

// AssignPermissions assigns permissions to a role
func (s *roleService) AssignPermissions(ctx context.Context, roleID uuid.UUID, req *dto.RolePermissionRequest, assignedBy uuid.UUID) (*dto.RolePermissionResponse, error) {
	ctx, span := tracer.Start(ctx, "RoleService.AssignPermissions")
	defer span.End()

	span.SetAttributes(
		attribute.String("role.id", roleID.String()),
		attribute.Int("permissions.count", len(req.PermissionIDs)),
	)

	// Get role to ensure it exists
	role, err := s.roleRepo.GetByID(ctx, roleID)
	if err != nil {
		s.logger.Error("Failed to get role for permission assignment", "error", err, "role_id", roleID)
		return nil, fmt.Errorf("failed to get role: %w", err)
	}

	if role == nil {
		return nil, fmt.Errorf("role not found")
	}

	// Validate permissions exist
	for _, permissionID := range req.PermissionIDs {
		permission, err := s.permissionRepo.GetByID(ctx, permissionID)
		if err != nil {
			s.logger.Error("Failed to validate permission", "error", err, "permission_id", permissionID)
			return nil, fmt.Errorf("failed to validate permission %s: %w", permissionID, err)
		}
		if permission == nil {
			return nil, fmt.Errorf("permission %s not found", permissionID)
		}
	}

	// Assign permissions
	if err := s.rolePermissionRepo.AssignPermissions(ctx, roleID, req.PermissionIDs, assignedBy); err != nil {
		s.logger.Error("Failed to assign permissions to role", "error", err, "role_id", roleID)
		return nil, fmt.Errorf("failed to assign permissions: %w", err)
	}

	// Get role permissions
	permissions, err := s.rolePermissionRepo.GetRolePermissions(ctx, roleID)
	if err != nil {
		s.logger.Error("Failed to get role permissions after assignment", "error", err, "role_id", roleID)
		return nil, fmt.Errorf("failed to get role permissions: %w", err)
	}

	s.logger.Info("Permissions assigned to role successfully", "role_id", roleID, "permissions_count", len(req.PermissionIDs))

	return &dto.RolePermissionResponse{
		RoleID:      roleID,
		Permissions: permissionDto.PermissionsToResponse(permissions),
	}, nil
}

// RevokePermissions revokes permissions from a role
func (s *roleService) RevokePermissions(ctx context.Context, roleID uuid.UUID, req *dto.RolePermissionRequest) error {
	ctx, span := tracer.Start(ctx, "RoleService.RevokePermissions")
	defer span.End()

	span.SetAttributes(
		attribute.String("role.id", roleID.String()),
		attribute.Int("permissions.count", len(req.PermissionIDs)),
	)

	// Get role to ensure it exists
	role, err := s.roleRepo.GetByID(ctx, roleID)
	if err != nil {
		s.logger.Error("Failed to get role for permission revocation", "error", err, "role_id", roleID)
		return fmt.Errorf("failed to get role: %w", err)
	}

	if role == nil {
		return fmt.Errorf("role not found")
	}

	// Revoke permissions
	if err := s.rolePermissionRepo.RevokePermissions(ctx, roleID, req.PermissionIDs); err != nil {
		s.logger.Error("Failed to revoke permissions from role", "error", err, "role_id", roleID)
		return fmt.Errorf("failed to revoke permissions: %w", err)
	}

	s.logger.Info("Permissions revoked from role successfully", "role_id", roleID, "permissions_count", len(req.PermissionIDs))
	return nil
}

// ReplacePermissions replaces all permissions for a role
func (s *roleService) ReplacePermissions(ctx context.Context, roleID uuid.UUID, req *dto.RolePermissionRequest, assignedBy uuid.UUID) (*dto.RolePermissionResponse, error) {
	ctx, span := tracer.Start(ctx, "RoleService.ReplacePermissions")
	defer span.End()

	span.SetAttributes(
		attribute.String("role.id", roleID.String()),
		attribute.Int("permissions.count", len(req.PermissionIDs)),
	)

	// Get role to ensure it exists
	role, err := s.roleRepo.GetByID(ctx, roleID)
	if err != nil {
		s.logger.Error("Failed to get role for permission replacement", "error", err, "role_id", roleID)
		return nil, fmt.Errorf("failed to get role: %w", err)
	}

	if role == nil {
		return nil, fmt.Errorf("role not found")
	}

	// Validate permissions exist
	for _, permissionID := range req.PermissionIDs {
		permission, err := s.permissionRepo.GetByID(ctx, permissionID)
		if err != nil {
			s.logger.Error("Failed to validate permission", "error", err, "permission_id", permissionID)
			return nil, fmt.Errorf("failed to validate permission %s: %w", permissionID, err)
		}
		if permission == nil {
			return nil, fmt.Errorf("permission %s not found", permissionID)
		}
	}

	// Replace permissions
	if err := s.rolePermissionRepo.ReplacePermissions(ctx, roleID, req.PermissionIDs, assignedBy); err != nil {
		s.logger.Error("Failed to replace permissions for role", "error", err, "role_id", roleID)
		return nil, fmt.Errorf("failed to replace permissions: %w", err)
	}

	// Get role permissions
	permissions, err := s.rolePermissionRepo.GetRolePermissions(ctx, roleID)
	if err != nil {
		s.logger.Error("Failed to get role permissions after replacement", "error", err, "role_id", roleID)
		return nil, fmt.Errorf("failed to get role permissions: %w", err)
	}

	s.logger.Info("Permissions replaced for role successfully", "role_id", roleID, "permissions_count", len(req.PermissionIDs))

	return &dto.RolePermissionResponse{
		RoleID:      roleID,
		Permissions: permissionDto.PermissionsToResponse(permissions),
	}, nil
}

// GetRolePermissions retrieves permissions for a role
func (s *roleService) GetRolePermissions(ctx context.Context, roleID uuid.UUID) (*dto.RolePermissionResponse, error) {
	ctx, span := tracer.Start(ctx, "RoleService.GetRolePermissions")
	defer span.End()

	span.SetAttributes(attribute.String("role.id", roleID.String()))

	permissions, err := s.rolePermissionRepo.GetRolePermissions(ctx, roleID)
	if err != nil {
		s.logger.Error("Failed to get role permissions", "error", err, "role_id", roleID)
		return nil, fmt.Errorf("failed to get role permissions: %w", err)
	}

	return &dto.RolePermissionResponse{
		RoleID:      roleID,
		Permissions: permissionDto.PermissionsToResponse(permissions),
	}, nil
}

// AssignRoleToUser assigns a role to a user
func (s *roleService) AssignRoleToUser(ctx context.Context, roleID uuid.UUID, req *dto.AssignRoleRequest, assignedBy uuid.UUID) (*dto.UserRoleResponse, error) {
	ctx, span := tracer.Start(ctx, "RoleService.AssignRoleToUser")
	defer span.End()

	span.SetAttributes(
		attribute.String("role.id", roleID.String()),
		attribute.String("user.id", req.UserID.String()),
		attribute.String("tenant.id", req.TenantID.String()),
	)

	// Get role to ensure it exists
	role, err := s.roleRepo.GetByID(ctx, roleID)
	if err != nil {
		s.logger.Error("Failed to get role for user assignment", "error", err, "role_id", roleID)
		return nil, fmt.Errorf("failed to get role: %w", err)
	}

	if role == nil {
		return nil, fmt.Errorf("role not found")
	}

	// Check if user already has the role
	hasRole, err := s.HasRole(ctx, req.UserID, roleID, req.TenantID)
	if err != nil {
		s.logger.Error("Failed to check if user has role", "error", err, "user_id", req.UserID, "role_id", roleID)
		return nil, fmt.Errorf("failed to check if user has role: %w", err)
	}

	if hasRole {
		return nil, fmt.Errorf("user already has this role")
	}

	// Assign role to user
	userRole := &domain.UserRole{
		ID:        uuid.New(),
		UserID:    req.UserID,
		RoleID:    roleID,
		TenantID:  req.TenantID,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		CreatedBy: assignedBy,
	}

	if err := s.userRoleRepo.AssignRole(ctx, userRole); err != nil {
		s.logger.Error("Failed to assign role to user", "error", err, "user_id", req.UserID, "role_id", roleID)
		return nil, fmt.Errorf("failed to assign role to user: %w", err)
	}

	s.logger.Info("Role assigned to user successfully", "user_id", req.UserID, "role_id", roleID, "tenant_id", req.TenantID)

	return &dto.UserRoleResponse{
		ID:       userRole.ID,
		UserID:   userRole.UserID,
		RoleID:   userRole.RoleID,
		TenantID: userRole.TenantID,
		Role:     dto.RoleToResponse(role),
	}, nil
}

// RevokeRoleFromUser revokes a role from a user
func (s *roleService) RevokeRoleFromUser(ctx context.Context, roleID uuid.UUID, req *dto.RevokeRoleRequest) error {
	ctx, span := tracer.Start(ctx, "RoleService.RevokeRoleFromUser")
	defer span.End()

	span.SetAttributes(
		attribute.String("role.id", roleID.String()),
		attribute.String("user.id", req.UserID.String()),
		attribute.String("tenant.id", req.TenantID.String()),
	)

	// Check if user has the role
	hasRole, err := s.HasRole(ctx, req.UserID, roleID, req.TenantID)
	if err != nil {
		s.logger.Error("Failed to check if user has role", "error", err, "user_id", req.UserID, "role_id", roleID)
		return fmt.Errorf("failed to check if user has role: %w", err)
	}

	if !hasRole {
		return fmt.Errorf("user does not have this role")
	}

	// Revoke role from user
	if err := s.userRoleRepo.RevokeRole(ctx, req.UserID, roleID, req.TenantID); err != nil {
		s.logger.Error("Failed to revoke role from user", "error", err, "user_id", req.UserID, "role_id", roleID)
		return fmt.Errorf("failed to revoke role from user: %w", err)
	}

	s.logger.Info("Role revoked from user successfully", "user_id", req.UserID, "role_id", roleID, "tenant_id", req.TenantID)
	return nil
}

// GetUserRoles retrieves roles for a user in a specific tenant
func (s *roleService) GetUserRoles(ctx context.Context, userID, tenantID uuid.UUID) ([]*dto.UserRoleResponse, error) {
	ctx, span := tracer.Start(ctx, "RoleService.GetUserRoles")
	defer span.End()

	span.SetAttributes(
		attribute.String("user.id", userID.String()),
		attribute.String("tenant.id", tenantID.String()),
	)

	userRoles, err := s.userRoleRepo.GetUserRoles(ctx, userID, tenantID)
	if err != nil {
		s.logger.Error("Failed to get user roles", "error", err, "user_id", userID, "tenant_id", tenantID)
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}

	return dto.UserRolesToResponse(userRoles), nil
}

// GetUserRolesByUser retrieves all roles for a user across all tenants
func (s *roleService) GetUserRolesByUser(ctx context.Context, userID uuid.UUID) ([]*dto.UserRoleResponse, error) {
	ctx, span := tracer.Start(ctx, "RoleService.GetUserRolesByUser")
	defer span.End()

	span.SetAttributes(attribute.String("user.id", userID.String()))

	userRoles, err := s.userRoleRepo.GetUserRolesByUser(ctx, userID)
	if err != nil {
		s.logger.Error("Failed to get user roles by user", "error", err, "user_id", userID)
		return nil, fmt.Errorf("failed to get user roles by user: %w", err)
	}

	return dto.UserRolesToResponse(userRoles), nil
}

// GetRoleUsers retrieves users who have a specific role
func (s *roleService) GetRoleUsers(ctx context.Context, roleID uuid.UUID) ([]*dto.UserRoleResponse, error) {
	ctx, span := tracer.Start(ctx, "RoleService.GetRoleUsers")
	defer span.End()

	span.SetAttributes(attribute.String("role.id", roleID.String()))

	userRoles, err := s.userRoleRepo.GetRoleUsers(ctx, roleID)
	if err != nil {
		s.logger.Error("Failed to get role users", "error", err, "role_id", roleID)
		return nil, fmt.Errorf("failed to get role users: %w", err)
	}

	return dto.UserRolesToResponse(userRoles), nil
}

// ValidateRoleSlug validates if a role slug is valid and available
func (s *roleService) ValidateRoleSlug(ctx context.Context, slug string, tenantID *uuid.UUID) error {
	ctx, span := tracer.Start(ctx, "RoleService.ValidateRoleSlug")
	defer span.End()

	span.SetAttributes(attribute.String("role.slug", slug))

	if slug == "" {
		return fmt.Errorf("role slug cannot be empty")
	}

	// Check if slug already exists
	existingRole, err := s.roleRepo.GetBySlug(ctx, slug, tenantID)
	if err != nil {
		return fmt.Errorf("failed to check role slug: %w", err)
	}

	if existingRole != nil {
		return fmt.Errorf("role slug already exists")
	}

	return nil
}

// ValidateRoleName validates if a role name is valid and available
func (s *roleService) ValidateRoleName(ctx context.Context, name string, tenantID *uuid.UUID) error {
	ctx, span := tracer.Start(ctx, "RoleService.ValidateRoleName")
	defer span.End()

	span.SetAttributes(attribute.String("role.name", name))

	if name == "" {
		return fmt.Errorf("role name cannot be empty")
	}

	// Check if name already exists
	existingRole, err := s.roleRepo.GetByName(ctx, name, tenantID)
	if err != nil {
		return fmt.Errorf("failed to check role name: %w", err)
	}

	if existingRole != nil {
		return fmt.Errorf("role name already exists")
	}

	return nil
}

// HasRole checks if a user has a specific role
func (s *roleService) HasRole(ctx context.Context, userID, roleID, tenantID uuid.UUID) (bool, error) {
	ctx, span := tracer.Start(ctx, "RoleService.HasRole")
	defer span.End()

	span.SetAttributes(
		attribute.String("user.id", userID.String()),
		attribute.String("role.id", roleID.String()),
		attribute.String("tenant.id", tenantID.String()),
	)

	return s.userRoleRepo.HasRole(ctx, userID, roleID, tenantID)
}

// HasAnyRole checks if a user has any of the specified roles
func (s *roleService) HasAnyRole(ctx context.Context, userID uuid.UUID, roleIDs []uuid.UUID, tenantID uuid.UUID) (bool, error) {
	ctx, span := tracer.Start(ctx, "RoleService.HasAnyRole")
	defer span.End()

	span.SetAttributes(
		attribute.String("user.id", userID.String()),
		attribute.Int("roles.count", len(roleIDs)),
		attribute.String("tenant.id", tenantID.String()),
	)

	return s.userRoleRepo.HasAnyRole(ctx, userID, roleIDs, tenantID)
}

// GetUserPermissions retrieves all permissions for a user through their roles
func (s *roleService) GetUserPermissions(ctx context.Context, userID, tenantID uuid.UUID) ([]*permissionDto.PermissionResponse, error) {
	ctx, span := tracer.Start(ctx, "RoleService.GetUserPermissions")
	defer span.End()

	span.SetAttributes(
		attribute.String("user.id", userID.String()),
		attribute.String("tenant.id", tenantID.String()),
	)

	permissions, err := s.userRoleRepo.GetUserPermissions(ctx, userID, tenantID)
	if err != nil {
		s.logger.Error("Failed to get user permissions", "error", err, "user_id", userID, "tenant_id", tenantID)
		return nil, fmt.Errorf("failed to get user permissions: %w", err)
	}

	return permissionDto.PermissionsToResponse(permissions), nil
}

// BulkCreateRoles creates multiple roles in bulk
func (s *roleService) BulkCreateRoles(ctx context.Context, req *dto.BulkRoleRequest, tenantID *uuid.UUID, createdBy uuid.UUID) (*dto.BulkRoleResponse, error) {
	ctx, span := tracer.Start(ctx, "RoleService.BulkCreateRoles")
	defer span.End()

	span.SetAttributes(attribute.Int("roles.count", len(req.Roles)))

	var successCount, failureCount int
	var errors []string
	var roles []*dto.RoleResponse

	for _, roleReq := range req.Roles {
		role, err := s.CreateRole(ctx, roleReq, tenantID, createdBy)
		if err != nil {
			failureCount++
			errors = append(errors, fmt.Sprintf("Role '%s': %s", roleReq.Name, err.Error()))
		} else {
			successCount++
			roles = append(roles, role)
		}
	}

	return &dto.BulkRoleResponse{
		SuccessCount: successCount,
		FailureCount: failureCount,
		Errors:       errors,
		Roles:        roles,
	}, nil
}

// BulkDeleteRoles deletes multiple roles in bulk
func (s *roleService) BulkDeleteRoles(ctx context.Context, req *dto.BulkRoleRequest) (*dto.BulkRoleResponse, error) {
	ctx, span := tracer.Start(ctx, "RoleService.BulkDeleteRoles")
	defer span.End()

	span.SetAttributes(attribute.Int("roles.count", len(req.RoleIDs)))

	var successCount, failureCount int
	var errors []string

	for _, roleID := range req.RoleIDs {
		if err := s.DeleteRole(ctx, roleID); err != nil {
			failureCount++
			errors = append(errors, fmt.Sprintf("Role '%s': %s", roleID.String(), err.Error()))
		} else {
			successCount++
		}
	}

	return &dto.BulkRoleResponse{
		SuccessCount: successCount,
		FailureCount: failureCount,
		Errors:       errors,
	}, nil
}

// BulkAssignRoles assigns roles to users in bulk
func (s *roleService) BulkAssignRoles(ctx context.Context, req *dto.BulkRoleRequest, assignedBy uuid.UUID) (*dto.BulkRoleResponse, error) {
	ctx, span := tracer.Start(ctx, "RoleService.BulkAssignRoles")
	defer span.End()

	span.SetAttributes(attribute.Int("assignments.count", len(req.Assignments)))

	var successCount, failureCount int
	var errors []string

	for _, assignment := range req.Assignments {
		_, err := s.AssignRoleToUser(ctx, assignment.RoleID, &dto.AssignRoleRequest{
			UserID:   assignment.UserID,
			TenantID: assignment.TenantID,
		}, assignedBy)
		if err != nil {
			failureCount++
			errors = append(errors, fmt.Sprintf("User '%s' Role '%s': %s", assignment.UserID.String(), assignment.RoleID.String(), err.Error()))
		} else {
			successCount++
		}
	}

	return &dto.BulkRoleResponse{
		SuccessCount: successCount,
		FailureCount: failureCount,
		Errors:       errors,
	}, nil
}

// BulkRevokeRoles revokes roles from users in bulk
func (s *roleService) BulkRevokeRoles(ctx context.Context, req *dto.BulkRoleRequest) (*dto.BulkRoleResponse, error) {
	ctx, span := tracer.Start(ctx, "RoleService.BulkRevokeRoles")
	defer span.End()

	span.SetAttributes(attribute.Int("revocations.count", len(req.Assignments)))

	var successCount, failureCount int
	var errors []string

	for _, assignment := range req.Assignments {
		err := s.RevokeRoleFromUser(ctx, assignment.RoleID, &dto.RevokeRoleRequest{
			UserID:   assignment.UserID,
			TenantID: assignment.TenantID,
		})
		if err != nil {
			failureCount++
			errors = append(errors, fmt.Sprintf("User '%s' Role '%s': %s", assignment.UserID.String(), assignment.RoleID.String(), err.Error()))
		} else {
			successCount++
		}
	}

	return &dto.BulkRoleResponse{
		SuccessCount: successCount,
		FailureCount: failureCount,
		Errors:       errors,
	}, nil
}

// GetRoleStats retrieves role statistics
func (s *roleService) GetRoleStats(ctx context.Context, req *dto.RoleStatsRequest) (*dto.RoleStatsResponse, error) {
	ctx, span := tracer.Start(ctx, "RoleService.GetRoleStats")
	defer span.End()

	stats, err := s.roleRepo.GetRoleStats(ctx, req)
	if err != nil {
		s.logger.Error("Failed to get role stats", "error", err)
		return nil, fmt.Errorf("failed to get role stats: %w", err)
	}

	return stats, nil
}

// GetTopRolesByUsage retrieves top roles by usage
func (s *roleService) GetTopRolesByUsage(ctx context.Context, limit int, tenantID *uuid.UUID) ([]*dto.RoleUsageResponse, error) {
	ctx, span := tracer.Start(ctx, "RoleService.GetTopRolesByUsage")
	defer span.End()

	span.SetAttributes(attribute.Int("limit", limit))

	usage, err := s.roleRepo.GetTopRolesByUsage(ctx, limit, tenantID)
	if err != nil {
		s.logger.Error("Failed to get top roles by usage", "error", err)
		return nil, fmt.Errorf("failed to get top roles by usage: %w", err)
	}

	return usage, nil
}

// InitializeDefaultRoles creates default roles for a tenant
func (s *roleService) InitializeDefaultRoles(ctx context.Context, tenantID *uuid.UUID, createdBy uuid.UUID) error {
	ctx, span := tracer.Start(ctx, "RoleService.InitializeDefaultRoles")
	defer span.End()

	s.logger.Info("Initializing default roles", "tenant_id", tenantID)

	defaultRoles := getDefaultRoles()

	for _, roleData := range defaultRoles {
		// Check if role already exists
		existingRole, err := s.roleRepo.GetBySlug(ctx, roleData.Slug, tenantID)
		if err != nil {
			s.logger.Error("Failed to check existing role", "error", err, "slug", roleData.Slug)
			continue
		}

		if existingRole != nil {
			s.logger.Info("Default role already exists", "slug", roleData.Slug)
			continue
		}

		// Create role
		role := &domain.Role{
			ID:          uuid.New(),
			TenantID:    tenantID,
			Name:        roleData.Name,
			Slug:        roleData.Slug,
			Description: &roleData.Description,
			IsSystem:    true,
			IsGlobal:    roleData.IsGlobal,
			IsDefault:   roleData.IsDefault,
			Priority:    roleData.Priority,
			Metadata:    make(domain.JSONMap),
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
			CreatedBy:   createdBy,
		}

		if err := s.roleRepo.Create(ctx, role); err != nil {
			s.logger.Error("Failed to create default role", "error", err, "role_name", role.Name)
			continue
		}

		s.logger.Info("Default role created", "role_id", role.ID, "role_name", role.Name)
	}

	return nil
}

// AssignDefaultRolesToUser assigns default roles to a user
func (s *roleService) AssignDefaultRolesToUser(ctx context.Context, userID, tenantID uuid.UUID, assignedBy uuid.UUID) error {
	ctx, span := tracer.Start(ctx, "RoleService.AssignDefaultRolesToUser")
	defer span.End()

	span.SetAttributes(
		attribute.String("user.id", userID.String()),
		attribute.String("tenant.id", tenantID.String()),
	)

	s.logger.Info("Assigning default roles to user", "user_id", userID, "tenant_id", tenantID)

	// Get default roles
	defaultRolesResp, err := s.GetDefaultRoles(ctx, &tenantID)
	if err != nil {
		s.logger.Error("Failed to get default roles", "error", err, "tenant_id", tenantID)
		return fmt.Errorf("failed to get default roles: %w", err)
	}

	// Assign each default role to the user
	allDefaultRoles := append(defaultRolesResp.TenantRoles, defaultRolesResp.GlobalRoles...)
	for _, role := range allDefaultRoles {
		// Check if user already has the role
		hasRole, err := s.HasRole(ctx, userID, role.ID, tenantID)
		if err != nil {
			s.logger.Error("Failed to check if user has role", "error", err, "user_id", userID, "role_id", role.ID)
			continue
		}

		if hasRole {
			s.logger.Info("User already has default role", "user_id", userID, "role_id", role.ID)
			continue
		}

		// Assign role to user
		userRole := &domain.UserRole{
			ID:        uuid.New(),
			UserID:    userID,
			RoleID:    role.ID,
			TenantID:  tenantID,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
			CreatedBy: assignedBy,
		}

		if err := s.userRoleRepo.AssignRole(ctx, userRole); err != nil {
			s.logger.Error("Failed to assign default role to user", "error", err, "user_id", userID, "role_id", role.ID)
			continue
		}

		s.logger.Info("Default role assigned to user", "user_id", userID, "role_id", role.ID, "role_name", role.Name)
	}

	return nil
}

// getDefaultRoles returns the default system roles to be created
func getDefaultRoles() []struct {
	Name        string
	Slug        string
	Description string
	IsGlobal    bool
	IsDefault   bool
	Priority    int
} {
	return []struct {
		Name        string
		Slug        string
		Description string
		IsGlobal    bool
		IsDefault   bool
		Priority    int
	}{
		{
			Name:        "Super Admin",
			Slug:        "super-admin",
			Description: "Full system access with all permissions",
			IsGlobal:    true,
			IsDefault:   false,
			Priority:    1000,
		},
		{
			Name:        "Admin",
			Slug:        "admin",
			Description: "Administrative access to tenant resources",
			IsGlobal:    false,
			IsDefault:   false,
			Priority:    900,
		},
		{
			Name:        "Manager",
			Slug:        "manager",
			Description: "Management access to tenant resources",
			IsGlobal:    false,
			IsDefault:   false,
			Priority:    800,
		},
		{
			Name:        "User",
			Slug:        "user",
			Description: "Standard user access",
			IsGlobal:    false,
			IsDefault:   true,
			Priority:    100,
		},
		{
			Name:        "Guest",
			Slug:        "guest",
			Description: "Limited guest access",
			IsGlobal:    false,
			IsDefault:   false,
			Priority:    50,
		},
	}
}
