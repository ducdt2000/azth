package service

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/ducdt2000/azth/backend/internal/constants"
	"github.com/ducdt2000/azth/backend/internal/domain"
	"github.com/ducdt2000/azth/backend/internal/modules/permission/dto"
	"github.com/ducdt2000/azth/backend/internal/modules/permission/repository"
	"github.com/google/uuid"
)

// permissionService implements PermissionService interface
type permissionService struct {
	permissionRepo repository.PermissionRepository
}

// NewPermissionService creates a new permission service
func NewPermissionService(permissionRepo repository.PermissionRepository) PermissionService {
	return &permissionService{
		permissionRepo: permissionRepo,
	}
}

// CreatePermission creates a new permission with validation and business rules
func (s *permissionService) CreatePermission(ctx context.Context, req *dto.PermissionRequest) (*dto.PermissionResponse, error) {
	// Validate permission code
	if err := s.ValidatePermissionCode(ctx, req.Code); err != nil {
		return nil, err
	}

	// Validate module/resource/action combination
	if err := s.ValidateModuleResourceAction(ctx, req.Module, req.Resource, req.Action); err != nil {
		return nil, err
	}

	// Create permission domain object
	permission := &domain.Permission{
		ID:          uuid.New(),
		Name:        req.Name,
		Code:        req.Code,
		Description: req.Description,
		Module:      req.Module,
		Resource:    req.Resource,
		Action:      req.Action,
		IsSystem:    false, // User-created permissions are not system permissions
		IsDefault:   req.IsDefault,
		Metadata:    req.Metadata,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	// Create permission in repository
	if err := s.permissionRepo.Create(ctx, permission); err != nil {
		return nil, fmt.Errorf("failed to create permission: %w", err)
	}

	return dto.PermissionToResponse(permission), nil
}

// GetPermission retrieves a permission by ID
func (s *permissionService) GetPermission(ctx context.Context, id uuid.UUID) (*dto.PermissionResponse, error) {
	permission, err := s.permissionRepo.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get permission: %w", err)
	}

	if permission == nil {
		return nil, fmt.Errorf("permission not found")
	}

	return dto.PermissionToResponse(permission), nil
}

// GetPermissionByCode retrieves a permission by code
func (s *permissionService) GetPermissionByCode(ctx context.Context, code string) (*dto.PermissionResponse, error) {
	permission, err := s.permissionRepo.GetByCode(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("failed to get permission by code: %w", err)
	}

	if permission == nil {
		return nil, fmt.Errorf("permission not found")
	}

	return dto.PermissionToResponse(permission), nil
}

// UpdatePermission updates an existing permission with validation
func (s *permissionService) UpdatePermission(ctx context.Context, id uuid.UUID, req *dto.UpdatePermissionRequest) (*dto.PermissionResponse, error) {
	// Get existing permission
	permission, err := s.permissionRepo.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get permission: %w", err)
	}

	if permission == nil {
		return nil, fmt.Errorf("permission not found")
	}

	// System permissions cannot be updated
	if permission.IsSystem {
		return nil, fmt.Errorf("system permissions cannot be updated")
	}

	// Update fields
	if req.Name != nil {
		permission.Name = *req.Name
	}
	if req.Description != nil {
		permission.Description = req.Description
	}
	if req.Module != nil {
		permission.Module = *req.Module
	}
	if req.Resource != nil {
		permission.Resource = *req.Resource
	}
	if req.Action != nil {
		permission.Action = *req.Action
	}
	if req.IsDefault != nil {
		permission.IsDefault = *req.IsDefault
	}
	if req.Metadata != nil {
		permission.Metadata = req.Metadata
	}

	permission.UpdatedAt = time.Now()

	// Update permission in repository
	if err := s.permissionRepo.Update(ctx, permission); err != nil {
		return nil, fmt.Errorf("failed to update permission: %w", err)
	}

	return dto.PermissionToResponse(permission), nil
}

// DeletePermission soft deletes a permission
func (s *permissionService) DeletePermission(ctx context.Context, id uuid.UUID) error {
	// Get existing permission
	permission, err := s.permissionRepo.GetByID(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to get permission: %w", err)
	}

	if permission == nil {
		return fmt.Errorf("permission not found")
	}

	// System permissions cannot be deleted
	if permission.IsSystem {
		return fmt.Errorf("system permissions cannot be deleted")
	}

	// Delete permission
	if err := s.permissionRepo.Delete(ctx, id); err != nil {
		return fmt.Errorf("failed to delete permission: %w", err)
	}

	return nil
}

// ListPermissions retrieves permissions with filtering and pagination
func (s *permissionService) ListPermissions(ctx context.Context, req *dto.PermissionListRequest) (*dto.PermissionListResponse, error) {
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

	// Get permissions from repository
	permissions, total, err := s.permissionRepo.List(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to list permissions: %w", err)
	}

	// Calculate total pages
	totalPages := int(math.Ceil(float64(total) / float64(req.Limit)))

	return &dto.PermissionListResponse{
		Permissions: dto.PermissionsToResponse(permissions),
		Total:       total,
		Page:        req.Page,
		Limit:       req.Limit,
		TotalPages:  totalPages,
	}, nil
}

// GetPermissionsByModule retrieves permissions by module
func (s *permissionService) GetPermissionsByModule(ctx context.Context, module string) ([]*dto.PermissionResponse, error) {
	permissions, err := s.permissionRepo.GetByModule(ctx, module)
	if err != nil {
		return nil, fmt.Errorf("failed to get permissions by module: %w", err)
	}

	return dto.PermissionsToResponse(permissions), nil
}

// GetPermissionsByResource retrieves permissions by module and resource
func (s *permissionService) GetPermissionsByResource(ctx context.Context, module, resource string) ([]*dto.PermissionResponse, error) {
	permissions, err := s.permissionRepo.GetByResource(ctx, module, resource)
	if err != nil {
		return nil, fmt.Errorf("failed to get permissions by resource: %w", err)
	}

	return dto.PermissionsToResponse(permissions), nil
}

// GetPermissionByAction retrieves permission by module, resource, and action
func (s *permissionService) GetPermissionByAction(ctx context.Context, module, resource, action string) (*dto.PermissionResponse, error) {
	permission, err := s.permissionRepo.GetByAction(ctx, module, resource, action)
	if err != nil {
		return nil, fmt.Errorf("failed to get permission by action: %w", err)
	}

	if permission == nil {
		return nil, fmt.Errorf("permission not found")
	}

	return dto.PermissionToResponse(permission), nil
}

// GetDefaultPermissions retrieves all default permissions
func (s *permissionService) GetDefaultPermissions(ctx context.Context) ([]*dto.PermissionResponse, error) {
	permissions, err := s.permissionRepo.GetDefaultPermissions(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get default permissions: %w", err)
	}

	return dto.PermissionsToResponse(permissions), nil
}

// GetSystemPermissions retrieves all system permissions
func (s *permissionService) GetSystemPermissions(ctx context.Context) ([]*dto.PermissionResponse, error) {
	permissions, err := s.permissionRepo.GetSystemPermissions(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get system permissions: %w", err)
	}

	return dto.PermissionsToResponse(permissions), nil
}

// GetPermissionModules retrieves available modules and their resources
func (s *permissionService) GetPermissionModules(ctx context.Context) (*dto.PermissionModulesResponse, error) {
	modulesData, err := s.permissionRepo.GetModules(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get permission modules: %w", err)
	}

	var modules []dto.PermissionModuleInfo
	for moduleName, resources := range modulesData {
		module := dto.PermissionModuleInfo{
			Name:      moduleName,
			Resources: make([]dto.PermissionResourceInfo, 0, len(resources)),
		}

		for resourceName, actions := range resources {
			resource := dto.PermissionResourceInfo{
				Name:    resourceName,
				Actions: actions,
			}
			module.Resources = append(module.Resources, resource)
		}

		modules = append(modules, module)
	}

	return &dto.PermissionModulesResponse{
		Modules: modules,
	}, nil
}

// GetPermissionsGrouped retrieves permissions grouped by module and resource
func (s *permissionService) GetPermissionsGrouped(ctx context.Context) ([]*dto.PermissionGroupResponse, error) {
	req := &dto.PermissionListRequest{
		Page:  1,
		Limit: 1000, // Get all permissions
	}

	permissions, _, err := s.permissionRepo.List(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to get permissions: %w", err)
	}

	// Group permissions by module and resource
	groups := make(map[string]*dto.PermissionGroupResponse)

	for _, permission := range permissions {
		key := fmt.Sprintf("%s:%s", permission.Module, permission.Resource)

		if groups[key] == nil {
			groups[key] = &dto.PermissionGroupResponse{
				Module:      permission.Module,
				Resource:    permission.Resource,
				Permissions: []*dto.PermissionResponse{},
			}
		}

		groups[key].Permissions = append(groups[key].Permissions, dto.PermissionToResponse(permission))
	}

	// Convert map to slice
	result := make([]*dto.PermissionGroupResponse, 0, len(groups))
	for _, group := range groups {
		result = append(result, group)
	}

	return result, nil
}

// BulkCreatePermissions creates multiple permissions in bulk
func (s *permissionService) BulkCreatePermissions(ctx context.Context, req *dto.BulkPermissionRequest) (*dto.BulkPermissionResponse, error) {
	if req.Action != "create" {
		return nil, fmt.Errorf("invalid action for bulk create: %s", req.Action)
	}

	if len(req.Permissions) == 0 {
		return nil, fmt.Errorf("no permissions provided for bulk create")
	}

	response := &dto.BulkPermissionResponse{
		Success: []uuid.UUID{},
		Failed:  []dto.BulkPermissionError{},
		Total:   len(req.Permissions),
	}

	var permissionsToCreate []*domain.Permission

	// Validate all permissions first
	for i, permReq := range req.Permissions {
		// Validate permission code
		if err := s.ValidatePermissionCode(ctx, permReq.Code); err != nil {
			response.Failed = append(response.Failed, dto.BulkPermissionError{
				Index: &i,
				Error: fmt.Sprintf("invalid permission code: %v", err),
			})
			continue
		}

		// Create permission domain object
		permission := &domain.Permission{
			ID:          uuid.New(),
			Name:        permReq.Name,
			Code:        permReq.Code,
			Description: permReq.Description,
			Module:      permReq.Module,
			Resource:    permReq.Resource,
			Action:      permReq.Action,
			IsSystem:    false,
			IsDefault:   permReq.IsDefault,
			Metadata:    permReq.Metadata,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}

		permissionsToCreate = append(permissionsToCreate, permission)
		response.Success = append(response.Success, permission.ID)
	}

	// Bulk create valid permissions
	if len(permissionsToCreate) > 0 {
		if err := s.permissionRepo.BulkCreate(ctx, permissionsToCreate); err != nil {
			return nil, fmt.Errorf("failed to bulk create permissions: %w", err)
		}
	}

	return response, nil
}

// BulkDeletePermissions deletes multiple permissions in bulk
func (s *permissionService) BulkDeletePermissions(ctx context.Context, req *dto.BulkPermissionRequest) (*dto.BulkPermissionResponse, error) {
	if req.Action != "delete" {
		return nil, fmt.Errorf("invalid action for bulk delete: %s", req.Action)
	}

	if len(req.PermissionIDs) == 0 {
		return nil, fmt.Errorf("no permission IDs provided for bulk delete")
	}

	response := &dto.BulkPermissionResponse{
		Success: []uuid.UUID{},
		Failed:  []dto.BulkPermissionError{},
		Total:   len(req.PermissionIDs),
	}

	// Get permissions to validate they can be deleted
	permissions, err := s.permissionRepo.GetPermissionsByIDs(ctx, req.PermissionIDs)
	if err != nil {
		return nil, fmt.Errorf("failed to get permissions for bulk delete: %w", err)
	}

	var validIDs []uuid.UUID
	permissionMap := make(map[uuid.UUID]*domain.Permission)

	for _, permission := range permissions {
		permissionMap[permission.ID] = permission
	}

	for _, id := range req.PermissionIDs {
		permission, exists := permissionMap[id]
		if !exists {
			response.Failed = append(response.Failed, dto.BulkPermissionError{
				PermissionID: &id,
				Error:        "permission not found",
			})
			continue
		}

		if permission.IsSystem {
			response.Failed = append(response.Failed, dto.BulkPermissionError{
				PermissionID: &id,
				Error:        "system permissions cannot be deleted",
			})
			continue
		}

		validIDs = append(validIDs, id)
		response.Success = append(response.Success, id)
	}

	// Bulk delete valid permissions
	if len(validIDs) > 0 {
		if err := s.permissionRepo.BulkDelete(ctx, validIDs); err != nil {
			return nil, fmt.Errorf("failed to bulk delete permissions: %w", err)
		}
	}

	return response, nil
}

// InitializeDefaultPermissions creates default system permissions if they don't exist
func (s *permissionService) InitializeDefaultPermissions(ctx context.Context) error {
	defaultPermissions := getDefaultSystemPermissions()

	for _, permData := range defaultPermissions {
		// Check if permission already exists
		exists, err := s.permissionRepo.ExistsByCode(ctx, permData.Code)
		if err != nil {
			return fmt.Errorf("failed to check if permission exists: %w", err)
		}

		if !exists {
			permission := &domain.Permission{
				ID:          uuid.New(),
				Name:        permData.Name,
				Code:        permData.Code,
				Description: permData.Description,
				Module:      permData.Module,
				Resource:    permData.Resource,
				Action:      permData.Action,
				IsSystem:    true,
				IsDefault:   permData.IsDefault,
				Metadata:    make(map[string]interface{}),
				CreatedAt:   time.Now(),
				UpdatedAt:   time.Now(),
			}

			if err := s.permissionRepo.Create(ctx, permission); err != nil {
				return fmt.Errorf("failed to create default permission %s: %w", permData.Code, err)
			}
		}
	}

	return nil
}

// ValidatePermissionCode validates if a permission code is valid and available
func (s *permissionService) ValidatePermissionCode(ctx context.Context, code string) error {
	if code == "" {
		return fmt.Errorf("permission code cannot be empty")
	}

	if len(code) < 3 {
		return fmt.Errorf("permission code must be at least 3 characters long")
	}

	if len(code) > 100 {
		return fmt.Errorf("permission code must be at most 100 characters long")
	}

	// Check if code already exists
	exists, err := s.permissionRepo.ExistsByCode(ctx, code)
	if err != nil {
		return fmt.Errorf("failed to check if permission code exists: %w", err)
	}

	if exists {
		return fmt.Errorf("permission code already exists")
	}

	return nil
}

// ValidateModuleResourceAction validates if the module/resource/action combination is valid
func (s *permissionService) ValidateModuleResourceAction(ctx context.Context, module, resource, action string) error {
	if module == "" || resource == "" || action == "" {
		return fmt.Errorf("module, resource, and action cannot be empty")
	}

	// Validate module format
	if !isValidIdentifier(module) {
		return fmt.Errorf("invalid module format")
	}

	// Validate resource format
	if !isValidIdentifier(resource) {
		return fmt.Errorf("invalid resource format")
	}

	// Validate action format
	if !isValidIdentifier(action) {
		return fmt.Errorf("invalid action format")
	}

	// Check if combination already exists
	exists, err := s.permissionRepo.ExistsByModuleResourceAction(ctx, module, resource, action)
	if err != nil {
		return fmt.Errorf("failed to check if module/resource/action combination exists: %w", err)
	}

	if exists {
		return fmt.Errorf("permission for module/resource/action combination already exists")
	}

	return nil
}

// isValidIdentifier checks if a string is a valid identifier (alphanumeric + underscore)
func isValidIdentifier(s string) bool {
	if len(s) == 0 {
		return false
	}

	for _, r := range s {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_') {
			return false
		}
	}

	return true
}

// getDefaultSystemPermissions returns the default system permissions
func getDefaultSystemPermissions() []struct {
	Name        string
	Code        string
	Description *string
	Module      string
	Resource    string
	Action      string
	IsDefault   bool
} {
	desc := func(s string) *string { return &s }

	return []struct {
		Name        string
		Code        string
		Description *string
		Module      string
		Resource    string
		Action      string
		IsDefault   bool
	}{
		// User permissions
		{"Read Users", constants.PermUserRead, desc("View user information and list users"), "user", "user", "read", true},
		{"Create Users", constants.PermUserCreate, desc("Create new users"), "user", "user", "create", false},
		{"Update Users", constants.PermUserUpdate, desc("Update user information"), "user", "user", "update", false},
		{"Delete Users", constants.PermUserDelete, desc("Delete or deactivate users"), "user", "user", "delete", false},
		{"User Stats", constants.PermUserStats, desc("View user statistics"), "user", "user", "stats", false},
		{"Bulk Update Users", constants.PermUserBulkUpdate, desc("Bulk update users"), "user", "user", "bulk_update", false},
		{"Update User Password", constants.PermUserUpdatePassword, desc("Change user passwords"), "user", "user", "update_password", false},
		{"Assign User Role", constants.PermUserAssignRole, desc("Assign roles to users"), "user", "user", "assign_role", false},
		{"Revoke User Role", constants.PermUserRevokeRole, desc("Revoke roles from users"), "user", "user", "revoke_role", false},

		// Tenant permissions
		{"Read Tenants", constants.PermTenantRead, desc("View tenant information and settings"), "tenant", "tenant", "read", true},
		{"Create Tenants", constants.PermTenantCreate, desc("Create new tenants"), "tenant", "tenant", "create", false},
		{"Update Tenants", constants.PermTenantUpdate, desc("Update tenant information"), "tenant", "tenant", "update", false},
		{"Delete Tenants", constants.PermTenantDelete, desc("Delete or suspend tenants"), "tenant", "tenant", "delete", false},
		{"Activate Tenants", constants.PermTenantActivate, desc("Activate tenants"), "tenant", "tenant", "activate", false},
		{"Deactivate Tenants", constants.PermTenantDeactivate, desc("Deactivate tenants"), "tenant", "tenant", "deactivate", false},
		{"Suspend Tenants", constants.PermTenantSuspend, desc("Suspend tenants"), "tenant", "tenant", "suspend", false},

		// Role permissions
		{"Read Roles", constants.PermRoleRead, desc("View roles and role assignments"), "role", "role", "read", true},
		{"Create Roles", constants.PermRoleCreate, desc("Create new roles"), "role", "role", "create", false},
		{"Update Roles", constants.PermRoleUpdate, desc("Update role information"), "role", "role", "update", false},
		{"Delete Roles", constants.PermRoleDelete, desc("Delete roles"), "role", "role", "delete", false},
		{"Role Stats", constants.PermRoleStats, desc("View role statistics"), "role", "role", "stats", false},
		{"Bulk Create Roles", constants.PermRoleBulkCreate, desc("Bulk create roles"), "role", "role", "bulk_create", false},
		{"Bulk Delete Roles", constants.PermRoleBulkDelete, desc("Bulk delete roles"), "role", "role", "bulk_delete", false},

		// Permission permissions
		{"Read Permissions", constants.PermPermissionRead, desc("View permissions"), "permission", "permission", "read", true},
		{"Create Permissions", constants.PermPermissionCreate, desc("Create new permissions"), "permission", "permission", "create", false},
		{"Update Permissions", constants.PermPermissionUpdate, desc("Update permission information"), "permission", "permission", "update", false},
		{"Delete Permissions", constants.PermPermissionDelete, desc("Delete permissions"), "permission", "permission", "delete", false},
		{"Assign Permissions", constants.PermPermissionAssign, desc("Assign permissions to roles"), "permission", "permission", "assign", false},
		{"Revoke Permissions", constants.PermPermissionRevoke, desc("Revoke permissions from roles"), "permission", "permission", "revoke", false},
		{"Bulk Create Permissions", constants.PermPermissionBulkCreate, desc("Bulk create permissions"), "permission", "permission", "bulk_create", false},
		{"Bulk Delete Permissions", constants.PermPermissionBulkDelete, desc("Bulk delete permissions"), "permission", "permission", "bulk_delete", false},
		{"Validate Permissions", constants.PermPermissionValidate, desc("Validate permission codes and actions"), "permission", "permission", "validate", false},

		// OIDC permissions
		{"Read OIDC", constants.PermOIDCRead, desc("View OIDC clients and configurations"), "oidc", "client", "read", false},
		{"Write OIDC", constants.PermOIDCWrite, desc("Create and update OIDC clients"), "oidc", "client", "write", false},
		{"Delete OIDC", constants.PermOIDCDelete, desc("Delete OIDC clients"), "oidc", "client", "delete", false},
		{"Admin OIDC", constants.PermOIDCAdmin, desc("Full administrative access to OIDC management"), "oidc", "client", "admin", false},

		// Audit permissions
		{"Read Audit", constants.PermAuditRead, desc("View audit logs and system activities"), "audit", "log", "read", false},

		// System permissions
		{"System Admin", constants.PermSystemAdmin, desc("Full system administrative access"), "system", "admin", "admin", false},
	}
}
