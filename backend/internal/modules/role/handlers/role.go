package handlers

import (
	"net/http"
	"strconv"

	"github.com/ducdt2000/azth/backend/internal/modules/role/dto"
	"github.com/ducdt2000/azth/backend/internal/modules/role/service"
	"github.com/ducdt2000/azth/backend/pkg/logger"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

// tracer for OpenTelemetry tracing
var tracer = otel.Tracer("role-handler")

// RoleHandler handles HTTP requests for role operations
type RoleHandler struct {
	roleService service.RoleService
	logger      *logger.Logger
}

// NewRoleHandler creates a new role handler
func NewRoleHandler(roleService service.RoleService, logger *logger.Logger) *RoleHandler {
	return &RoleHandler{
		roleService: roleService,
		logger:      logger,
	}
}

// CreateRole handles POST /api/v1/roles
func (h *RoleHandler) CreateRole(c echo.Context) error {
	ctx, span := tracer.Start(c.Request().Context(), "RoleHandler.CreateRole")
	defer span.End()

	var req dto.RoleRequest
	if err := c.Bind(&req); err != nil {
		h.logger.Error("Failed to bind role request", "error", err)
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid request body",
		})
	}

	// Get tenant ID from query params (optional for global roles)
	var tenantID *uuid.UUID
	if tenantIDStr := c.QueryParam("tenant_id"); tenantIDStr != "" {
		if parsedTenantID, err := uuid.Parse(tenantIDStr); err == nil {
			tenantID = &parsedTenantID
		}
	}

	// TODO: Get created by from JWT token
	createdBy := uuid.New() // Placeholder

	span.SetAttributes(
		attribute.String("role.name", req.Name),
		attribute.String("role.slug", req.Slug),
		attribute.Bool("role.is_global", req.IsGlobal),
	)

	role, err := h.roleService.CreateRole(ctx, &req, tenantID, createdBy)
	if err != nil {
		h.logger.Error("Failed to create role", "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})
	}

	return c.JSON(http.StatusCreated, role)
}

// GetRole handles GET /api/v1/roles/:id
func (h *RoleHandler) GetRole(c echo.Context) error {
	ctx, span := tracer.Start(c.Request().Context(), "RoleHandler.GetRole")
	defer span.End()

	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid role ID",
		})
	}

	span.SetAttributes(attribute.String("role.id", id.String()))

	role, err := h.roleService.GetRole(ctx, id)
	if err != nil {
		h.logger.Error("Failed to get role", "error", err, "role_id", id)
		return c.JSON(http.StatusNotFound, map[string]string{
			"error": err.Error(),
		})
	}

	return c.JSON(http.StatusOK, role)
}

// GetRoleBySlug handles GET /api/v1/roles/slug/:slug
func (h *RoleHandler) GetRoleBySlug(c echo.Context) error {
	ctx, span := tracer.Start(c.Request().Context(), "RoleHandler.GetRoleBySlug")
	defer span.End()

	slug := c.Param("slug")

	// Get tenant ID from query params (optional for global roles)
	var tenantID *uuid.UUID
	if tenantIDStr := c.QueryParam("tenant_id"); tenantIDStr != "" {
		if parsedTenantID, err := uuid.Parse(tenantIDStr); err == nil {
			tenantID = &parsedTenantID
		}
	}

	span.SetAttributes(attribute.String("role.slug", slug))

	role, err := h.roleService.GetRoleBySlug(ctx, slug, tenantID)
	if err != nil {
		h.logger.Error("Failed to get role by slug", "error", err, "slug", slug)
		return c.JSON(http.StatusNotFound, map[string]string{
			"error": err.Error(),
		})
	}

	return c.JSON(http.StatusOK, role)
}

// UpdateRole handles PUT /api/v1/roles/:id
func (h *RoleHandler) UpdateRole(c echo.Context) error {
	ctx, span := tracer.Start(c.Request().Context(), "RoleHandler.UpdateRole")
	defer span.End()

	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid role ID",
		})
	}

	var req dto.UpdateRoleRequest
	if err := c.Bind(&req); err != nil {
		h.logger.Error("Failed to bind update role request", "error", err)
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid request body",
		})
	}

	// TODO: Get updated by from JWT token
	updatedBy := uuid.New() // Placeholder

	span.SetAttributes(attribute.String("role.id", id.String()))

	role, err := h.roleService.UpdateRole(ctx, id, &req, updatedBy)
	if err != nil {
		h.logger.Error("Failed to update role", "error", err, "role_id", id)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})
	}

	return c.JSON(http.StatusOK, role)
}

// DeleteRole handles DELETE /api/v1/roles/:id
func (h *RoleHandler) DeleteRole(c echo.Context) error {
	ctx, span := tracer.Start(c.Request().Context(), "RoleHandler.DeleteRole")
	defer span.End()

	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid role ID",
		})
	}

	span.SetAttributes(attribute.String("role.id", id.String()))

	if err := h.roleService.DeleteRole(ctx, id); err != nil {
		h.logger.Error("Failed to delete role", "error", err, "role_id", id)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})
	}

	return c.JSON(http.StatusOK, map[string]string{
		"message": "Role deleted successfully",
	})
}

// ListRoles handles GET /api/v1/roles
func (h *RoleHandler) ListRoles(c echo.Context) error {
	ctx, span := tracer.Start(c.Request().Context(), "RoleHandler.ListRoles")
	defer span.End()

	// Parse query parameters
	var req dto.RoleListRequest

	// Pagination
	if pageStr := c.QueryParam("page"); pageStr != "" {
		if page, err := strconv.Atoi(pageStr); err == nil {
			req.Page = page
		}
	}
	if limitStr := c.QueryParam("limit"); limitStr != "" {
		if limit, err := strconv.Atoi(limitStr); err == nil {
			req.Limit = limit
		}
	}

	// Filters
	req.Search = c.QueryParam("search")

	// Parse boolean query parameters
	if isGlobalStr := c.QueryParam("is_global"); isGlobalStr != "" {
		if isGlobal, err := strconv.ParseBool(isGlobalStr); err == nil {
			req.IsGlobal = &isGlobal
		}
	}

	if isSystemStr := c.QueryParam("is_system"); isSystemStr != "" {
		if isSystem, err := strconv.ParseBool(isSystemStr); err == nil {
			req.IsSystem = &isSystem
		}
	}

	if isDefaultStr := c.QueryParam("is_default"); isDefaultStr != "" {
		if isDefault, err := strconv.ParseBool(isDefaultStr); err == nil {
			req.IsDefault = &isDefault
		}
	}

	if tenantIDStr := c.QueryParam("tenant_id"); tenantIDStr != "" {
		if tenantID, err := uuid.Parse(tenantIDStr); err == nil {
			req.TenantID = &tenantID
		}
	}

	roles, err := h.roleService.ListRoles(ctx, &req)
	if err != nil {
		h.logger.Error("Failed to list roles", "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})
	}

	return c.JSON(http.StatusOK, roles)
}

// GetRolesByTenant handles GET /api/v1/tenants/:tenant_id/roles
func (h *RoleHandler) GetRolesByTenant(c echo.Context) error {
	ctx, span := tracer.Start(c.Request().Context(), "RoleHandler.GetRolesByTenant")
	defer span.End()

	tenantIDStr := c.Param("tenant_id")
	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid tenant ID",
		})
	}

	span.SetAttributes(attribute.String("tenant.id", tenantID.String()))

	roles, err := h.roleService.GetRolesByTenant(ctx, tenantID)
	if err != nil {
		h.logger.Error("Failed to get roles by tenant", "error", err, "tenant_id", tenantID)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})
	}

	return c.JSON(http.StatusOK, roles)
}

// GetGlobalRoles handles GET /api/v1/roles/global
func (h *RoleHandler) GetGlobalRoles(c echo.Context) error {
	ctx, span := tracer.Start(c.Request().Context(), "RoleHandler.GetGlobalRoles")
	defer span.End()

	roles, err := h.roleService.GetGlobalRoles(ctx)
	if err != nil {
		h.logger.Error("Failed to get global roles", "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})
	}

	return c.JSON(http.StatusOK, roles)
}

// GetSystemRoles handles GET /api/v1/roles/system
func (h *RoleHandler) GetSystemRoles(c echo.Context) error {
	ctx, span := tracer.Start(c.Request().Context(), "RoleHandler.GetSystemRoles")
	defer span.End()

	roles, err := h.roleService.GetSystemRoles(ctx)
	if err != nil {
		h.logger.Error("Failed to get system roles", "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})
	}

	return c.JSON(http.StatusOK, roles)
}

// GetDefaultRoles handles GET /api/v1/roles/default
func (h *RoleHandler) GetDefaultRoles(c echo.Context) error {
	ctx, span := tracer.Start(c.Request().Context(), "RoleHandler.GetDefaultRoles")
	defer span.End()

	// Get tenant ID from query params (optional)
	var tenantID *uuid.UUID
	if tenantIDStr := c.QueryParam("tenant_id"); tenantIDStr != "" {
		if parsedTenantID, err := uuid.Parse(tenantIDStr); err == nil {
			tenantID = &parsedTenantID
		}
	}

	roles, err := h.roleService.GetDefaultRoles(ctx, tenantID)
	if err != nil {
		h.logger.Error("Failed to get default roles", "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})
	}

	return c.JSON(http.StatusOK, roles)
}

// AssignPermissions handles POST /api/v1/roles/:id/permissions
func (h *RoleHandler) AssignPermissions(c echo.Context) error {
	ctx, span := tracer.Start(c.Request().Context(), "RoleHandler.AssignPermissions")
	defer span.End()

	idStr := c.Param("id")
	roleID, err := uuid.Parse(idStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid role ID",
		})
	}

	var req dto.RolePermissionRequest
	if err := c.Bind(&req); err != nil {
		h.logger.Error("Failed to bind role permission request", "error", err)
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid request body",
		})
	}

	// TODO: Get assigned by from JWT token
	assignedBy := uuid.New() // Placeholder

	span.SetAttributes(
		attribute.String("role.id", roleID.String()),
		attribute.Int("permissions.count", len(req.PermissionIDs)),
	)

	result, err := h.roleService.AssignPermissions(ctx, roleID, &req, assignedBy)
	if err != nil {
		h.logger.Error("Failed to assign permissions to role", "error", err, "role_id", roleID)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})
	}

	return c.JSON(http.StatusOK, result)
}

// RevokePermissions handles DELETE /api/v1/roles/:id/permissions
func (h *RoleHandler) RevokePermissions(c echo.Context) error {
	ctx, span := tracer.Start(c.Request().Context(), "RoleHandler.RevokePermissions")
	defer span.End()

	idStr := c.Param("id")
	roleID, err := uuid.Parse(idStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid role ID",
		})
	}

	var req dto.RolePermissionRequest
	if err := c.Bind(&req); err != nil {
		h.logger.Error("Failed to bind role permission request", "error", err)
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid request body",
		})
	}

	span.SetAttributes(
		attribute.String("role.id", roleID.String()),
		attribute.Int("permissions.count", len(req.PermissionIDs)),
	)

	if err := h.roleService.RevokePermissions(ctx, roleID, &req); err != nil {
		h.logger.Error("Failed to revoke permissions from role", "error", err, "role_id", roleID)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})
	}

	return c.JSON(http.StatusOK, map[string]string{
		"message": "Permissions revoked successfully",
	})
}

// ReplacePermissions handles PUT /api/v1/roles/:id/permissions
func (h *RoleHandler) ReplacePermissions(c echo.Context) error {
	ctx, span := tracer.Start(c.Request().Context(), "RoleHandler.ReplacePermissions")
	defer span.End()

	idStr := c.Param("id")
	roleID, err := uuid.Parse(idStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid role ID",
		})
	}

	var req dto.RolePermissionRequest
	if err := c.Bind(&req); err != nil {
		h.logger.Error("Failed to bind role permission request", "error", err)
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid request body",
		})
	}

	// TODO: Get assigned by from JWT token
	assignedBy := uuid.New() // Placeholder

	span.SetAttributes(
		attribute.String("role.id", roleID.String()),
		attribute.Int("permissions.count", len(req.PermissionIDs)),
	)

	result, err := h.roleService.ReplacePermissions(ctx, roleID, &req, assignedBy)
	if err != nil {
		h.logger.Error("Failed to replace permissions for role", "error", err, "role_id", roleID)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})
	}

	return c.JSON(http.StatusOK, result)
}

// GetRolePermissions handles GET /api/v1/roles/:id/permissions
func (h *RoleHandler) GetRolePermissions(c echo.Context) error {
	ctx, span := tracer.Start(c.Request().Context(), "RoleHandler.GetRolePermissions")
	defer span.End()

	idStr := c.Param("id")
	roleID, err := uuid.Parse(idStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid role ID",
		})
	}

	span.SetAttributes(attribute.String("role.id", roleID.String()))

	permissions, err := h.roleService.GetRolePermissions(ctx, roleID)
	if err != nil {
		h.logger.Error("Failed to get role permissions", "error", err, "role_id", roleID)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})
	}

	return c.JSON(http.StatusOK, permissions)
}

// AssignRoleToUser handles POST /api/v1/roles/:id/users
func (h *RoleHandler) AssignRoleToUser(c echo.Context) error {
	ctx, span := tracer.Start(c.Request().Context(), "RoleHandler.AssignRoleToUser")
	defer span.End()

	idStr := c.Param("id")
	roleID, err := uuid.Parse(idStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid role ID",
		})
	}

	var req dto.AssignRoleRequest
	if err := c.Bind(&req); err != nil {
		h.logger.Error("Failed to bind assign role request", "error", err)
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid request body",
		})
	}

	// TODO: Get assigned by from JWT token
	assignedBy := uuid.New() // Placeholder

	span.SetAttributes(
		attribute.String("role.id", roleID.String()),
		attribute.String("user.id", req.UserID.String()),
		attribute.String("tenant.id", req.TenantID.String()),
	)

	result, err := h.roleService.AssignRoleToUser(ctx, roleID, &req, assignedBy)
	if err != nil {
		h.logger.Error("Failed to assign role to user", "error", err, "role_id", roleID, "user_id", req.UserID)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})
	}

	return c.JSON(http.StatusOK, result)
}

// RevokeRoleFromUser handles DELETE /api/v1/roles/:id/users
func (h *RoleHandler) RevokeRoleFromUser(c echo.Context) error {
	ctx, span := tracer.Start(c.Request().Context(), "RoleHandler.RevokeRoleFromUser")
	defer span.End()

	idStr := c.Param("id")
	roleID, err := uuid.Parse(idStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid role ID",
		})
	}

	var req dto.RevokeRoleRequest
	if err := c.Bind(&req); err != nil {
		h.logger.Error("Failed to bind revoke role request", "error", err)
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid request body",
		})
	}

	span.SetAttributes(
		attribute.String("role.id", roleID.String()),
		attribute.String("user.id", req.UserID.String()),
		attribute.String("tenant.id", req.TenantID.String()),
	)

	if err := h.roleService.RevokeRoleFromUser(ctx, roleID, &req); err != nil {
		h.logger.Error("Failed to revoke role from user", "error", err, "role_id", roleID, "user_id", req.UserID)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})
	}

	return c.JSON(http.StatusOK, map[string]string{
		"message": "Role revoked from user successfully",
	})
}

// GetUserRoles handles GET /api/v1/users/:user_id/roles
func (h *RoleHandler) GetUserRoles(c echo.Context) error {
	ctx, span := tracer.Start(c.Request().Context(), "RoleHandler.GetUserRoles")
	defer span.End()

	userIDStr := c.Param("user_id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid user ID",
		})
	}

	tenantIDStr := c.QueryParam("tenant_id")
	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid or missing tenant ID",
		})
	}

	span.SetAttributes(
		attribute.String("user.id", userID.String()),
		attribute.String("tenant.id", tenantID.String()),
	)

	roles, err := h.roleService.GetUserRoles(ctx, userID, tenantID)
	if err != nil {
		h.logger.Error("Failed to get user roles", "error", err, "user_id", userID, "tenant_id", tenantID)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})
	}

	return c.JSON(http.StatusOK, roles)
}

// GetUserPermissions handles GET /api/v1/users/:user_id/permissions
func (h *RoleHandler) GetUserPermissions(c echo.Context) error {
	ctx, span := tracer.Start(c.Request().Context(), "RoleHandler.GetUserPermissions")
	defer span.End()

	userIDStr := c.Param("user_id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid user ID",
		})
	}

	tenantIDStr := c.QueryParam("tenant_id")
	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid or missing tenant ID",
		})
	}

	span.SetAttributes(
		attribute.String("user.id", userID.String()),
		attribute.String("tenant.id", tenantID.String()),
	)

	permissions, err := h.roleService.GetUserPermissions(ctx, userID, tenantID)
	if err != nil {
		h.logger.Error("Failed to get user permissions", "error", err, "user_id", userID, "tenant_id", tenantID)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})
	}

	return c.JSON(http.StatusOK, permissions)
}

// BulkCreateRoles handles POST /api/v1/roles/bulk
func (h *RoleHandler) BulkCreateRoles(c echo.Context) error {
	ctx, span := tracer.Start(c.Request().Context(), "RoleHandler.BulkCreateRoles")
	defer span.End()

	var req dto.BulkRoleRequest
	if err := c.Bind(&req); err != nil {
		h.logger.Error("Failed to bind bulk role request", "error", err)
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid request body",
		})
	}

	// Get tenant ID from query params (optional for global roles)
	var tenantID *uuid.UUID
	if tenantIDStr := c.QueryParam("tenant_id"); tenantIDStr != "" {
		if parsedTenantID, err := uuid.Parse(tenantIDStr); err == nil {
			tenantID = &parsedTenantID
		}
	}

	// TODO: Get created by from JWT token
	createdBy := uuid.New() // Placeholder

	span.SetAttributes(attribute.Int("roles.count", len(req.Roles)))

	result, err := h.roleService.BulkCreateRoles(ctx, &req, tenantID, createdBy)
	if err != nil {
		h.logger.Error("Failed to bulk create roles", "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})
	}

	return c.JSON(http.StatusCreated, result)
}

// BulkDeleteRoles handles DELETE /api/v1/roles/bulk
func (h *RoleHandler) BulkDeleteRoles(c echo.Context) error {
	ctx, span := tracer.Start(c.Request().Context(), "RoleHandler.BulkDeleteRoles")
	defer span.End()

	var req dto.BulkRoleRequest
	if err := c.Bind(&req); err != nil {
		h.logger.Error("Failed to bind bulk role request", "error", err)
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid request body",
		})
	}

	span.SetAttributes(attribute.Int("roles.count", len(req.RoleIDs)))

	result, err := h.roleService.BulkDeleteRoles(ctx, &req)
	if err != nil {
		h.logger.Error("Failed to bulk delete roles", "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})
	}

	return c.JSON(http.StatusOK, result)
}

// GetRoleStats handles GET /api/v1/roles/stats
func (h *RoleHandler) GetRoleStats(c echo.Context) error {
	ctx, span := tracer.Start(c.Request().Context(), "RoleHandler.GetRoleStats")
	defer span.End()

	var req dto.RoleStatsRequest

	// Get tenant ID from query params (optional)
	if tenantIDStr := c.QueryParam("tenant_id"); tenantIDStr != "" {
		if tenantID, err := uuid.Parse(tenantIDStr); err == nil {
			req.TenantID = &tenantID
		}
	}

	stats, err := h.roleService.GetRoleStats(ctx, &req)
	if err != nil {
		h.logger.Error("Failed to get role stats", "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})
	}

	return c.JSON(http.StatusOK, stats)
}

// InitializeDefaultRoles handles POST /api/v1/roles/initialize
func (h *RoleHandler) InitializeDefaultRoles(c echo.Context) error {
	ctx, span := tracer.Start(c.Request().Context(), "RoleHandler.InitializeDefaultRoles")
	defer span.End()

	// Get tenant ID from query params (optional for global roles)
	var tenantID *uuid.UUID
	if tenantIDStr := c.QueryParam("tenant_id"); tenantIDStr != "" {
		if parsedTenantID, err := uuid.Parse(tenantIDStr); err == nil {
			tenantID = &parsedTenantID
		}
	}

	// TODO: Get created by from JWT token
	createdBy := uuid.New() // Placeholder

	if err := h.roleService.InitializeDefaultRoles(ctx, tenantID, createdBy); err != nil {
		h.logger.Error("Failed to initialize default roles", "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})
	}

	return c.JSON(http.StatusOK, map[string]string{
		"message": "Default roles initialized successfully",
	})
}
