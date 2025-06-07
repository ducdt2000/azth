package handlers

import (
	"net/http"
	"strconv"

	"github.com/ducdt2000/azth/backend/internal/modules/permission/dto"
	"github.com/ducdt2000/azth/backend/internal/modules/permission/service"
	"github.com/ducdt2000/azth/backend/pkg/logger"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

// tracer for OpenTelemetry tracing
var tracer = otel.Tracer("permission-handler")

// PermissionHandler handles HTTP requests for permission operations
type PermissionHandler struct {
	permissionService service.PermissionService
	logger            *logger.Logger
}

// NewPermissionHandler creates a new permission handler
func NewPermissionHandler(permissionService service.PermissionService, logger *logger.Logger) *PermissionHandler {
	return &PermissionHandler{
		permissionService: permissionService,
		logger:            logger,
	}
}

// CreatePermission handles POST /api/v1/permissions
func (h *PermissionHandler) CreatePermission(c echo.Context) error {
	ctx, span := tracer.Start(c.Request().Context(), "PermissionHandler.CreatePermission")
	defer span.End()

	var req dto.PermissionRequest
	if err := c.Bind(&req); err != nil {
		h.logger.Error("Failed to bind permission request", "error", err)
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid request body",
		})
	}

	span.SetAttributes(
		attribute.String("permission.name", req.Name),
		attribute.String("permission.code", req.Code),
		attribute.String("permission.module", req.Module),
		attribute.String("permission.resource", req.Resource),
		attribute.String("permission.action", req.Action),
	)

	permission, err := h.permissionService.CreatePermission(ctx, &req)
	if err != nil {
		h.logger.Error("Failed to create permission", "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})
	}

	return c.JSON(http.StatusCreated, permission)
}

// GetPermission handles GET /api/v1/permissions/:id
func (h *PermissionHandler) GetPermission(c echo.Context) error {
	ctx, span := tracer.Start(c.Request().Context(), "PermissionHandler.GetPermission")
	defer span.End()

	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid permission ID",
		})
	}

	span.SetAttributes(attribute.String("permission.id", id.String()))

	permission, err := h.permissionService.GetPermission(ctx, id)
	if err != nil {
		h.logger.Error("Failed to get permission", "error", err, "permission_id", id)
		return c.JSON(http.StatusNotFound, map[string]string{
			"error": err.Error(),
		})
	}

	return c.JSON(http.StatusOK, permission)
}

// GetPermissionByCode handles GET /api/v1/permissions/code/:code
func (h *PermissionHandler) GetPermissionByCode(c echo.Context) error {
	ctx, span := tracer.Start(c.Request().Context(), "PermissionHandler.GetPermissionByCode")
	defer span.End()

	code := c.Param("code")
	span.SetAttributes(attribute.String("permission.code", code))

	permission, err := h.permissionService.GetPermissionByCode(ctx, code)
	if err != nil {
		h.logger.Error("Failed to get permission by code", "error", err, "code", code)
		return c.JSON(http.StatusNotFound, map[string]string{
			"error": err.Error(),
		})
	}

	return c.JSON(http.StatusOK, permission)
}

// UpdatePermission handles PUT /api/v1/permissions/:id
func (h *PermissionHandler) UpdatePermission(c echo.Context) error {
	ctx, span := tracer.Start(c.Request().Context(), "PermissionHandler.UpdatePermission")
	defer span.End()

	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid permission ID",
		})
	}

	var req dto.UpdatePermissionRequest
	if err := c.Bind(&req); err != nil {
		h.logger.Error("Failed to bind update permission request", "error", err)
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid request body",
		})
	}

	span.SetAttributes(attribute.String("permission.id", id.String()))

	permission, err := h.permissionService.UpdatePermission(ctx, id, &req)
	if err != nil {
		h.logger.Error("Failed to update permission", "error", err, "permission_id", id)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})
	}

	return c.JSON(http.StatusOK, permission)
}

// DeletePermission handles DELETE /api/v1/permissions/:id
func (h *PermissionHandler) DeletePermission(c echo.Context) error {
	ctx, span := tracer.Start(c.Request().Context(), "PermissionHandler.DeletePermission")
	defer span.End()

	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid permission ID",
		})
	}

	span.SetAttributes(attribute.String("permission.id", id.String()))

	if err := h.permissionService.DeletePermission(ctx, id); err != nil {
		h.logger.Error("Failed to delete permission", "error", err, "permission_id", id)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})
	}

	return c.JSON(http.StatusOK, map[string]string{
		"message": "Permission deleted successfully",
	})
}

// ListPermissions handles GET /api/v1/permissions
func (h *PermissionHandler) ListPermissions(c echo.Context) error {
	ctx, span := tracer.Start(c.Request().Context(), "PermissionHandler.ListPermissions")
	defer span.End()

	// Parse query parameters
	var req dto.PermissionListRequest

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
	req.Module = c.QueryParam("module")
	req.Resource = c.QueryParam("resource")
	req.Action = c.QueryParam("action")

	// Parse boolean query parameters
	if systemStr := c.QueryParam("is_system"); systemStr != "" {
		if systemVal, err := strconv.ParseBool(systemStr); err == nil {
			req.IsSystem = &systemVal
		}
	}
	if defaultStr := c.QueryParam("is_default"); defaultStr != "" {
		if defaultVal, err := strconv.ParseBool(defaultStr); err == nil {
			req.IsDefault = &defaultVal
		}
	}

	permissions, err := h.permissionService.ListPermissions(ctx, &req)
	if err != nil {
		h.logger.Error("Failed to list permissions", "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})
	}

	return c.JSON(http.StatusOK, permissions)
}

// GetPermissionsByModule handles GET /api/v1/permissions/module/:module
func (h *PermissionHandler) GetPermissionsByModule(c echo.Context) error {
	ctx, span := tracer.Start(c.Request().Context(), "PermissionHandler.GetPermissionsByModule")
	defer span.End()

	module := c.Param("module")
	span.SetAttributes(attribute.String("permission.module", module))

	permissions, err := h.permissionService.GetPermissionsByModule(ctx, module)
	if err != nil {
		h.logger.Error("Failed to get permissions by module", "error", err, "module", module)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})
	}

	return c.JSON(http.StatusOK, permissions)
}

// GetPermissionsByResource handles GET /api/v1/permissions/module/:module/resource/:resource
func (h *PermissionHandler) GetPermissionsByResource(c echo.Context) error {
	ctx, span := tracer.Start(c.Request().Context(), "PermissionHandler.GetPermissionsByResource")
	defer span.End()

	module := c.Param("module")
	resource := c.Param("resource")

	span.SetAttributes(
		attribute.String("permission.module", module),
		attribute.String("permission.resource", resource),
	)

	permissions, err := h.permissionService.GetPermissionsByResource(ctx, module, resource)
	if err != nil {
		h.logger.Error("Failed to get permissions by resource", "error", err, "module", module, "resource", resource)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})
	}

	return c.JSON(http.StatusOK, permissions)
}

// GetPermissionByAction handles GET /api/v1/permissions/module/:module/resource/:resource/action/:action
func (h *PermissionHandler) GetPermissionByAction(c echo.Context) error {
	ctx, span := tracer.Start(c.Request().Context(), "PermissionHandler.GetPermissionByAction")
	defer span.End()

	module := c.Param("module")
	resource := c.Param("resource")
	action := c.Param("action")

	span.SetAttributes(
		attribute.String("permission.module", module),
		attribute.String("permission.resource", resource),
		attribute.String("permission.action", action),
	)

	permission, err := h.permissionService.GetPermissionByAction(ctx, module, resource, action)
	if err != nil {
		h.logger.Error("Failed to get permission by action", "error", err, "module", module, "resource", resource, "action", action)
		return c.JSON(http.StatusNotFound, map[string]string{
			"error": err.Error(),
		})
	}

	return c.JSON(http.StatusOK, permission)
}

// GetDefaultPermissions handles GET /api/v1/permissions/default
func (h *PermissionHandler) GetDefaultPermissions(c echo.Context) error {
	ctx, span := tracer.Start(c.Request().Context(), "PermissionHandler.GetDefaultPermissions")
	defer span.End()

	permissions, err := h.permissionService.GetDefaultPermissions(ctx)
	if err != nil {
		h.logger.Error("Failed to get default permissions", "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})
	}

	return c.JSON(http.StatusOK, permissions)
}

// GetSystemPermissions handles GET /api/v1/permissions/system
func (h *PermissionHandler) GetSystemPermissions(c echo.Context) error {
	ctx, span := tracer.Start(c.Request().Context(), "PermissionHandler.GetSystemPermissions")
	defer span.End()

	permissions, err := h.permissionService.GetSystemPermissions(ctx)
	if err != nil {
		h.logger.Error("Failed to get system permissions", "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})
	}

	return c.JSON(http.StatusOK, permissions)
}

// GetPermissionModules handles GET /api/v1/permissions/modules
func (h *PermissionHandler) GetPermissionModules(c echo.Context) error {
	ctx, span := tracer.Start(c.Request().Context(), "PermissionHandler.GetPermissionModules")
	defer span.End()

	modules, err := h.permissionService.GetPermissionModules(ctx)
	if err != nil {
		h.logger.Error("Failed to get permission modules", "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})
	}

	return c.JSON(http.StatusOK, modules)
}

// GetPermissionsGrouped handles GET /api/v1/permissions/grouped
func (h *PermissionHandler) GetPermissionsGrouped(c echo.Context) error {
	ctx, span := tracer.Start(c.Request().Context(), "PermissionHandler.GetPermissionsGrouped")
	defer span.End()

	groups, err := h.permissionService.GetPermissionsGrouped(ctx)
	if err != nil {
		h.logger.Error("Failed to get permissions grouped", "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})
	}

	return c.JSON(http.StatusOK, groups)
}

// BulkCreatePermissions handles POST /api/v1/permissions/bulk
func (h *PermissionHandler) BulkCreatePermissions(c echo.Context) error {
	ctx, span := tracer.Start(c.Request().Context(), "PermissionHandler.BulkCreatePermissions")
	defer span.End()

	var req dto.BulkPermissionRequest
	if err := c.Bind(&req); err != nil {
		h.logger.Error("Failed to bind bulk permission request", "error", err)
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid request body",
		})
	}

	span.SetAttributes(attribute.Int("permissions.count", len(req.Permissions)))

	result, err := h.permissionService.BulkCreatePermissions(ctx, &req)
	if err != nil {
		h.logger.Error("Failed to bulk create permissions", "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})
	}

	return c.JSON(http.StatusCreated, result)
}

// BulkDeletePermissions handles DELETE /api/v1/permissions/bulk
func (h *PermissionHandler) BulkDeletePermissions(c echo.Context) error {
	ctx, span := tracer.Start(c.Request().Context(), "PermissionHandler.BulkDeletePermissions")
	defer span.End()

	var req dto.BulkPermissionRequest
	if err := c.Bind(&req); err != nil {
		h.logger.Error("Failed to bind bulk permission request", "error", err)
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid request body",
		})
	}

	span.SetAttributes(attribute.Int("permissions.count", len(req.PermissionIDs)))

	result, err := h.permissionService.BulkDeletePermissions(ctx, &req)
	if err != nil {
		h.logger.Error("Failed to bulk delete permissions", "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})
	}

	return c.JSON(http.StatusOK, result)
}

// InitializeDefaultPermissions handles POST /api/v1/permissions/initialize
func (h *PermissionHandler) InitializeDefaultPermissions(c echo.Context) error {
	ctx, span := tracer.Start(c.Request().Context(), "PermissionHandler.InitializeDefaultPermissions")
	defer span.End()

	if err := h.permissionService.InitializeDefaultPermissions(ctx); err != nil {
		h.logger.Error("Failed to initialize default permissions", "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})
	}

	return c.JSON(http.StatusOK, map[string]string{
		"message": "Default permissions initialized successfully",
	})
}

// ValidatePermissionCode handles POST /api/v1/permissions/validate/code
func (h *PermissionHandler) ValidatePermissionCode(c echo.Context) error {
	ctx, span := tracer.Start(c.Request().Context(), "PermissionHandler.ValidatePermissionCode")
	defer span.End()

	var req struct {
		Code string `json:"code" validate:"required"`
	}

	if err := c.Bind(&req); err != nil {
		h.logger.Error("Failed to bind validate permission code request", "error", err)
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid request body",
		})
	}

	span.SetAttributes(attribute.String("permission.code", req.Code))

	if err := h.permissionService.ValidatePermissionCode(ctx, req.Code); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": err.Error(),
			"valid": "false",
		})
	}

	return c.JSON(http.StatusOK, map[string]string{
		"message": "Permission code is valid",
		"valid":   "true",
	})
}

// ValidateModuleResourceAction handles POST /api/v1/permissions/validate/action
func (h *PermissionHandler) ValidateModuleResourceAction(c echo.Context) error {
	ctx, span := tracer.Start(c.Request().Context(), "PermissionHandler.ValidateModuleResourceAction")
	defer span.End()

	var req struct {
		Module   string `json:"module" validate:"required"`
		Resource string `json:"resource" validate:"required"`
		Action   string `json:"action" validate:"required"`
	}

	if err := c.Bind(&req); err != nil {
		h.logger.Error("Failed to bind validate module resource action request", "error", err)
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid request body",
		})
	}

	span.SetAttributes(
		attribute.String("permission.module", req.Module),
		attribute.String("permission.resource", req.Resource),
		attribute.String("permission.action", req.Action),
	)

	if err := h.permissionService.ValidateModuleResourceAction(ctx, req.Module, req.Resource, req.Action); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": err.Error(),
			"valid": "false",
		})
	}

	return c.JSON(http.StatusOK, map[string]string{
		"message": "Module/Resource/Action combination is valid",
		"valid":   "true",
	})
}
