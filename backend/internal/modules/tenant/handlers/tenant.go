package handlers

import (
	"context"
	"net/http"
	"strconv"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/ducdt2000/azth/backend/internal/modules/tenant/dto"
	"github.com/ducdt2000/azth/backend/internal/modules/tenant/service"
	"github.com/ducdt2000/azth/backend/pkg/logger"
	"github.com/ducdt2000/azth/backend/pkg/response"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

// tracer for OpenTelemetry tracing
var tracer = otel.Tracer("tenant-handler")

// TenantHandler handles HTTP requests for tenant operations using CQRS pattern
type TenantHandler struct {
	service  *service.TenantCQRSService
	logger   *logger.Logger
	response *response.ResponseBuilder
}

// NewTenantHandler creates a new tenant handler
func NewTenantHandler(
	service *service.TenantCQRSService,
	logger *logger.Logger,
	responseBuilder *response.ResponseBuilder,
) *TenantHandler {
	return &TenantHandler{
		service:  service,
		logger:   logger,
		response: responseBuilder,
	}
}

// CreateTenant godoc
// @Summary Create a new tenant
// @Description Create a new tenant organization
// @Tags Tenants
// @Accept json
// @Produce json
// @Param request body dto.CreateTenantRequest true "Tenant creation request"
// @Success 201 {object} response.Response{data=dto.TenantResponse} "Tenant created successfully"
// @Failure 400 {object} response.Response{error=response.ErrorInfo} "Invalid request data"
// @Failure 409 {object} response.Response{error=response.ErrorInfo} "Slug or domain already exists"
// @Failure 500 {object} response.Response{error=response.ErrorInfo} "Internal server error"
// @Router /api/v1/tenants [post]
// @Security BearerAuth
func (h *TenantHandler) CreateTenant(c echo.Context) error {
	ctx, span := tracer.Start(c.Request().Context(), "TenantHandler.CreateTenant")
	defer span.End()

	var req dto.CreateTenantRequest
	if err := c.Bind(&req); err != nil {
		h.logger.Error("Failed to bind create tenant request", "error", err)
		return h.response.ValidationError(c, map[string]interface{}{
			"field": "request_body",
			"error": err.Error(),
		})
	}

	if err := c.Validate(&req); err != nil {
		h.logger.Error("Failed to validate create tenant request", "error", err)
		return h.response.ValidationError(c, map[string]interface{}{
			"field": "validation",
			"error": err.Error(),
		})
	}

	// Add user context to request context
	ctx = h.addUserContextToRequest(c)

	span.SetAttributes(
		attribute.String("tenant.name", req.Name),
		attribute.String("tenant.slug", req.Slug),
	)

	// Call service layer
	tenant, err := h.service.CreateTenant(ctx, &req)
	if err != nil {
		h.logger.Error("Failed to create tenant", "error", err)
		return h.response.ServiceError(c, err)
	}

	// Add request metadata
	requestID := response.GetRequestID(c)
	meta := h.response.WithRequestID(requestID)

	h.logger.Info("Tenant created successfully", "tenant_id", tenant.ID, "slug", req.Slug)
	return h.response.Created(c, response.TENANT_CREATED, tenant, meta)
}

// GetTenant godoc
// @Summary Get tenant by ID
// @Description Retrieve a tenant by their unique identifier
// @Tags Tenants
// @Accept json
// @Produce json
// @Param id path string true "Tenant ID" format(uuid)
// @Success 200 {object} response.Response{data=dto.TenantResponse} "Tenant retrieved successfully"
// @Failure 400 {object} response.Response{error=response.ErrorInfo} "Invalid tenant ID"
// @Failure 404 {object} response.Response{error=response.ErrorInfo} "Tenant not found"
// @Failure 500 {object} response.Response{error=response.ErrorInfo} "Internal server error"
// @Router /api/v1/tenants/{id} [get]
// @Security BearerAuth
func (h *TenantHandler) GetTenant(c echo.Context) error {
	ctx, span := tracer.Start(c.Request().Context(), "TenantHandler.GetTenant")
	defer span.End()

	tenantID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return h.response.BadRequest(c, response.REQUEST_PARAM_INVALID, map[string]interface{}{
			"param":    "id",
			"provided": c.Param("id"),
		})
	}

	span.SetAttributes(attribute.String("tenant.id", tenantID.String()))

	ctx = h.addUserContextToRequest(c)
	tenant, err := h.service.GetTenant(ctx, tenantID)
	if err != nil {
		h.logger.Error("Failed to get tenant", "tenant_id", tenantID, "error", err)
		return h.response.ServiceError(c, err)
	}

	// Add request metadata
	requestID := response.GetRequestID(c)
	meta := h.response.WithRequestID(requestID)

	return h.response.Success(c, response.TENANT_RETRIEVED, tenant, meta)
}

// GetTenantBySlug godoc
// @Summary Get tenant by slug
// @Description Retrieve a tenant by their unique slug identifier
// @Tags Tenants
// @Accept json
// @Produce json
// @Param slug path string true "Tenant slug"
// @Success 200 {object} response.Response{data=dto.TenantResponse} "Tenant retrieved successfully"
// @Failure 404 {object} response.Response{error=response.ErrorInfo} "Tenant not found"
// @Failure 500 {object} response.Response{error=response.ErrorInfo} "Internal server error"
// @Router /api/v1/tenants/slug/{slug} [get]
// @Security BearerAuth
func (h *TenantHandler) GetTenantBySlug(c echo.Context) error {
	slug := c.Param("slug")
	if slug == "" {
		return c.JSON(http.StatusBadRequest, response.Response{
			Success: false,
			Message: "Slug is required",
			Error: &response.ErrorInfo{
				Code:    "INVALID_SLUG",
				Message: "Slug parameter is required",
			},
		})
	}

	ctx := h.addUserContextToRequest(c)
	tenant, err := h.service.GetTenantBySlug(ctx, slug)
	if err != nil {
		h.logger.Error("Failed to get tenant by slug", "slug", slug, "error", err)
		return h.response.ServiceError(c, err)
	}

	// Add request metadata
	requestID := response.GetRequestID(c)
	meta := h.response.WithRequestID(requestID)

	return h.response.Success(c, response.TENANT_RETRIEVED, tenant, meta)
}

// UpdateTenant godoc
// @Summary Update tenant
// @Description Update an existing tenant's information
// @Tags Tenants
// @Accept json
// @Produce json
// @Param id path string true "Tenant ID" format(uuid)
// @Param request body dto.UpdateTenantRequest true "Tenant update request"
// @Success 200 {object} response.Response{data=dto.TenantResponse} "Tenant updated successfully"
// @Failure 400 {object} response.Response{error=response.ErrorInfo} "Invalid request data"
// @Failure 404 {object} response.Response{error=response.ErrorInfo} "Tenant not found"
// @Failure 409 {object} response.Response{error=response.ErrorInfo} "Domain already exists"
// @Failure 500 {object} response.Response{error=response.ErrorInfo} "Internal server error"
// @Router /api/v1/tenants/{id} [put]
// @Security BearerAuth
func (h *TenantHandler) UpdateTenant(c echo.Context) error {
	ctx, span := tracer.Start(c.Request().Context(), "TenantHandler.UpdateTenant")
	defer span.End()

	tenantID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return h.response.BadRequest(c, response.REQUEST_PARAM_INVALID, map[string]interface{}{
			"param":    "id",
			"provided": c.Param("id"),
		})
	}

	var req dto.UpdateTenantRequest
	if err := c.Bind(&req); err != nil {
		h.logger.Error("Failed to bind update tenant request", "error", err)
		return h.response.ValidationError(c, map[string]interface{}{
			"field": "request_body",
			"error": err.Error(),
		})
	}

	if err := c.Validate(&req); err != nil {
		h.logger.Error("Failed to validate update tenant request", "error", err)
		return h.response.ValidationError(c, map[string]interface{}{
			"field": "validation",
			"error": err.Error(),
		})
	}

	span.SetAttributes(attribute.String("tenant.id", tenantID.String()))

	ctx = h.addUserContextToRequest(c)
	tenant, err := h.service.UpdateTenant(ctx, tenantID, &req)
	if err != nil {
		h.logger.Error("Failed to update tenant", "tenant_id", tenantID, "error", err)
		return h.response.ServiceError(c, err)
	}

	// Add request metadata
	requestID := response.GetRequestID(c)
	meta := h.response.WithRequestID(requestID)

	h.logger.Info("Tenant updated successfully", "tenant_id", tenantID)
	return h.response.Success(c, response.TENANT_UPDATED, tenant, meta)
}

// DeleteTenant godoc
// @Summary Delete tenant
// @Description Soft delete a tenant
// @Tags Tenants
// @Accept json
// @Produce json
// @Param id path string true "Tenant ID" format(uuid)
// @Param reason query string false "Deletion reason"
// @Success 200 {object} response.Response{} "Tenant deleted successfully"
// @Failure 400 {object} response.Response{error=response.ErrorInfo} "Invalid tenant ID"
// @Failure 404 {object} response.Response{error=response.ErrorInfo} "Tenant not found"
// @Failure 500 {object} response.Response{error=response.ErrorInfo} "Internal server error"
// @Router /api/v1/tenants/{id} [delete]
// @Security BearerAuth
func (h *TenantHandler) DeleteTenant(c echo.Context) error {
	ctx, span := tracer.Start(c.Request().Context(), "TenantHandler.DeleteTenant")
	defer span.End()

	tenantID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return h.response.BadRequest(c, response.REQUEST_PARAM_INVALID, map[string]interface{}{
			"param":    "id",
			"provided": c.Param("id"),
		})
	}

	span.SetAttributes(attribute.String("tenant.id", tenantID.String()))

	ctx = h.addUserContextToRequest(c)
	err = h.service.DeleteTenant(ctx, tenantID)
	if err != nil {
		h.logger.Error("Failed to delete tenant", "tenant_id", tenantID, "error", err)
		return h.response.ServiceError(c, err)
	}

	h.logger.Info("Tenant deleted successfully", "tenant_id", tenantID)
	return h.response.Success(c, response.TENANT_DELETED, map[string]interface{}{
		"tenant_id": tenantID,
	})
}

// ListTenants godoc
// @Summary List tenants
// @Description List tenants with pagination and filtering
// @Tags Tenants
// @Accept json
// @Produce json
// @Param page query int false "Page number" minimum(1) default(1)
// @Param limit query int false "Items per page" minimum(1) maximum(100) default(20)
// @Param sort query string false "Sort field" Enums(created_at, updated_at, name, slug) default(created_at)
// @Param order query string false "Sort order" Enums(asc, desc) default(desc)
// @Param search query string false "Search term"
// @Param status query string false "Filter by status" Enums(active, inactive, suspended, trial)
// @Param plan query string false "Filter by plan" Enums(free, pro, enterprise)
// @Success 200 {object} response.Response{data=dto.TenantListResponse} "Tenants retrieved successfully"
// @Failure 400 {object} response.Response{error=response.ErrorInfo} "Invalid query parameters"
// @Failure 500 {object} response.Response{error=response.ErrorInfo} "Internal server error"
// @Router /api/v1/tenants [get]
// @Security BearerAuth
func (h *TenantHandler) ListTenants(c echo.Context) error {
	ctx, span := tracer.Start(c.Request().Context(), "TenantHandler.ListTenants")
	defer span.End()

	req, err := h.parseTenantListRequest(c)
	if err != nil {
		return h.response.BadRequest(c, response.REQUEST_INVALID, map[string]interface{}{
			"error": err.Error(),
		})
	}

	span.SetAttributes(
		attribute.Int("tenant.page", req.Page),
		attribute.Int("tenant.limit", req.Limit),
		attribute.String("tenant.sort", req.Sort),
		attribute.String("tenant.order", req.Order),
		attribute.String("tenant.search", req.Search),
		attribute.String("tenant.status", req.Status),
		attribute.String("tenant.plan", req.Plan),
	)

	ctx = h.addUserContextToRequest(c)
	tenants, err := h.service.ListTenants(ctx, req)
	if err != nil {
		h.logger.Error("Failed to list tenants", "error", err)
		return h.response.ServiceError(c, err)
	}

	// Add request metadata
	requestID := response.GetRequestID(c)
	meta := h.response.WithRequestID(requestID)

	return h.response.Success(c, response.TENANT_RETRIEVED, tenants, meta)
}

// ActivateTenant godoc
// @Summary Activate tenant
// @Description Activate a tenant
// @Tags Tenants
// @Accept json
// @Produce json
// @Param id path string true "Tenant ID" format(uuid)
// @Param reason query string false "Activation reason"
// @Success 200 {object} response.Response{data=dto.TenantResponse} "Tenant activated successfully"
// @Failure 400 {object} response.Response{error=response.ErrorInfo} "Invalid tenant ID"
// @Failure 404 {object} response.Response{error=response.ErrorInfo} "Tenant not found"
// @Failure 500 {object} response.Response{error=response.ErrorInfo} "Internal server error"
// @Router /api/v1/tenants/{id}/activate [post]
// @Security BearerAuth
func (h *TenantHandler) ActivateTenant(c echo.Context) error {
	tenantID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, response.Response{
			Success: false,
			Message: "Invalid tenant ID",
			Error: &response.ErrorInfo{
				Code:    "INVALID_TENANT_ID",
				Message: "Invalid tenant ID format",
			},
		})
	}

	ctx := h.addUserContextToRequest(c)
	err = h.service.ActivateTenant(ctx, tenantID)
	if err != nil {
		h.logger.Error("Failed to activate tenant", "tenant_id", tenantID, "error", err)
		return h.response.ServiceError(c, err)
	}

	// Get updated tenant for response
	tenant, err := h.service.GetTenant(ctx, tenantID)
	if err != nil {
		h.logger.Error("Failed to retrieve updated tenant", "error", err)
		return h.response.ServiceError(c, err)
	}

	// Add request metadata
	requestID := response.GetRequestID(c)
	meta := h.response.WithRequestID(requestID)

	h.logger.Info("Tenant activated successfully", "tenant_id", tenantID)
	return h.response.Success(c, response.TENANT_ACTIVATED, tenant, meta)
}

// DeactivateTenant godoc
// @Summary Deactivate tenant
// @Description Deactivate a tenant
// @Tags Tenants
// @Accept json
// @Produce json
// @Param id path string true "Tenant ID" format(uuid)
// @Param reason query string false "Deactivation reason"
// @Success 200 {object} response.Response{data=dto.TenantResponse} "Tenant deactivated successfully"
// @Failure 400 {object} response.Response{error=response.ErrorInfo} "Invalid tenant ID"
// @Failure 404 {object} response.Response{error=response.ErrorInfo} "Tenant not found"
// @Failure 500 {object} response.Response{error=response.ErrorInfo} "Internal server error"
// @Router /api/v1/tenants/{id}/deactivate [post]
// @Security BearerAuth
func (h *TenantHandler) DeactivateTenant(c echo.Context) error {
	tenantID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, response.Response{
			Success: false,
			Message: "Invalid tenant ID",
			Error: &response.ErrorInfo{
				Code:    "INVALID_TENANT_ID",
				Message: "Invalid tenant ID format",
			},
		})
	}

	ctx := h.addUserContextToRequest(c)
	err = h.service.DeactivateTenant(ctx, tenantID)
	if err != nil {
		h.logger.Error("Failed to deactivate tenant", "tenant_id", tenantID, "error", err)
		return h.handleServiceError(c, err)
	}

	// Get updated tenant for response
	tenant, err := h.service.GetTenant(ctx, tenantID)
	if err != nil {
		h.logger.Error("Failed to retrieve updated tenant", "error", err)
		return h.handleServiceError(c, err)
	}

	h.logger.Info("Tenant deactivated successfully", "tenant_id", tenantID)
	return c.JSON(http.StatusOK, response.Response{
		Success: true,
		Message: "Tenant deactivated successfully",
		Data:    tenant,
	})
}

// SuspendTenant godoc
// @Summary Suspend tenant
// @Description Suspend a tenant
// @Tags Tenants
// @Accept json
// @Produce json
// @Param id path string true "Tenant ID" format(uuid)
// @Param reason query string true "Suspension reason"
// @Success 200 {object} response.Response{data=dto.TenantResponse} "Tenant suspended successfully"
// @Failure 400 {object} response.Response{error=response.ErrorInfo} "Invalid tenant ID or missing reason"
// @Failure 404 {object} response.Response{error=response.ErrorInfo} "Tenant not found"
// @Failure 500 {object} response.Response{error=response.ErrorInfo} "Internal server error"
// @Router /api/v1/tenants/{id}/suspend [post]
// @Security BearerAuth
func (h *TenantHandler) SuspendTenant(c echo.Context) error {
	tenantID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, response.Response{
			Success: false,
			Message: "Invalid tenant ID",
			Error: &response.ErrorInfo{
				Code:    "INVALID_TENANT_ID",
				Message: "Invalid tenant ID format",
			},
		})
	}

	ctx := h.addUserContextToRequest(c)
	err = h.service.SuspendTenant(ctx, tenantID)
	if err != nil {
		h.logger.Error("Failed to suspend tenant", "tenant_id", tenantID, "error", err)
		return h.handleServiceError(c, err)
	}

	// Get updated tenant for response
	tenant, err := h.service.GetTenant(ctx, tenantID)
	if err != nil {
		h.logger.Error("Failed to retrieve updated tenant", "error", err)
		return h.handleServiceError(c, err)
	}

	h.logger.Info("Tenant suspended successfully", "tenant_id", tenantID)
	return c.JSON(http.StatusOK, response.Response{
		Success: true,
		Message: "Tenant suspended successfully",
		Data:    tenant,
	})
}

// BulkUpdateTenants godoc
// @Summary Bulk update tenants
// @Description Perform bulk operations on multiple tenants
// @Tags Tenants
// @Accept json
// @Produce json
// @Param request body dto.BulkTenantRequest true "Bulk operation request"
// @Success 200 {object} response.Response{data=dto.BulkOperationResponse} "Bulk operation completed"
// @Failure 400 {object} response.Response{error=response.ErrorInfo} "Invalid request data"
// @Failure 500 {object} response.Response{error=response.ErrorInfo} "Internal server error"
// @Router /api/v1/tenants/bulk [post]
// @Security BearerAuth
func (h *TenantHandler) BulkUpdateTenants(c echo.Context) error {
	var req dto.BulkTenantRequest
	if err := c.Bind(&req); err != nil {
		h.logger.Error("Failed to bind bulk tenant request", "error", err)
		return c.JSON(http.StatusBadRequest, response.Response{
			Success: false,
			Message: "Invalid request data",
			Error: &response.ErrorInfo{
				Code:    "INVALID_REQUEST",
				Message: "Invalid request data",
				Details: err.Error(),
			},
		})
	}

	ctx := h.addUserContextToRequest(c)
	bulkResponse, err := h.service.BulkUpdateTenants(ctx, &req)
	if err != nil {
		h.logger.Error("Failed to perform bulk operation", "error", err)
		return h.handleServiceError(c, err)
	}

	h.logger.Info("Bulk operation completed", "total", bulkResponse.TotalProcessed, "success", bulkResponse.SuccessCount, "errors", bulkResponse.ErrorCount)
	return c.JSON(http.StatusOK, response.Response{
		Success: true,
		Message: "Bulk operation completed",
		Data:    bulkResponse,
	})
}

// Helper methods

func (h *TenantHandler) addUserContextToRequest(c echo.Context) context.Context {
	ctx := c.Request().Context()

	// Extract user ID from context (should be set by authentication middleware)
	if userIDStr := c.Get("user_id"); userIDStr != nil {
		if userID, err := uuid.Parse(userIDStr.(string)); err == nil {
			ctx = context.WithValue(ctx, "user_id", userID)
		}
	}

	return ctx
}

func (h *TenantHandler) parseTenantListRequest(c echo.Context) (*dto.TenantListRequest, error) {
	req := &dto.TenantListRequest{
		Page:   1,
		Limit:  20,
		Sort:   "created_at",
		Order:  "desc",
		Search: c.QueryParam("search"),
		Status: c.QueryParam("status"),
		Plan:   c.QueryParam("plan"),
	}

	if page := c.QueryParam("page"); page != "" {
		if p, err := strconv.Atoi(page); err == nil && p > 0 {
			req.Page = p
		}
	}

	if limit := c.QueryParam("limit"); limit != "" {
		if l, err := strconv.Atoi(limit); err == nil && l > 0 && l <= 100 {
			req.Limit = l
		}
	}

	if sort := c.QueryParam("sort"); sort != "" {
		req.Sort = sort
	}

	if order := c.QueryParam("order"); order != "" {
		req.Order = order
	}

	return req, nil
}

func (h *TenantHandler) handleServiceError(c echo.Context, err error) error {
	// Map specific errors to HTTP status codes
	switch {
	case err.Error() == "tenant already exists":
		return c.JSON(http.StatusConflict, response.Response{
			Success: false,
			Message: "Tenant already exists",
			Error: &response.ErrorInfo{
				Code:    "TENANT_EXISTS",
				Message: "Tenant already exists",
			},
		})
	case err.Error() == "tenant not found" || err.Error() == "failed to retrieve created tenant: tenant not found":
		return c.JSON(http.StatusNotFound, response.Response{
			Success: false,
			Message: "Tenant not found",
			Error: &response.ErrorInfo{
				Code:    "TENANT_NOT_FOUND",
				Message: "Tenant not found",
			},
		})
	case err.Error() == "tenant slug already exists" || err.Error() == "tenant domain already exists":
		return c.JSON(http.StatusConflict, response.Response{
			Success: false,
			Message: "Resource already exists",
			Error: &response.ErrorInfo{
				Code:    "RESOURCE_EXISTS",
				Message: err.Error(),
			},
		})
	default:
		return c.JSON(http.StatusInternalServerError, response.Response{
			Success: false,
			Message: "Internal server error",
			Error: &response.ErrorInfo{
				Code:    "INTERNAL_ERROR",
				Message: "An internal error occurred",
				Details: err.Error(),
			},
		})
	}
}
