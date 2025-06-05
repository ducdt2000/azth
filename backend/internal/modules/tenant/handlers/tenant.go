package handlers

import (
	"net/http"
	"strconv"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/ducdt2000/azth/backend/internal/modules/tenant/dto"
	"github.com/ducdt2000/azth/backend/internal/modules/tenant/service"
	"github.com/ducdt2000/azth/backend/pkg/logger"
)

// TenantHandler handles HTTP requests for tenant operations
type TenantHandler struct {
	tenantService service.TenantService
	logger        *logger.Logger
}

// NewTenantHandler creates a new tenant handler
func NewTenantHandler(tenantService service.TenantService, logger *logger.Logger) *TenantHandler {
	return &TenantHandler{
		tenantService: tenantService,
		logger:        logger,
	}
}

// CreateTenant godoc
// @Summary Create a new tenant
// @Description Create a new tenant organization with the provided information
// @Tags Tenants
// @Accept json
// @Produce json
// @Param request body dto.CreateTenantRequest true "Tenant creation request"
// @Success 201 {object} dto.APIResponse{data=dto.TenantResponse} "Tenant created successfully"
// @Failure 400 {object} dto.APIResponse{error=dto.APIError} "Invalid request data"
// @Failure 409 {object} dto.APIResponse{error=dto.APIError} "Slug or domain already exists"
// @Failure 500 {object} dto.APIResponse{error=dto.APIError} "Internal server error"
// @Router /api/v1/tenants [post]
// @Security BearerAuth
func (h *TenantHandler) CreateTenant(c echo.Context) error {
	var req dto.CreateTenantRequest
	if err := c.Bind(&req); err != nil {
		h.logger.Error("Failed to bind create tenant request", "error", err)
		return c.JSON(http.StatusBadRequest, dto.APIResponse{
			Success: false,
			Message: "Invalid request data",
			Error: &dto.APIError{
				Code:    "INVALID_REQUEST",
				Message: "Invalid request data",
				Details: err.Error(),
			},
		})
	}

	if err := c.Validate(&req); err != nil {
		h.logger.Error("Failed to validate create tenant request", "error", err)
		return c.JSON(http.StatusBadRequest, dto.APIResponse{
			Success: false,
			Message: "Validation failed",
			Error: &dto.APIError{
				Code:    "VALIDATION_ERROR",
				Message: "Validation failed",
				Details: err.Error(),
			},
		})
	}

	tenant, err := h.tenantService.CreateTenant(c.Request().Context(), &req)
	if err != nil {
		h.logger.Error("Failed to create tenant", "error", err)
		return h.handleServiceError(c, err)
	}

	h.logger.Info("Tenant created successfully", "tenant_id", tenant.ID, "slug", tenant.Slug)
	return c.JSON(http.StatusCreated, dto.APIResponse{
		Success: true,
		Message: "Tenant created successfully",
		Data:    tenant,
	})
}

// GetTenant godoc
// @Summary Get tenant by ID
// @Description Retrieve a tenant by their unique identifier
// @Tags Tenants
// @Accept json
// @Produce json
// @Param id path string true "Tenant ID" format(uuid)
// @Success 200 {object} dto.APIResponse{data=dto.TenantResponse} "Tenant retrieved successfully"
// @Failure 400 {object} dto.APIResponse{error=dto.APIError} "Invalid tenant ID"
// @Failure 404 {object} dto.APIResponse{error=dto.APIError} "Tenant not found"
// @Failure 500 {object} dto.APIResponse{error=dto.APIError} "Internal server error"
// @Router /api/v1/tenants/{id} [get]
// @Security BearerAuth
func (h *TenantHandler) GetTenant(c echo.Context) error {
	tenantID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, dto.APIResponse{
			Success: false,
			Message: "Invalid tenant ID",
			Error: &dto.APIError{
				Code:    "INVALID_TENANT_ID",
				Message: "Invalid tenant ID format",
			},
		})
	}

	tenant, err := h.tenantService.GetTenant(c.Request().Context(), tenantID)
	if err != nil {
		h.logger.Error("Failed to get tenant", "tenant_id", tenantID, "error", err)
		return h.handleServiceError(c, err)
	}

	return c.JSON(http.StatusOK, dto.APIResponse{
		Success: true,
		Message: "Tenant retrieved successfully",
		Data:    tenant,
	})
}

// GetTenantBySlug godoc
// @Summary Get tenant by slug
// @Description Retrieve a tenant by their unique slug identifier
// @Tags Tenants
// @Accept json
// @Produce json
// @Param slug path string true "Tenant slug"
// @Success 200 {object} dto.APIResponse{data=dto.TenantResponse} "Tenant retrieved successfully"
// @Failure 404 {object} dto.APIResponse{error=dto.APIError} "Tenant not found"
// @Failure 500 {object} dto.APIResponse{error=dto.APIError} "Internal server error"
// @Router /api/v1/tenants/slug/{slug} [get]
// @Security BearerAuth
func (h *TenantHandler) GetTenantBySlug(c echo.Context) error {
	slug := c.Param("slug")
	if slug == "" {
		return c.JSON(http.StatusBadRequest, dto.APIResponse{
			Success: false,
			Message: "Slug is required",
			Error: &dto.APIError{
				Code:    "INVALID_SLUG",
				Message: "Slug parameter is required",
			},
		})
	}

	tenant, err := h.tenantService.GetTenantBySlug(c.Request().Context(), slug)
	if err != nil {
		h.logger.Error("Failed to get tenant by slug", "slug", slug, "error", err)
		return h.handleServiceError(c, err)
	}

	return c.JSON(http.StatusOK, dto.APIResponse{
		Success: true,
		Message: "Tenant retrieved successfully",
		Data:    tenant,
	})
}

// UpdateTenant godoc
// @Summary Update tenant
// @Description Update an existing tenant's information
// @Tags Tenants
// @Accept json
// @Produce json
// @Param id path string true "Tenant ID" format(uuid)
// @Param request body dto.UpdateTenantRequest true "Tenant update request"
// @Success 200 {object} dto.APIResponse{data=dto.TenantResponse} "Tenant updated successfully"
// @Failure 400 {object} dto.APIResponse{error=dto.APIError} "Invalid request data"
// @Failure 404 {object} dto.APIResponse{error=dto.APIError} "Tenant not found"
// @Failure 409 {object} dto.APIResponse{error=dto.APIError} "Domain already exists"
// @Failure 500 {object} dto.APIResponse{error=dto.APIError} "Internal server error"
// @Router /api/v1/tenants/{id} [put]
// @Security BearerAuth
func (h *TenantHandler) UpdateTenant(c echo.Context) error {
	tenantID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, dto.APIResponse{
			Success: false,
			Message: "Invalid tenant ID",
			Error: &dto.APIError{
				Code:    "INVALID_TENANT_ID",
				Message: "Invalid tenant ID format",
			},
		})
	}

	var req dto.UpdateTenantRequest
	if err := c.Bind(&req); err != nil {
		h.logger.Error("Failed to bind update tenant request", "error", err)
		return c.JSON(http.StatusBadRequest, dto.APIResponse{
			Success: false,
			Message: "Invalid request data",
			Error: &dto.APIError{
				Code:    "INVALID_REQUEST",
				Message: "Invalid request data",
				Details: err.Error(),
			},
		})
	}

	if err := c.Validate(&req); err != nil {
		h.logger.Error("Failed to validate update tenant request", "error", err)
		return c.JSON(http.StatusBadRequest, dto.APIResponse{
			Success: false,
			Message: "Validation failed",
			Error: &dto.APIError{
				Code:    "VALIDATION_ERROR",
				Message: "Validation failed",
				Details: err.Error(),
			},
		})
	}

	tenant, err := h.tenantService.UpdateTenant(c.Request().Context(), tenantID, &req)
	if err != nil {
		h.logger.Error("Failed to update tenant", "tenant_id", tenantID, "error", err)
		return h.handleServiceError(c, err)
	}

	h.logger.Info("Tenant updated successfully", "tenant_id", tenantID)
	return c.JSON(http.StatusOK, dto.APIResponse{
		Success: true,
		Message: "Tenant updated successfully",
		Data:    tenant,
	})
}

// DeleteTenant godoc
// @Summary Delete tenant
// @Description Soft delete a tenant and all associated data
// @Tags Tenants
// @Accept json
// @Produce json
// @Param id path string true "Tenant ID" format(uuid)
// @Success 200 {object} dto.APIResponse "Tenant deleted successfully"
// @Failure 400 {object} dto.APIResponse{error=dto.APIError} "Invalid tenant ID"
// @Failure 404 {object} dto.APIResponse{error=dto.APIError} "Tenant not found"
// @Failure 500 {object} dto.APIResponse{error=dto.APIError} "Internal server error"
// @Router /api/v1/tenants/{id} [delete]
// @Security BearerAuth
func (h *TenantHandler) DeleteTenant(c echo.Context) error {
	tenantID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, dto.APIResponse{
			Success: false,
			Message: "Invalid tenant ID",
			Error: &dto.APIError{
				Code:    "INVALID_TENANT_ID",
				Message: "Invalid tenant ID format",
			},
		})
	}

	err = h.tenantService.DeleteTenant(c.Request().Context(), tenantID)
	if err != nil {
		h.logger.Error("Failed to delete tenant", "tenant_id", tenantID, "error", err)
		return h.handleServiceError(c, err)
	}

	h.logger.Info("Tenant deleted successfully", "tenant_id", tenantID)
	return c.JSON(http.StatusOK, dto.APIResponse{
		Success: true,
		Message: "Tenant deleted successfully",
	})
}

// ListTenants godoc
// @Summary List tenants
// @Description Retrieve a paginated list of tenants with optional filtering
// @Tags Tenants
// @Accept json
// @Produce json
// @Param page query int false "Page number" default(1) minimum(1)
// @Param limit query int false "Items per page" default(20) minimum(1) maximum(100)
// @Param sort query string false "Sort field" Enums(created_at, updated_at, name, slug) default(created_at)
// @Param order query string false "Sort order" Enums(asc, desc) default(desc)
// @Param search query string false "Search term (name, slug, domain)"
// @Param status query string false "Filter by status" Enums(active, inactive, suspended, trial)
// @Param plan query string false "Filter by plan" Enums(free, pro, enterprise)
// @Success 200 {object} dto.APIResponse{data=dto.TenantListResponse} "Tenants retrieved successfully"
// @Failure 400 {object} dto.APIResponse{error=dto.APIError} "Invalid query parameters"
// @Failure 500 {object} dto.APIResponse{error=dto.APIError} "Internal server error"
// @Router /api/v1/tenants [get]
// @Security BearerAuth
func (h *TenantHandler) ListTenants(c echo.Context) error {
	req, err := h.parseTenantListRequest(c)
	if err != nil {
		return c.JSON(http.StatusBadRequest, dto.APIResponse{
			Success: false,
			Message: "Invalid query parameters",
			Error: &dto.APIError{
				Code:    "INVALID_QUERY_PARAMS",
				Message: "Invalid query parameters",
				Details: err.Error(),
			},
		})
	}

	tenants, err := h.tenantService.ListTenants(c.Request().Context(), req)
	if err != nil {
		h.logger.Error("Failed to list tenants", "error", err)
		return h.handleServiceError(c, err)
	}

	return c.JSON(http.StatusOK, dto.APIResponse{
		Success: true,
		Message: "Tenants retrieved successfully",
		Data:    tenants,
	})
}

// GetTenantStats godoc
// @Summary Get tenant statistics
// @Description Retrieve tenant statistics with optional filtering
// @Tags Tenants
// @Accept json
// @Produce json
// @Param date_from query string false "Start date for statistics" format(date)
// @Param date_to query string false "End date for statistics" format(date)
// @Success 200 {object} dto.APIResponse{data=dto.TenantStatsResponse} "Tenant statistics retrieved successfully"
// @Failure 400 {object} dto.APIResponse{error=dto.APIError} "Invalid query parameters"
// @Failure 500 {object} dto.APIResponse{error=dto.APIError} "Internal server error"
// @Router /api/v1/tenants/stats [get]
// @Security BearerAuth
func (h *TenantHandler) GetTenantStats(c echo.Context) error {
	req, err := h.parseTenantStatsRequest(c)
	if err != nil {
		return c.JSON(http.StatusBadRequest, dto.APIResponse{
			Success: false,
			Message: "Invalid query parameters",
			Error: &dto.APIError{
				Code:    "INVALID_QUERY_PARAMS",
				Message: "Invalid query parameters",
				Details: err.Error(),
			},
		})
	}

	stats, err := h.tenantService.GetTenantStats(c.Request().Context(), req)
	if err != nil {
		h.logger.Error("Failed to get tenant stats", "error", err)
		return h.handleServiceError(c, err)
	}

	return c.JSON(http.StatusOK, dto.APIResponse{
		Success: true,
		Message: "Tenant statistics retrieved successfully",
		Data:    stats,
	})
}

// GetTenantUserStats godoc
// @Summary Get tenant user statistics
// @Description Retrieve user statistics for a specific tenant
// @Tags Tenants
// @Accept json
// @Produce json
// @Param id path string true "Tenant ID" format(uuid)
// @Success 200 {object} dto.APIResponse{data=dto.TenantUserStatsResponse} "Tenant user statistics retrieved successfully"
// @Failure 400 {object} dto.APIResponse{error=dto.APIError} "Invalid tenant ID"
// @Failure 404 {object} dto.APIResponse{error=dto.APIError} "Tenant not found"
// @Failure 500 {object} dto.APIResponse{error=dto.APIError} "Internal server error"
// @Router /api/v1/tenants/{id}/stats/users [get]
// @Security BearerAuth
func (h *TenantHandler) GetTenantUserStats(c echo.Context) error {
	tenantID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, dto.APIResponse{
			Success: false,
			Message: "Invalid tenant ID",
			Error: &dto.APIError{
				Code:    "INVALID_TENANT_ID",
				Message: "Invalid tenant ID format",
			},
		})
	}

	stats, err := h.tenantService.GetTenantUserStats(c.Request().Context(), tenantID)
	if err != nil {
		h.logger.Error("Failed to get tenant user stats", "tenant_id", tenantID, "error", err)
		return h.handleServiceError(c, err)
	}

	return c.JSON(http.StatusOK, dto.APIResponse{
		Success: true,
		Message: "Tenant user statistics retrieved successfully",
		Data:    stats,
	})
}

// BulkUpdateTenants godoc
// @Summary Bulk update tenants
// @Description Perform bulk operations on multiple tenants
// @Tags Tenants
// @Accept json
// @Produce json
// @Param request body dto.BulkTenantRequest true "Bulk operation request"
// @Success 200 {object} dto.APIResponse{data=dto.BulkOperationResponse} "Bulk operation completed"
// @Failure 400 {object} dto.APIResponse{error=dto.APIError} "Invalid request data"
// @Failure 500 {object} dto.APIResponse{error=dto.APIError} "Internal server error"
// @Router /api/v1/tenants/bulk [post]
// @Security BearerAuth
func (h *TenantHandler) BulkUpdateTenants(c echo.Context) error {
	var req dto.BulkTenantRequest
	if err := c.Bind(&req); err != nil {
		h.logger.Error("Failed to bind bulk update request", "error", err)
		return c.JSON(http.StatusBadRequest, dto.APIResponse{
			Success: false,
			Message: "Invalid request data",
			Error: &dto.APIError{
				Code:    "INVALID_REQUEST",
				Message: "Invalid request data",
				Details: err.Error(),
			},
		})
	}

	if err := c.Validate(&req); err != nil {
		h.logger.Error("Failed to validate bulk update request", "error", err)
		return c.JSON(http.StatusBadRequest, dto.APIResponse{
			Success: false,
			Message: "Validation failed",
			Error: &dto.APIError{
				Code:    "VALIDATION_ERROR",
				Message: "Validation failed",
				Details: err.Error(),
			},
		})
	}

	result, err := h.tenantService.BulkUpdateTenants(c.Request().Context(), &req)
	if err != nil {
		h.logger.Error("Failed to perform bulk update", "error", err)
		return h.handleServiceError(c, err)
	}

	h.logger.Info("Bulk operation completed", "success_count", result.SuccessCount, "failure_count", result.FailureCount)
	return c.JSON(http.StatusOK, dto.APIResponse{
		Success: true,
		Message: "Bulk operation completed",
		Data:    result,
	})
}

// Helper methods
func (h *TenantHandler) parseTenantListRequest(c echo.Context) (*dto.TenantListRequest, error) {
	req := &dto.TenantListRequest{
		Page:  1,
		Limit: 20,
		Sort:  "created_at",
		Order: "desc",
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

	req.Search = c.QueryParam("search")
	req.Status = c.QueryParam("status")
	req.Plan = c.QueryParam("plan")

	return req, nil
}

func (h *TenantHandler) parseTenantStatsRequest(c echo.Context) (*dto.TenantStatsRequest, error) {
	req := &dto.TenantStatsRequest{}

	if dateFrom := c.QueryParam("date_from"); dateFrom != "" {
		req.DateFrom = &dateFrom
	}

	if dateTo := c.QueryParam("date_to"); dateTo != "" {
		req.DateTo = &dateTo
	}

	return req, nil
}

func (h *TenantHandler) handleServiceError(c echo.Context, err error) error {
	// TODO: Implement proper error handling based on error types
	// This is a simplified version
	return c.JSON(http.StatusInternalServerError, dto.APIResponse{
		Success: false,
		Message: "Internal server error",
		Error: &dto.APIError{
			Code:    "INTERNAL_ERROR",
			Message: "An internal error occurred",
		},
	})
}
