package handlers

import (
	"net/http"
	"strconv"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/ducdt2000/azth/backend/internal/modules/user/dto"
	"github.com/ducdt2000/azth/backend/internal/modules/user/service"
	"github.com/ducdt2000/azth/backend/pkg/logger"
)

// UserHandler handles HTTP requests for user operations
type UserHandler struct {
	userService service.UserService
	logger      *logger.Logger
}

// NewUserHandler creates a new user handler
func NewUserHandler(userService service.UserService, logger *logger.Logger) *UserHandler {
	return &UserHandler{
		userService: userService,
		logger:      logger,
	}
}

// CreateUser godoc
// @Summary Create a new user
// @Description Create a new user account with the provided information
// @Tags Users
// @Accept json
// @Produce json
// @Param request body dto.CreateUserRequest true "User creation request"
// @Success 201 {object} dto.APIResponse{data=dto.UserResponse} "User created successfully"
// @Failure 400 {object} dto.APIResponse{error=dto.APIError} "Invalid request data"
// @Failure 409 {object} dto.APIResponse{error=dto.APIError} "Email or username already exists"
// @Failure 500 {object} dto.APIResponse{error=dto.APIError} "Internal server error"
// @Router /api/v1/users [post]
// @Security BearerAuth
func (h *UserHandler) CreateUser(c echo.Context) error {
	var req dto.CreateUserRequest
	if err := c.Bind(&req); err != nil {
		h.logger.Error("Failed to bind create user request", "error", err)
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
		h.logger.Error("Failed to validate create user request", "error", err)
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

	// Extract tenant ID from context (set by middleware)
	tenantID, err := h.getTenantIDFromContext(c)
	if err != nil {
		return c.JSON(http.StatusBadRequest, dto.APIResponse{
			Success: false,
			Message: "Invalid tenant",
			Error: &dto.APIError{
				Code:    "INVALID_TENANT",
				Message: "Invalid tenant",
			},
		})
	}

	user, err := h.userService.CreateUser(c.Request().Context(), &req, tenantID)
	if err != nil {
		h.logger.Error("Failed to create user", "error", err)
		return h.handleServiceError(c, err)
	}

	h.logger.Info("User created successfully", "user_id", user.ID, "email", user.Email)
	return c.JSON(http.StatusCreated, dto.APIResponse{
		Success: true,
		Message: "User created successfully",
		Data:    user,
	})
}

// GetUser godoc
// @Summary Get user by ID
// @Description Retrieve a user by their unique identifier
// @Tags Users
// @Accept json
// @Produce json
// @Param id path string true "User ID" format(uuid)
// @Success 200 {object} dto.APIResponse{data=dto.UserResponse} "User retrieved successfully"
// @Failure 400 {object} dto.APIResponse{error=dto.APIError} "Invalid user ID"
// @Failure 404 {object} dto.APIResponse{error=dto.APIError} "User not found"
// @Failure 500 {object} dto.APIResponse{error=dto.APIError} "Internal server error"
// @Router /api/v1/users/{id} [get]
// @Security BearerAuth
func (h *UserHandler) GetUser(c echo.Context) error {
	userID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, dto.APIResponse{
			Success: false,
			Message: "Invalid user ID",
			Error: &dto.APIError{
				Code:    "INVALID_USER_ID",
				Message: "Invalid user ID format",
			},
		})
	}

	user, err := h.userService.GetUser(c.Request().Context(), userID)
	if err != nil {
		h.logger.Error("Failed to get user", "user_id", userID, "error", err)
		return h.handleServiceError(c, err)
	}

	return c.JSON(http.StatusOK, dto.APIResponse{
		Success: true,
		Message: "User retrieved successfully",
		Data:    user,
	})
}

// UpdateUser godoc
// @Summary Update user
// @Description Update an existing user's information
// @Tags Users
// @Accept json
// @Produce json
// @Param id path string true "User ID" format(uuid)
// @Param request body dto.UpdateUserRequest true "User update request"
// @Success 200 {object} dto.APIResponse{data=dto.UserResponse} "User updated successfully"
// @Failure 400 {object} dto.APIResponse{error=dto.APIError} "Invalid request data"
// @Failure 404 {object} dto.APIResponse{error=dto.APIError} "User not found"
// @Failure 409 {object} dto.APIResponse{error=dto.APIError} "Email or username already exists"
// @Failure 500 {object} dto.APIResponse{error=dto.APIError} "Internal server error"
// @Router /api/v1/users/{id} [put]
// @Security BearerAuth
func (h *UserHandler) UpdateUser(c echo.Context) error {
	userID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, dto.APIResponse{
			Success: false,
			Message: "Invalid user ID",
			Error: &dto.APIError{
				Code:    "INVALID_USER_ID",
				Message: "Invalid user ID format",
			},
		})
	}

	var req dto.UpdateUserRequest
	if err := c.Bind(&req); err != nil {
		h.logger.Error("Failed to bind update user request", "error", err)
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
		h.logger.Error("Failed to validate update user request", "error", err)
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

	user, err := h.userService.UpdateUser(c.Request().Context(), userID, &req)
	if err != nil {
		h.logger.Error("Failed to update user", "user_id", userID, "error", err)
		return h.handleServiceError(c, err)
	}

	h.logger.Info("User updated successfully", "user_id", userID)
	return c.JSON(http.StatusOK, dto.APIResponse{
		Success: true,
		Message: "User updated successfully",
		Data:    user,
	})
}

// DeleteUser godoc
// @Summary Delete user
// @Description Soft delete a user account
// @Tags Users
// @Accept json
// @Produce json
// @Param id path string true "User ID" format(uuid)
// @Success 200 {object} dto.APIResponse "User deleted successfully"
// @Failure 400 {object} dto.APIResponse{error=dto.APIError} "Invalid user ID"
// @Failure 404 {object} dto.APIResponse{error=dto.APIError} "User not found"
// @Failure 500 {object} dto.APIResponse{error=dto.APIError} "Internal server error"
// @Router /api/v1/users/{id} [delete]
// @Security BearerAuth
func (h *UserHandler) DeleteUser(c echo.Context) error {
	userID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, dto.APIResponse{
			Success: false,
			Message: "Invalid user ID",
			Error: &dto.APIError{
				Code:    "INVALID_USER_ID",
				Message: "Invalid user ID format",
			},
		})
	}

	err = h.userService.DeleteUser(c.Request().Context(), userID)
	if err != nil {
		h.logger.Error("Failed to delete user", "user_id", userID, "error", err)
		return h.handleServiceError(c, err)
	}

	h.logger.Info("User deleted successfully", "user_id", userID)
	return c.JSON(http.StatusOK, dto.APIResponse{
		Success: true,
		Message: "User deleted successfully",
	})
}

// ListUsers godoc
// @Summary List users
// @Description Retrieve a paginated list of users with optional filtering
// @Tags Users
// @Accept json
// @Produce json
// @Param page query int false "Page number" default(1) minimum(1)
// @Param limit query int false "Items per page" default(20) minimum(1) maximum(100)
// @Param sort query string false "Sort field" Enums(created_at, updated_at, email, username, first_name, last_name) default(created_at)
// @Param order query string false "Sort order" Enums(asc, desc) default(desc)
// @Param search query string false "Search term (email, username, name)"
// @Param status query string false "Filter by status" Enums(active, inactive, suspended, pending)
// @Param tenant_id query string false "Filter by tenant ID" format(uuid)
// @Success 200 {object} dto.APIResponse{data=dto.UserListResponse} "Users retrieved successfully"
// @Failure 400 {object} dto.APIResponse{error=dto.APIError} "Invalid query parameters"
// @Failure 500 {object} dto.APIResponse{error=dto.APIError} "Internal server error"
// @Router /api/v1/users [get]
// @Security BearerAuth
func (h *UserHandler) ListUsers(c echo.Context) error {
	req, err := h.parseUserListRequest(c)
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

	users, err := h.userService.ListUsers(c.Request().Context(), req)
	if err != nil {
		h.logger.Error("Failed to list users", "error", err)
		return h.handleServiceError(c, err)
	}

	return c.JSON(http.StatusOK, dto.APIResponse{
		Success: true,
		Message: "Users retrieved successfully",
		Data:    users,
	})
}

// ChangePassword godoc
// @Summary Change user password
// @Description Change a user's password with current password verification
// @Tags Users
// @Accept json
// @Produce json
// @Param id path string true "User ID" format(uuid)
// @Param request body dto.ChangePasswordRequest true "Password change request"
// @Success 200 {object} dto.APIResponse "Password changed successfully"
// @Failure 400 {object} dto.APIResponse{error=dto.APIError} "Invalid request data"
// @Failure 401 {object} dto.APIResponse{error=dto.APIError} "Current password is incorrect"
// @Failure 404 {object} dto.APIResponse{error=dto.APIError} "User not found"
// @Failure 500 {object} dto.APIResponse{error=dto.APIError} "Internal server error"
// @Router /api/v1/users/{id}/password [put]
// @Security BearerAuth
func (h *UserHandler) ChangePassword(c echo.Context) error {
	userID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, dto.APIResponse{
			Success: false,
			Message: "Invalid user ID",
			Error: &dto.APIError{
				Code:    "INVALID_USER_ID",
				Message: "Invalid user ID format",
			},
		})
	}

	var req dto.ChangePasswordRequest
	if err := c.Bind(&req); err != nil {
		h.logger.Error("Failed to bind change password request", "error", err)
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
		h.logger.Error("Failed to validate change password request", "error", err)
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

	err = h.userService.ChangePassword(c.Request().Context(), userID, &req)
	if err != nil {
		h.logger.Error("Failed to change password", "user_id", userID, "error", err)
		return h.handleServiceError(c, err)
	}

	h.logger.Info("Password changed successfully", "user_id", userID)
	return c.JSON(http.StatusOK, dto.APIResponse{
		Success: true,
		Message: "Password changed successfully",
	})
}

// GetUserStats godoc
// @Summary Get user statistics
// @Description Retrieve user statistics with optional filtering
// @Tags Users
// @Accept json
// @Produce json
// @Param tenant_id query string false "Filter by tenant ID" format(uuid)
// @Param date_from query string false "Start date for statistics" format(date)
// @Param date_to query string false "End date for statistics" format(date)
// @Success 200 {object} dto.APIResponse{data=dto.UserStatsResponse} "User statistics retrieved successfully"
// @Failure 400 {object} dto.APIResponse{error=dto.APIError} "Invalid query parameters"
// @Failure 500 {object} dto.APIResponse{error=dto.APIError} "Internal server error"
// @Router /api/v1/users/stats [get]
// @Security BearerAuth
func (h *UserHandler) GetUserStats(c echo.Context) error {
	req, err := h.parseUserStatsRequest(c)
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

	stats, err := h.userService.GetUserStats(c.Request().Context(), req)
	if err != nil {
		h.logger.Error("Failed to get user stats", "error", err)
		return h.handleServiceError(c, err)
	}

	return c.JSON(http.StatusOK, dto.APIResponse{
		Success: true,
		Message: "User statistics retrieved successfully",
		Data:    stats,
	})
}

// BulkUpdateUsers godoc
// @Summary Bulk update users
// @Description Perform bulk operations on multiple users
// @Tags Users
// @Accept json
// @Produce json
// @Param request body dto.BulkUserRequest true "Bulk operation request"
// @Success 200 {object} dto.APIResponse{data=dto.BulkOperationResponse} "Bulk operation completed"
// @Failure 400 {object} dto.APIResponse{error=dto.APIError} "Invalid request data"
// @Failure 500 {object} dto.APIResponse{error=dto.APIError} "Internal server error"
// @Router /api/v1/users/bulk [post]
// @Security BearerAuth
func (h *UserHandler) BulkUpdateUsers(c echo.Context) error {
	var req dto.BulkUserRequest
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

	result, err := h.userService.BulkUpdateUsers(c.Request().Context(), &req)
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
func (h *UserHandler) getTenantIDFromContext(c echo.Context) (uuid.UUID, error) {
	// This would typically be set by authentication middleware
	tenantIDStr := c.Get("tenant_id")
	if tenantIDStr == nil {
		return uuid.Nil, echo.NewHTTPError(http.StatusBadRequest, "tenant ID not found in context")
	}
	return uuid.Parse(tenantIDStr.(string))
}

func (h *UserHandler) parseUserListRequest(c echo.Context) (*dto.UserListRequest, error) {
	req := &dto.UserListRequest{
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
	req.TenantID = c.QueryParam("tenant_id")

	return req, nil
}

func (h *UserHandler) parseUserStatsRequest(c echo.Context) (*dto.UserStatsRequest, error) {
	req := &dto.UserStatsRequest{}

	if tenantIDStr := c.QueryParam("tenant_id"); tenantIDStr != "" {
		if tenantID, err := uuid.Parse(tenantIDStr); err == nil {
			req.TenantID = &tenantID
		}
	}

	if dateFrom := c.QueryParam("date_from"); dateFrom != "" {
		req.DateFrom = &dateFrom
	}

	if dateTo := c.QueryParam("date_to"); dateTo != "" {
		req.DateTo = &dateTo
	}

	return req, nil
}

func (h *UserHandler) handleServiceError(c echo.Context, err error) error {
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
