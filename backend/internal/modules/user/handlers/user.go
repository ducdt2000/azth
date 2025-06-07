package handlers

import (
	"fmt"
	"strconv"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/ducdt2000/azth/backend/internal/modules/user/dto"
	"github.com/ducdt2000/azth/backend/internal/modules/user/service"
	"github.com/ducdt2000/azth/backend/pkg/logger"
	"github.com/ducdt2000/azth/backend/pkg/response"
)

// UserHandlerV2 demonstrates the new response system
type UserHandlerV2 struct {
	userService service.UserService
	logger      *logger.Logger
	response    *response.ResponseBuilder
}

// NewUserHandlerV2 creates a new user handler with response builder
func NewUserHandlerV2(
	userService service.UserService,
	logger *logger.Logger,
	responseBuilder *response.ResponseBuilder,
) *UserHandlerV2 {
	return &UserHandlerV2{
		userService: userService,
		logger:      logger,
		response:    responseBuilder,
	}
}

// CreateUser godoc
// @Summary Create a new user
// @Description Create a new user account with the provided information
// @Tags Users
// @Accept json
// @Produce json
// @Param request body dto.CreateUserRequest true "User creation request"
// @Success 201 {object} response.Response{data=dto.UserResponse} "User created successfully"
// @Failure 400 {object} response.Response{error=response.ErrorInfo} "Invalid request data"
// @Failure 409 {object} response.Response{error=response.ErrorInfo} "Email or username already exists"
// @Failure 500 {object} response.Response{error=response.ErrorInfo} "Internal server error"
// @Router /api/v1/users [post]
// @Security BearerAuth
func (h *UserHandlerV2) CreateUser(c echo.Context) error {
	var req dto.CreateUserRequest
	if err := c.Bind(&req); err != nil {
		h.logger.Error("Failed to bind create user request", "error", err)
		return h.response.ValidationError(c, map[string]interface{}{
			"field": "request_body",
			"error": err.Error(),
		})
	}

	if err := c.Validate(&req); err != nil {
		h.logger.Error("Failed to validate create user request", "error", err)
		return h.response.ValidationError(c, map[string]interface{}{
			"field": "validation",
			"error": err.Error(),
		})
	}

	// Extract tenant ID from context (set by middleware)
	tenantID, err := h.getTenantIDFromContext(c)
	if err != nil {
		return h.response.BadRequest(c, response.TENANT_INVALID_ID, nil)
	}

	user, err := h.userService.CreateUser(c.Request().Context(), &req, tenantID)
	if err != nil {
		h.logger.Error("Failed to create user", "error", err)
		return h.response.UserServiceError(c, err)
	}

	h.logger.Info("User created successfully", "user_id", user.ID, "email", user.Email)

	// Create location header for the created resource
	location := "/api/v1/users/" + user.ID.String()
	return h.response.CreatedWithLocation(c, response.USER_CREATED, user, location)
}

// GetUser godoc
// @Summary Get user by ID
// @Description Retrieve a user by their unique identifier
// @Tags Users
// @Accept json
// @Produce json
// @Param id path string true "User ID" format(uuid)
// @Success 200 {object} response.Response{data=dto.UserResponse} "User retrieved successfully"
// @Failure 400 {object} response.Response{error=response.ErrorInfo} "Invalid user ID"
// @Failure 404 {object} response.Response{error=response.ErrorInfo} "User not found"
// @Failure 500 {object} response.Response{error=response.ErrorInfo} "Internal server error"
// @Router /api/v1/users/{id} [get]
// @Security BearerAuth
func (h *UserHandlerV2) GetUser(c echo.Context) error {
	userID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return h.response.BadRequest(c, response.USER_INVALID_ID, map[string]interface{}{
			"provided_id": c.Param("id"),
		})
	}

	user, err := h.userService.GetUser(c.Request().Context(), userID)
	if err != nil {
		h.logger.Error("Failed to get user", "user_id", userID, "error", err)
		return h.response.UserServiceError(c, err)
	}

	// Add request metadata
	requestID := response.GetRequestID(c)
	meta := h.response.WithRequestID(requestID)

	return h.response.Success(c, response.USER_RETRIEVED, user, meta)
}

// ListUsers godoc
// @Summary List users with pagination
// @Description Retrieve a paginated list of users
// @Tags Users
// @Accept json
// @Produce json
// @Param page query int false "Page number" default(1)
// @Param limit query int false "Items per page" default(20)
// @Param search query string false "Search term"
// @Success 200 {object} response.Response{data=dto.UserListResponse} "Users retrieved successfully"
// @Failure 400 {object} response.Response{error=response.ErrorInfo} "Invalid request parameters"
// @Failure 500 {object} response.Response{error=response.ErrorInfo} "Internal server error"
// @Router /api/v1/users [get]
// @Security BearerAuth
func (h *UserHandlerV2) ListUsers(c echo.Context) error {
	req, err := h.parseUserListRequest(c)
	if err != nil {
		return h.response.ValidationError(c, map[string]interface{}{
			"field": "query_parameters",
			"error": err.Error(),
		})
	}

	userListResponse, err := h.userService.ListUsers(c.Request().Context(), req)
	if err != nil {
		h.logger.Error("Failed to list users", "error", err)
		return h.response.UserServiceError(c, err)
	}

	// Create pagination metadata from the response
	pagination := response.NewPaginationMeta(
		userListResponse.Pagination.Page,
		userListResponse.Pagination.Limit,
		userListResponse.Pagination.Total,
	)

	return h.response.SuccessWithPagination(c, response.USERS_LISTED, userListResponse, pagination)
}

// UpdateUser godoc
// @Summary Update user
// @Description Update an existing user's information
// @Tags Users
// @Accept json
// @Produce json
// @Param id path string true "User ID" format(uuid)
// @Param request body dto.UpdateUserRequest true "User update request"
// @Success 200 {object} response.Response{data=dto.UserResponse} "User updated successfully"
// @Failure 400 {object} response.Response{error=response.ErrorInfo} "Invalid request data"
// @Failure 404 {object} response.Response{error=response.ErrorInfo} "User not found"
// @Failure 409 {object} response.Response{error=response.ErrorInfo} "Email or username already exists"
// @Failure 500 {object} response.Response{error=response.ErrorInfo} "Internal server error"
// @Router /api/v1/users/{id} [put]
// @Security BearerAuth
func (h *UserHandlerV2) UpdateUser(c echo.Context) error {
	userID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return h.response.BadRequest(c, response.USER_INVALID_ID, map[string]interface{}{
			"provided_id": c.Param("id"),
		})
	}

	var req dto.UpdateUserRequest
	if err := c.Bind(&req); err != nil {
		h.logger.Error("Failed to bind update user request", "error", err)
		return h.response.ValidationError(c, map[string]interface{}{
			"field": "request_body",
			"error": err.Error(),
		})
	}

	if err := c.Validate(&req); err != nil {
		h.logger.Error("Failed to validate update user request", "error", err)
		return h.response.ValidationError(c, map[string]interface{}{
			"field": "validation",
			"error": err.Error(),
		})
	}

	user, err := h.userService.UpdateUser(c.Request().Context(), userID, &req)
	if err != nil {
		h.logger.Error("Failed to update user", "user_id", userID, "error", err)
		return h.response.UserServiceError(c, err)
	}

	h.logger.Info("User updated successfully", "user_id", userID)

	// Add metadata with request ID and version
	requestID := response.GetRequestID(c)
	meta := h.response.WithMeta(requestID, "v1", nil)

	return h.response.Success(c, response.USER_UPDATED, user, meta)
}

// DeleteUser godoc
// @Summary Delete user
// @Description Delete an existing user
// @Tags Users
// @Accept json
// @Produce json
// @Param id path string true "User ID" format(uuid)
// @Success 200 {object} response.Response "User deleted successfully"
// @Failure 400 {object} response.Response{error=response.ErrorInfo} "Invalid user ID"
// @Failure 404 {object} response.Response{error=response.ErrorInfo} "User not found"
// @Failure 500 {object} response.Response{error=response.ErrorInfo} "Internal server error"
// @Router /api/v1/users/{id} [delete]
// @Security BearerAuth
func (h *UserHandlerV2) DeleteUser(c echo.Context) error {
	userID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return h.response.BadRequest(c, response.USER_INVALID_ID, map[string]interface{}{
			"provided_id": c.Param("id"),
		})
	}

	err = h.userService.DeleteUser(c.Request().Context(), userID)
	if err != nil {
		h.logger.Error("Failed to delete user", "user_id", userID, "error", err)
		return h.response.UserServiceError(c, err)
	}

	h.logger.Info("User deleted successfully", "user_id", userID)
	return h.response.Success(c, response.USER_DELETED, map[string]interface{}{
		"user_id": userID,
	})
}

// Helper methods (same as original but with better error handling)
func (h *UserHandlerV2) getTenantIDFromContext(c echo.Context) (uuid.UUID, error) {
	tenantIDStr, ok := c.Get("tenant_id").(string)
	if !ok {
		return uuid.Nil, fmt.Errorf("tenant ID not found in context")
	}
	return uuid.Parse(tenantIDStr)
}

func (h *UserHandlerV2) parseUserListRequest(c echo.Context) (*dto.UserListRequest, error) {
	req := &dto.UserListRequest{
		Page:  1,
		Limit: 20,
	}

	if pageStr := c.QueryParam("page"); pageStr != "" {
		if page, err := strconv.Atoi(pageStr); err == nil && page > 0 {
			req.Page = page
		}
	}

	if limitStr := c.QueryParam("limit"); limitStr != "" {
		if limit, err := strconv.Atoi(limitStr); err == nil && limit > 0 && limit <= 100 {
			req.Limit = limit
		}
	}

	req.Search = c.QueryParam("search")
	req.Sort = c.QueryParam("sort")
	req.Order = c.QueryParam("order")
	req.Status = c.QueryParam("status")
	req.TenantID = c.QueryParam("tenant_id")

	return req, nil
}
