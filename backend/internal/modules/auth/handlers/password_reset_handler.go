package handlers

import (
	"github.com/ducdt2000/azth/backend/internal/modules/auth/dto"
	"github.com/ducdt2000/azth/backend/internal/modules/auth/service"
	"github.com/ducdt2000/azth/backend/pkg/response"
	"github.com/ducdt2000/azth/backend/pkg/validator"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

// PasswordResetHandler handles password reset related HTTP requests
type PasswordResetHandler struct {
	authService service.AuthService
	response    *response.ResponseBuilder
	validator   *validator.CustomValidator
}

// NewPasswordResetHandler creates a new password reset handler
func NewPasswordResetHandler(
	authService service.AuthService,
	response *response.ResponseBuilder,
	validator *validator.CustomValidator,
) *PasswordResetHandler {
	return &PasswordResetHandler{
		authService: authService,
		response:    response,
		validator:   validator,
	}
}

// RequestPasswordReset handles password reset requests
// @Summary Request password reset
// @Description Initiates a password reset process by sending a reset code to the user's email
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body dto.RequestPasswordResetRequest true "Password reset request"
// @Success 200 {object} dto.RequestPasswordResetResponse
// @Failure 400 {object} response.Response
// @Failure 429 {object} response.Response "Too many requests"
// @Failure 500 {object} response.Response
// @Router /api/v1/auth/password/reset/request [post]
func (h *PasswordResetHandler) RequestPasswordReset(c echo.Context) error {
	var req dto.RequestPasswordResetRequest

	// Bind request
	if err := c.Bind(&req); err != nil {
		return h.response.BadRequest(c, response.REQUEST_BODY_INVALID, map[string]interface{}{
			"error": err.Error(),
		})
	}

	// Set IP and User Agent
	req.IPAddress = c.RealIP()
	req.UserAgent = c.Request().UserAgent()

	// Validate request
	if err := h.validator.Validate(&req); err != nil {
		return h.response.BadRequest(c, response.VALIDATION_FAILED, err)
	}

	// Process password reset request
	result, err := h.authService.RequestPasswordReset(c.Request().Context(), &req)
	if err != nil {
		return h.response.ServiceError(c, err)
	}

	return h.response.Success(c, response.SUCCESS, result)
}

// ConfirmPasswordReset handles password reset confirmation
// @Summary Confirm password reset
// @Description Confirms a password reset using the provided token and sets a new password
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body dto.ConfirmPasswordResetRequest true "Password reset confirmation"
// @Success 200 {object} dto.ConfirmPasswordResetResponse
// @Failure 400 {object} response.Response
// @Failure 404 {object} response.Response "Invalid or expired token"
// @Failure 500 {object} response.Response
// @Router /api/v1/auth/password/reset/confirm [post]
func (h *PasswordResetHandler) ConfirmPasswordReset(c echo.Context) error {
	var req dto.ConfirmPasswordResetRequest

	// Bind request
	if err := c.Bind(&req); err != nil {
		return h.response.BadRequest(c, response.REQUEST_BODY_INVALID, map[string]interface{}{
			"error": err.Error(),
		})
	}

	// Set IP and User Agent
	req.IPAddress = c.RealIP()
	req.UserAgent = c.Request().UserAgent()

	// Validate request
	if err := h.validator.Validate(&req); err != nil {
		return h.response.BadRequest(c, response.VALIDATION_FAILED, err)
	}

	// Process password reset confirmation
	result, err := h.authService.ConfirmPasswordReset(c.Request().Context(), &req)
	if err != nil {
		return h.response.ServiceError(c, err)
	}

	if !result.Success {
		return h.response.BadRequest(c, response.BAD_REQUEST, result)
	}

	return h.response.Success(c, response.SUCCESS, result)
}

// UpdatePassword handles password updates for authenticated users
// @Summary Update password
// @Description Updates the password for an authenticated user
// @Tags Authentication
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body dto.UpdatePasswordRequest true "Password update request"
// @Success 200 {object} dto.UpdatePasswordResponse
// @Failure 400 {object} response.Response
// @Failure 401 {object} response.Response "Unauthorized"
// @Failure 403 {object} response.Response "MFA required"
// @Failure 500 {object} response.Response
// @Router /api/v1/auth/password/update [put]
func (h *PasswordResetHandler) UpdatePassword(c echo.Context) error {
	var req dto.UpdatePasswordRequest

	// Get user ID from context (set by auth middleware)
	userID, ok := c.Get("user_id").(uuid.UUID)
	if !ok {
		return h.response.Unauthorized(c, response.UNAUTHORIZED, nil)
	}

	// Bind request
	if err := c.Bind(&req); err != nil {
		return h.response.BadRequest(c, response.REQUEST_BODY_INVALID, map[string]interface{}{
			"error": err.Error(),
		})
	}

	// Set IP and User Agent
	req.IPAddress = c.RealIP()
	req.UserAgent = c.Request().UserAgent()

	// Validate request
	if err := h.validator.Validate(&req); err != nil {
		return h.response.BadRequest(c, response.VALIDATION_FAILED, err)
	}

	// Process password update
	result, err := h.authService.UpdatePassword(c.Request().Context(), userID, &req)
	if err != nil {
		return h.response.ServiceError(c, err)
	}

	if !result.Success {
		if result.RequiresMFA {
			return h.response.Forbidden(c, response.AUTH_MFA_REQUIRED, result)
		}
		return h.response.BadRequest(c, response.BAD_REQUEST, result)
	}

	return h.response.Success(c, response.USER_PASSWORD_CHANGED, result)
}
