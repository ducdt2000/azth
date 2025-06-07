package handlers

import (
	"strings"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"

	"github.com/ducdt2000/azth/backend/internal/modules/auth/dto"
	"github.com/ducdt2000/azth/backend/internal/modules/auth/service"
	"github.com/ducdt2000/azth/backend/pkg/response"
	"github.com/ducdt2000/azth/backend/pkg/validator"
)

// AuthHandler handles authentication HTTP requests
type AuthHandler struct {
	authService service.AuthService
	validator   *validator.CustomValidator
	tracer      trace.Tracer
	response    *response.ResponseBuilder
}

// NewAuthHandler creates a new authentication handler
func NewAuthHandler(
	authService service.AuthService,
	validator *validator.CustomValidator,
	responseBuilder *response.ResponseBuilder,
) *AuthHandler {
	return &AuthHandler{
		authService: authService,
		validator:   validator,
		tracer:      otel.Tracer("auth-handler"),
		response:    responseBuilder,
	}
}

// Login handles user login
// @Summary Login user
// @Description Authenticate user with email and password
// @Tags auth
// @Accept json
// @Produce json
// @Param request body dto.LoginRequest true "Login request"
// @Success 200 {object} response.Response{data=dto.LoginResponse} "Login successful"
// @Failure 400 {object} response.Response{error=response.ErrorInfo} "Bad request"
// @Failure 401 {object} response.Response{error=response.ErrorInfo} "Unauthorized"
// @Failure 423 {object} response.Response{error=response.ErrorInfo} "Account locked"
// @Failure 500 {object} response.Response{error=response.ErrorInfo} "Internal server error"
// @Router /auth/login [post]
func (h *AuthHandler) Login(c echo.Context) error {
	ctx, span := h.tracer.Start(c.Request().Context(), "auth.handler.Login")
	defer span.End()

	var req dto.LoginRequest
	if err := c.Bind(&req); err != nil {
		span.RecordError(err)
		return h.response.ValidationError(c, map[string]interface{}{
			"field": "request_body",
			"error": err.Error(),
		})
	}

	// Add IP address and user agent to request
	req.IPAddress = h.getClientIP(c)
	req.UserAgent = c.Request().UserAgent()

	// Validate request
	if err := h.validator.Validate(&req); err != nil {
		span.RecordError(err)
		return h.response.ValidationError(c, map[string]interface{}{
			"field": "validation",
			"error": err.Error(),
		})
	}

	// Perform login
	loginResponse, err := h.authService.Login(ctx, &req)
	if err != nil {
		span.RecordError(err)
		return h.response.AuthServiceError(c, err)
	}

	// Add request metadata
	requestID := response.GetRequestID(c)
	meta := h.response.WithRequestID(requestID)

	span.AddEvent("login successful")
	return h.response.Success(c, response.AUTH_LOGIN_SUCCESS, loginResponse, meta)
}

// RefreshToken handles token refresh
// @Summary Refresh access token
// @Description Refresh an expired access token using refresh token
// @Tags auth
// @Accept json
// @Produce json
// @Param request body dto.RefreshRequest true "Refresh request"
// @Success 200 {object} response.Response{data=dto.RefreshResponse} "Token refreshed"
// @Failure 400 {object} response.Response{error=response.ErrorInfo} "Bad request"
// @Failure 401 {object} response.Response{error=response.ErrorInfo} "Invalid refresh token"
// @Failure 500 {object} response.Response{error=response.ErrorInfo} "Internal server error"
// @Router /auth/refresh [post]
func (h *AuthHandler) RefreshToken(c echo.Context) error {
	ctx, span := h.tracer.Start(c.Request().Context(), "auth.handler.RefreshToken")
	defer span.End()

	var req dto.RefreshRequest
	if err := c.Bind(&req); err != nil {
		span.RecordError(err)
		return h.response.ValidationError(c, map[string]interface{}{
			"field": "request_body",
			"error": err.Error(),
		})
	}

	// Add IP address and user agent to request
	req.IPAddress = h.getClientIP(c)
	req.UserAgent = c.Request().UserAgent()

	// Validate request
	if err := h.validator.Validate(&req); err != nil {
		span.RecordError(err)
		return h.response.ValidationError(c, map[string]interface{}{
			"field": "validation",
			"error": err.Error(),
		})
	}

	// Refresh token
	refreshResponse, err := h.authService.RefreshToken(ctx, req.RefreshToken)
	if err != nil {
		span.RecordError(err)
		return h.response.AuthServiceError(c, err)
	}

	// Add request metadata
	requestID := response.GetRequestID(c)
	meta := h.response.WithRequestID(requestID)

	span.AddEvent("token refreshed successfully")
	return h.response.Success(c, response.AUTH_TOKEN_REFRESHED, refreshResponse, meta)
}

// Logout handles user logout
// @Summary Logout user
// @Description Logout user and revoke session
// @Tags auth
// @Accept json
// @Produce json
// @Param request body dto.LogoutRequest true "Logout request"
// @Security BearerAuth
// @Success 200 {object} response.Response "Logout successful"
// @Failure 400 {object} response.Response{error=response.ErrorInfo} "Bad request"
// @Failure 401 {object} response.Response{error=response.ErrorInfo} "Unauthorized"
// @Failure 500 {object} response.Response{error=response.ErrorInfo} "Internal server error"
// @Router /auth/logout [post]
func (h *AuthHandler) Logout(c echo.Context) error {
	ctx, span := h.tracer.Start(c.Request().Context(), "auth.handler.Logout")
	defer span.End()

	// Extract token from header
	token := h.extractTokenFromHeader(c)
	if token == "" {
		span.AddEvent("no token provided")
		return h.response.Unauthorized(c, response.AUTH_TOKEN_MISSING, nil)
	}

	var req dto.LogoutRequest
	if err := c.Bind(&req); err != nil {
		// Default to single session logout if no body
		req.All = false
	}

	if req.All {
		// Get user ID from session first
		session, err := h.authService.GetSession(ctx, token)
		if err != nil {
			span.RecordError(err)
			return h.response.AuthServiceError(c, err)
		}

		// Logout from all sessions
		if err := h.authService.LogoutAll(ctx, session.UserID); err != nil {
			span.RecordError(err)
			return h.response.AuthServiceError(c, err)
		}
	} else {
		// Logout from current session only
		if err := h.authService.Logout(ctx, token); err != nil {
			span.RecordError(err)
			return h.response.AuthServiceError(c, err)
		}
	}

	span.AddEvent("logout successful")
	return h.response.Success(c, response.AUTH_LOGOUT_SUCCESS, map[string]interface{}{
		"all_sessions": req.All,
	})
}

// GetSessions retrieves user sessions
// @Summary Get user sessions
// @Description Get all active sessions for the authenticated user
// @Tags auth
// @Produce json
// @Security BearerAuth
// @Success 200 {object} response.Response{data=[]dto.SessionResponse} "Sessions retrieved successfully"
// @Failure 401 {object} response.Response{error=response.ErrorInfo} "Unauthorized"
// @Failure 500 {object} response.Response{error=response.ErrorInfo} "Internal server error"
// @Router /auth/sessions [get]
func (h *AuthHandler) GetSessions(c echo.Context) error {
	ctx, span := h.tracer.Start(c.Request().Context(), "auth.handler.GetSessions")
	defer span.End()

	// Extract token from header
	token := h.extractTokenFromHeader(c)
	if token == "" {
		span.AddEvent("no token provided")
		return h.response.Unauthorized(c, response.AUTH_TOKEN_MISSING, nil)
	}

	// Get session to extract user ID
	session, err := h.authService.GetSession(ctx, token)
	if err != nil {
		span.RecordError(err)
		return h.response.AuthServiceError(c, err)
	}

	// Get all user sessions
	sessions, err := h.authService.GetUserSessions(ctx, session.UserID)
	if err != nil {
		span.RecordError(err)
		return h.response.AuthServiceError(c, err)
	}

	// Add request metadata
	requestID := response.GetRequestID(c)
	meta := h.response.WithRequestID(requestID)

	span.AddEvent("sessions retrieved successfully")
	return h.response.Success(c, response.AUTH_SESSIONS_LISTED, sessions, meta)
}

// RevokeSession revokes a specific session
// @Summary Revoke session
// @Description Revoke a specific user session by ID
// @Tags auth
// @Param id path string true "Session ID" format(uuid)
// @Security BearerAuth
// @Success 200 {object} response.Response "Session revoked successfully"
// @Failure 400 {object} response.Response{error=response.ErrorInfo} "Invalid session ID"
// @Failure 401 {object} response.Response{error=response.ErrorInfo} "Unauthorized"
// @Failure 404 {object} response.Response{error=response.ErrorInfo} "Session not found"
// @Failure 500 {object} response.Response{error=response.ErrorInfo} "Internal server error"
// @Router /auth/sessions/{id} [delete]
func (h *AuthHandler) RevokeSession(c echo.Context) error {
	ctx, span := h.tracer.Start(c.Request().Context(), "auth.handler.RevokeSession")
	defer span.End()

	// Extract token from header
	token := h.extractTokenFromHeader(c)
	if token == "" {
		span.AddEvent("no token provided")
		return h.response.Unauthorized(c, response.AUTH_TOKEN_MISSING, nil)
	}

	// Parse session ID
	sessionIDStr := c.Param("id")
	sessionID, err := uuid.Parse(sessionIDStr)
	if err != nil {
		return h.response.BadRequest(c, response.REQUEST_PARAM_INVALID, map[string]interface{}{
			"param":    "id",
			"provided": sessionIDStr,
		})
	}

	// Revoke session
	if err := h.authService.RevokeSession(ctx, sessionID, "user_revoke"); err != nil {
		span.RecordError(err)
		return h.response.AuthServiceError(c, err)
	}

	span.AddEvent("session revoked successfully")
	return h.response.Success(c, response.AUTH_SESSION_REVOKED, map[string]interface{}{
		"session_id": sessionID,
	})
}

// LogoutAll handles logout from all sessions
// @Summary Logout from all sessions
// @Description Logout user from all active sessions
// @Tags auth
// @Security BearerAuth
// @Success 200 {object} response.Response "Logged out from all sessions"
// @Failure 401 {object} response.Response{error=response.ErrorInfo} "Unauthorized"
// @Failure 500 {object} response.Response{error=response.ErrorInfo} "Internal server error"
// @Router /auth/sessions [delete]
func (h *AuthHandler) LogoutAll(c echo.Context) error {
	ctx, span := h.tracer.Start(c.Request().Context(), "auth.handler.LogoutAll")
	defer span.End()

	// Extract token from header
	token := h.extractTokenFromHeader(c)
	if token == "" {
		span.AddEvent("no token provided")
		return h.response.Unauthorized(c, response.AUTH_TOKEN_MISSING, nil)
	}

	// Get session to extract user ID
	session, err := h.authService.GetSession(ctx, token)
	if err != nil {
		span.RecordError(err)
		return h.response.AuthServiceError(c, err)
	}

	// Logout from all sessions
	if err := h.authService.LogoutAll(ctx, session.UserID); err != nil {
		span.RecordError(err)
		return h.response.AuthServiceError(c, err)
	}

	span.AddEvent("logout from all sessions successful")
	return h.response.Success(c, response.AUTH_LOGOUT_SUCCESS, map[string]interface{}{
		"all_sessions": true,
	})
}

// EnableMFA enables multi-factor authentication
// @Summary Enable MFA
// @Description Enable multi-factor authentication for the user
// @Tags auth
// @Produce json
// @Security BearerAuth
// @Success 200 {object} response.Response{data=dto.MFAEnableResponse} "MFA enabled successfully"
// @Failure 401 {object} response.Response{error=response.ErrorInfo} "Unauthorized"
// @Failure 500 {object} response.Response{error=response.ErrorInfo} "Internal server error"
// @Router /auth/mfa/enable [post]
func (h *AuthHandler) EnableMFA(c echo.Context) error {
	ctx, span := h.tracer.Start(c.Request().Context(), "auth.handler.EnableMFA")
	defer span.End()

	// Extract token and get session
	token := h.extractTokenFromHeader(c)
	if token == "" {
		span.AddEvent("no token provided")
		return h.response.Unauthorized(c, response.AUTH_TOKEN_MISSING, nil)
	}

	session, err := h.authService.ValidateSession(ctx, token)
	if err != nil {
		span.RecordError(err)
		return h.response.AuthServiceError(c, err)
	}

	// Enable MFA
	mfaResponse, err := h.authService.EnableMFA(ctx, session.UserID)
	if err != nil {
		span.RecordError(err)
		return h.response.AuthServiceError(c, err)
	}

	// Add request metadata
	requestID := response.GetRequestID(c)
	meta := h.response.WithRequestID(requestID)

	span.AddEvent("MFA enabled successfully")
	return h.response.Success(c, response.AUTH_MFA_ENABLED, mfaResponse, meta)
}

// DisableMFA disables multi-factor authentication
// @Summary Disable MFA
// @Description Disable multi-factor authentication for the user
// @Tags auth
// @Security BearerAuth
// @Success 200 {object} response.Response "MFA disabled successfully"
// @Failure 401 {object} response.Response{error=response.ErrorInfo} "Unauthorized"
// @Failure 500 {object} response.Response{error=response.ErrorInfo} "Internal server error"
// @Router /auth/mfa/disable [delete]
func (h *AuthHandler) DisableMFA(c echo.Context) error {
	ctx, span := h.tracer.Start(c.Request().Context(), "auth.handler.DisableMFA")
	defer span.End()

	// Extract token and get session
	token := h.extractTokenFromHeader(c)
	if token == "" {
		span.AddEvent("no token provided")
		return h.response.Unauthorized(c, response.AUTH_TOKEN_MISSING, nil)
	}

	session, err := h.authService.ValidateSession(ctx, token)
	if err != nil {
		span.RecordError(err)
		return h.response.AuthServiceError(c, err)
	}

	// Disable MFA
	if err := h.authService.DisableMFA(ctx, session.UserID); err != nil {
		span.RecordError(err)
		return h.response.AuthServiceError(c, err)
	}

	span.AddEvent("MFA disabled successfully")
	return h.response.Success(c, response.AUTH_MFA_DISABLED, map[string]interface{}{
		"user_id": session.UserID,
	})
}

// ValidateMFA validates MFA code
// @Summary Validate MFA code
// @Description Validate multi-factor authentication code
// @Tags auth
// @Accept json
// @Produce json
// @Param request body dto.MFAValidateRequest true "MFA validation request"
// @Security BearerAuth
// @Success 200 {object} response.Response{data=map[string]bool} "MFA validation result"
// @Failure 400 {object} response.Response{error=response.ErrorInfo} "Bad request"
// @Failure 401 {object} response.Response{error=response.ErrorInfo} "Unauthorized"
// @Failure 500 {object} response.Response{error=response.ErrorInfo} "Internal server error"
// @Router /auth/mfa/validate [post]
func (h *AuthHandler) ValidateMFA(c echo.Context) error {
	ctx, span := h.tracer.Start(c.Request().Context(), "auth.handler.ValidateMFA")
	defer span.End()

	var req dto.MFAValidateRequest
	if err := c.Bind(&req); err != nil {
		span.RecordError(err)
		return h.response.ValidationError(c, map[string]interface{}{
			"field": "request_body",
			"error": err.Error(),
		})
	}

	// Validate request
	if err := h.validator.Validate(&req); err != nil {
		span.RecordError(err)
		return h.response.ValidationError(c, map[string]interface{}{
			"field": "validation",
			"error": err.Error(),
		})
	}

	// Validate MFA
	valid, err := h.authService.ValidateMFA(ctx, req.UserID, req.Code)
	if err != nil {
		span.RecordError(err)
		return h.response.AuthServiceError(c, err)
	}

	responseCode := response.AUTH_MFA_VALIDATED
	if !valid {
		responseCode = response.AUTH_MFA_INVALID_CODE
	}

	// Add request metadata
	requestID := response.GetRequestID(c)
	meta := h.response.WithRequestID(requestID)

	span.AddEvent("MFA validation completed")
	return h.response.Success(c, responseCode, map[string]interface{}{
		"valid": valid,
	}, meta)
}

// GenerateBackupCodes generates new backup codes
// @Summary Generate backup codes
// @Description Generate new backup codes for MFA
// @Tags auth
// @Produce json
// @Security BearerAuth
// @Success 200 {object} response.Response{data=map[string][]string} "Backup codes generated"
// @Failure 401 {object} response.Response{error=response.ErrorInfo} "Unauthorized"
// @Failure 500 {object} response.Response{error=response.ErrorInfo} "Internal server error"
// @Router /auth/mfa/backup-codes [post]
func (h *AuthHandler) GenerateBackupCodes(c echo.Context) error {
	ctx, span := h.tracer.Start(c.Request().Context(), "auth.handler.GenerateBackupCodes")
	defer span.End()

	// Extract token and get session
	token := h.extractTokenFromHeader(c)
	if token == "" {
		span.AddEvent("no token provided")
		return h.response.Unauthorized(c, response.AUTH_TOKEN_MISSING, nil)
	}

	session, err := h.authService.ValidateSession(ctx, token)
	if err != nil {
		span.RecordError(err)
		return h.response.AuthServiceError(c, err)
	}

	// Generate backup codes
	codes, err := h.authService.GenerateBackupCodes(ctx, session.UserID)
	if err != nil {
		span.RecordError(err)
		return h.response.AuthServiceError(c, err)
	}

	// Add request metadata
	requestID := response.GetRequestID(c)
	meta := h.response.WithRequestID(requestID)

	span.AddEvent("backup codes generated successfully")
	return h.response.Success(c, response.AUTH_BACKUP_CODES_GEN, map[string]interface{}{
		"backup_codes": codes,
		"count":        len(codes),
	}, meta)
}

// Helper methods

func (h *AuthHandler) extractTokenFromHeader(c echo.Context) string {
	authHeader := c.Request().Header.Get("Authorization")
	if authHeader == "" {
		return ""
	}

	// Extract Bearer token
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || parts[0] != "Bearer" {
		return ""
	}

	return parts[1]
}

func (h *AuthHandler) getClientIP(c echo.Context) string {
	// Check X-Forwarded-For header first
	if ip := c.Request().Header.Get("X-Forwarded-For"); ip != "" {
		// X-Forwarded-For can contain multiple IPs, get the first one
		if parts := strings.Split(ip, ","); len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}

	// Check X-Real-IP header
	if ip := c.Request().Header.Get("X-Real-IP"); ip != "" {
		return ip
	}

	// Fall back to remote address
	return c.RealIP()
}
