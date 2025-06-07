package handlers

import (
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"

	"github.com/ducdt2000/azth/backend/internal/modules/auth/dto"
	"github.com/ducdt2000/azth/backend/internal/modules/auth/service"
	"github.com/ducdt2000/azth/backend/pkg/validator"
)

// AuthHandler handles authentication HTTP requests
type AuthHandler struct {
	authService service.AuthService
	validator   *validator.CustomValidator
	tracer      trace.Tracer
}

// NewAuthHandler creates a new authentication handler
func NewAuthHandler(authService service.AuthService, validator *validator.CustomValidator) *AuthHandler {
	return &AuthHandler{
		authService: authService,
		validator:   validator,
		tracer:      otel.Tracer("auth-handler"),
	}
}

// RegisterRoutes registers authentication routes
func (h *AuthHandler) RegisterRoutes(g *echo.Group) {
	auth := g.Group("/auth")

	// Public routes (no authentication required)
	auth.POST("/login", h.Login)
	auth.POST("/refresh", h.RefreshToken)
	auth.POST("/logout", h.Logout)

	// Protected routes (authentication required)
	// Note: These would typically use authentication middleware
	auth.GET("/sessions", h.GetSessions)
	auth.DELETE("/sessions/:id", h.RevokeSession)
	auth.DELETE("/sessions", h.LogoutAll)

	// MFA routes
	auth.POST("/mfa/enable", h.EnableMFA)
	auth.DELETE("/mfa/disable", h.DisableMFA)
	auth.POST("/mfa/validate", h.ValidateMFA)
	auth.POST("/mfa/backup-codes", h.GenerateBackupCodes)
}

// Login handles user login
// @Summary Login user
// @Description Authenticate user with email and password
// @Tags auth
// @Accept json
// @Produce json
// @Param request body dto.LoginRequest true "Login request"
// @Success 200 {object} dto.LoginResponse "Login successful"
// @Failure 400 {object} echo.HTTPError "Bad request"
// @Failure 401 {object} echo.HTTPError "Unauthorized"
// @Failure 423 {object} echo.HTTPError "Account locked"
// @Failure 500 {object} echo.HTTPError "Internal server error"
// @Router /auth/login [post]
func (h *AuthHandler) Login(c echo.Context) error {
	ctx, span := h.tracer.Start(c.Request().Context(), "auth.handler.Login")
	defer span.End()

	var req dto.LoginRequest
	if err := c.Bind(&req); err != nil {
		span.RecordError(err)
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request body")
	}

	// Add IP address and user agent to request
	req.IPAddress = h.getClientIP(c)
	req.UserAgent = c.Request().UserAgent()

	// Validate request
	if err := h.validator.Validate(&req); err != nil {
		span.RecordError(err)
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	// Perform login
	response, err := h.authService.Login(ctx, &req)
	if err != nil {
		span.RecordError(err)
		return h.handleAuthError(err)
	}

	span.AddEvent("login successful")
	return c.JSON(http.StatusOK, response)
}

// RefreshToken handles token refresh
// @Summary Refresh access token
// @Description Refresh an expired access token using refresh token
// @Tags auth
// @Accept json
// @Produce json
// @Param request body dto.RefreshRequest true "Refresh request"
// @Success 200 {object} dto.RefreshResponse "Token refreshed"
// @Failure 400 {object} echo.HTTPError "Bad request"
// @Failure 401 {object} echo.HTTPError "Invalid refresh token"
// @Failure 500 {object} echo.HTTPError "Internal server error"
// @Router /auth/refresh [post]
func (h *AuthHandler) RefreshToken(c echo.Context) error {
	ctx, span := h.tracer.Start(c.Request().Context(), "auth.handler.RefreshToken")
	defer span.End()

	var req dto.RefreshRequest
	if err := c.Bind(&req); err != nil {
		span.RecordError(err)
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request body")
	}

	// Add IP address and user agent to request
	req.IPAddress = h.getClientIP(c)
	req.UserAgent = c.Request().UserAgent()

	// Validate request
	if err := h.validator.Validate(&req); err != nil {
		span.RecordError(err)
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	// Refresh token
	response, err := h.authService.RefreshToken(ctx, req.RefreshToken)
	if err != nil {
		span.RecordError(err)
		return h.handleAuthError(err)
	}

	span.AddEvent("token refreshed successfully")
	return c.JSON(http.StatusOK, response)
}

// Logout handles user logout
// @Summary Logout user
// @Description Logout user and revoke session
// @Tags auth
// @Accept json
// @Produce json
// @Param request body dto.LogoutRequest true "Logout request"
// @Security BearerAuth
// @Success 200 {object} map[string]string "Logout successful"
// @Failure 400 {object} echo.HTTPError "Bad request"
// @Failure 401 {object} echo.HTTPError "Unauthorized"
// @Failure 500 {object} echo.HTTPError "Internal server error"
// @Router /auth/logout [post]
func (h *AuthHandler) Logout(c echo.Context) error {
	ctx, span := h.tracer.Start(c.Request().Context(), "auth.handler.Logout")
	defer span.End()

	// Extract token from header
	token := h.extractTokenFromHeader(c)
	if token == "" {
		span.AddEvent("no token provided")
		return echo.NewHTTPError(http.StatusUnauthorized, "No token provided")
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
			return h.handleAuthError(err)
		}

		// Logout from all sessions
		if err := h.authService.LogoutAll(ctx, session.UserID); err != nil {
			span.RecordError(err)
			return h.handleAuthError(err)
		}
	} else {
		// Logout from current session only
		if err := h.authService.Logout(ctx, token); err != nil {
			span.RecordError(err)
			return h.handleAuthError(err)
		}
	}

	span.AddEvent("logout successful")
	return c.JSON(http.StatusOK, map[string]string{"message": "Logout successful"})
}

// GetSessions retrieves user sessions
// @Summary Get user sessions
// @Description Get all active sessions for the authenticated user
// @Tags auth
// @Produce json
// @Security BearerAuth
// @Success 200 {object} dto.SessionListResponse "Sessions retrieved"
// @Failure 401 {object} echo.HTTPError "Unauthorized"
// @Failure 500 {object} echo.HTTPError "Internal server error"
// @Router /auth/sessions [get]
func (h *AuthHandler) GetSessions(c echo.Context) error {
	ctx, span := h.tracer.Start(c.Request().Context(), "auth.handler.GetSessions")
	defer span.End()

	// Extract token and get session
	token := h.extractTokenFromHeader(c)
	if token == "" {
		span.AddEvent("no token provided")
		return echo.NewHTTPError(http.StatusUnauthorized, "No token provided")
	}

	session, err := h.authService.ValidateSession(ctx, token)
	if err != nil {
		span.RecordError(err)
		return h.handleAuthError(err)
	}

	// Get all user sessions
	sessions, err := h.authService.GetUserSessions(ctx, session.UserID)
	if err != nil {
		span.RecordError(err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get sessions")
	}

	// Convert to response format
	sessionInfos := make([]dto.SessionInfo, len(sessions))
	for i, s := range sessions {
		sessionInfos[i] = dto.SessionInfo{
			ID:           s.ID,
			IPAddress:    s.IPAddress,
			UserAgent:    s.UserAgent,
			LastActivity: s.LastActivity,
			ExpiresAt:    s.ExpiresAt,
			CreatedAt:    s.CreatedAt,
		}
	}

	response := dto.SessionListResponse{
		Sessions: sessionInfos,
		Total:    len(sessionInfos),
	}

	span.AddEvent("sessions retrieved successfully")
	return c.JSON(http.StatusOK, response)
}

// RevokeSession revokes a specific session
// @Summary Revoke session
// @Description Revoke a specific session by ID
// @Tags auth
// @Param id path string true "Session ID"
// @Security BearerAuth
// @Success 200 {object} map[string]string "Session revoked"
// @Failure 400 {object} echo.HTTPError "Bad request"
// @Failure 401 {object} echo.HTTPError "Unauthorized"
// @Failure 404 {object} echo.HTTPError "Session not found"
// @Failure 500 {object} echo.HTTPError "Internal server error"
// @Router /auth/sessions/{id} [delete]
func (h *AuthHandler) RevokeSession(c echo.Context) error {
	ctx, span := h.tracer.Start(c.Request().Context(), "auth.handler.RevokeSession")
	defer span.End()

	// Extract token and validate session
	token := h.extractTokenFromHeader(c)
	if token == "" {
		span.AddEvent("no token provided")
		return echo.NewHTTPError(http.StatusUnauthorized, "No token provided")
	}

	_, err := h.authService.ValidateSession(ctx, token)
	if err != nil {
		span.RecordError(err)
		return h.handleAuthError(err)
	}

	// Parse session ID
	sessionIDStr := c.Param("id")
	sessionID, err := uuid.Parse(sessionIDStr)
	if err != nil {
		span.RecordError(err)
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid session ID")
	}

	// Revoke session
	if err := h.authService.RevokeSession(ctx, sessionID, "user_revoke"); err != nil {
		span.RecordError(err)
		return h.handleAuthError(err)
	}

	span.AddEvent("session revoked successfully")
	return c.JSON(http.StatusOK, map[string]string{"message": "Session revoked successfully"})
}

// LogoutAll handles logout from all sessions
// @Summary Logout from all sessions
// @Description Logout user from all active sessions
// @Tags auth
// @Security BearerAuth
// @Success 200 {object} map[string]string "Logout successful"
// @Failure 401 {object} echo.HTTPError "Unauthorized"
// @Failure 500 {object} echo.HTTPError "Internal server error"
// @Router /auth/sessions [delete]
func (h *AuthHandler) LogoutAll(c echo.Context) error {
	ctx, span := h.tracer.Start(c.Request().Context(), "auth.handler.LogoutAll")
	defer span.End()

	// Extract token and get session
	token := h.extractTokenFromHeader(c)
	if token == "" {
		span.AddEvent("no token provided")
		return echo.NewHTTPError(http.StatusUnauthorized, "No token provided")
	}

	session, err := h.authService.ValidateSession(ctx, token)
	if err != nil {
		span.RecordError(err)
		return h.handleAuthError(err)
	}

	// Logout from all sessions
	if err := h.authService.LogoutAll(ctx, session.UserID); err != nil {
		span.RecordError(err)
		return h.handleAuthError(err)
	}

	span.AddEvent("logout all successful")
	return c.JSON(http.StatusOK, map[string]string{"message": "Logout from all sessions successful"})
}

// EnableMFA enables multi-factor authentication
// @Summary Enable MFA
// @Description Enable multi-factor authentication for the user
// @Tags auth
// @Produce json
// @Security BearerAuth
// @Success 200 {object} dto.MFASetupResponse "MFA enabled"
// @Failure 401 {object} echo.HTTPError "Unauthorized"
// @Failure 500 {object} echo.HTTPError "Internal server error"
// @Router /auth/mfa/enable [post]
func (h *AuthHandler) EnableMFA(c echo.Context) error {
	ctx, span := h.tracer.Start(c.Request().Context(), "auth.handler.EnableMFA")
	defer span.End()

	// Extract token and get session
	token := h.extractTokenFromHeader(c)
	if token == "" {
		span.AddEvent("no token provided")
		return echo.NewHTTPError(http.StatusUnauthorized, "No token provided")
	}

	session, err := h.authService.ValidateSession(ctx, token)
	if err != nil {
		span.RecordError(err)
		return h.handleAuthError(err)
	}

	// Enable MFA
	response, err := h.authService.EnableMFA(ctx, session.UserID)
	if err != nil {
		span.RecordError(err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to enable MFA")
	}

	span.AddEvent("MFA enabled successfully")
	return c.JSON(http.StatusOK, response)
}

// DisableMFA disables multi-factor authentication
// @Summary Disable MFA
// @Description Disable multi-factor authentication for the user
// @Tags auth
// @Security BearerAuth
// @Success 200 {object} map[string]string "MFA disabled"
// @Failure 401 {object} echo.HTTPError "Unauthorized"
// @Failure 500 {object} echo.HTTPError "Internal server error"
// @Router /auth/mfa/disable [delete]
func (h *AuthHandler) DisableMFA(c echo.Context) error {
	ctx, span := h.tracer.Start(c.Request().Context(), "auth.handler.DisableMFA")
	defer span.End()

	// Extract token and get session
	token := h.extractTokenFromHeader(c)
	if token == "" {
		span.AddEvent("no token provided")
		return echo.NewHTTPError(http.StatusUnauthorized, "No token provided")
	}

	session, err := h.authService.ValidateSession(ctx, token)
	if err != nil {
		span.RecordError(err)
		return h.handleAuthError(err)
	}

	// Disable MFA
	if err := h.authService.DisableMFA(ctx, session.UserID); err != nil {
		span.RecordError(err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to disable MFA")
	}

	span.AddEvent("MFA disabled successfully")
	return c.JSON(http.StatusOK, map[string]string{"message": "MFA disabled successfully"})
}

// ValidateMFA validates MFA code
// @Summary Validate MFA code
// @Description Validate multi-factor authentication code
// @Tags auth
// @Accept json
// @Produce json
// @Param request body dto.MFAValidateRequest true "MFA validation request"
// @Security BearerAuth
// @Success 200 {object} map[string]bool "MFA validation result"
// @Failure 400 {object} echo.HTTPError "Bad request"
// @Failure 401 {object} echo.HTTPError "Unauthorized"
// @Failure 500 {object} echo.HTTPError "Internal server error"
// @Router /auth/mfa/validate [post]
func (h *AuthHandler) ValidateMFA(c echo.Context) error {
	ctx, span := h.tracer.Start(c.Request().Context(), "auth.handler.ValidateMFA")
	defer span.End()

	var req dto.MFAValidateRequest
	if err := c.Bind(&req); err != nil {
		span.RecordError(err)
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request body")
	}

	// Validate request
	if err := h.validator.Validate(&req); err != nil {
		span.RecordError(err)
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	// Validate MFA
	valid, err := h.authService.ValidateMFA(ctx, req.UserID, req.Code)
	if err != nil {
		span.RecordError(err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to validate MFA")
	}

	span.AddEvent("MFA validation completed")
	return c.JSON(http.StatusOK, map[string]bool{"valid": valid})
}

// GenerateBackupCodes generates new backup codes
// @Summary Generate backup codes
// @Description Generate new backup codes for MFA
// @Tags auth
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string][]string "Backup codes generated"
// @Failure 401 {object} echo.HTTPError "Unauthorized"
// @Failure 500 {object} echo.HTTPError "Internal server error"
// @Router /auth/mfa/backup-codes [post]
func (h *AuthHandler) GenerateBackupCodes(c echo.Context) error {
	ctx, span := h.tracer.Start(c.Request().Context(), "auth.handler.GenerateBackupCodes")
	defer span.End()

	// Extract token and get session
	token := h.extractTokenFromHeader(c)
	if token == "" {
		span.AddEvent("no token provided")
		return echo.NewHTTPError(http.StatusUnauthorized, "No token provided")
	}

	session, err := h.authService.ValidateSession(ctx, token)
	if err != nil {
		span.RecordError(err)
		return h.handleAuthError(err)
	}

	// Generate backup codes
	codes, err := h.authService.GenerateBackupCodes(ctx, session.UserID)
	if err != nil {
		span.RecordError(err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to generate backup codes")
	}

	span.AddEvent("backup codes generated successfully")
	return c.JSON(http.StatusOK, map[string][]string{"backup_codes": codes})
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

func (h *AuthHandler) handleAuthError(err error) error {
	if authErr, ok := err.(*dto.AuthError); ok {
		switch authErr.Code {
		case dto.ErrCodeInvalidCredentials:
			return echo.NewHTTPError(http.StatusUnauthorized, authErr.Message)
		case dto.ErrCodeAccountLocked:
			return echo.NewHTTPError(http.StatusLocked, authErr.Message)
		case dto.ErrCodeMFARequired:
			return echo.NewHTTPError(http.StatusUnauthorized, authErr.Message)
		case dto.ErrCodeInvalidMFA:
			return echo.NewHTTPError(http.StatusUnauthorized, authErr.Message)
		case dto.ErrCodeSessionExpired, dto.ErrCodeSessionNotFound:
			return echo.NewHTTPError(http.StatusUnauthorized, authErr.Message)
		case dto.ErrCodeInvalidToken:
			return echo.NewHTTPError(http.StatusUnauthorized, authErr.Message)
		case dto.ErrCodeUserNotFound:
			return echo.NewHTTPError(http.StatusNotFound, authErr.Message)
		case dto.ErrCodeTenantNotFound:
			return echo.NewHTTPError(http.StatusNotFound, authErr.Message)
		default:
			return echo.NewHTTPError(http.StatusInternalServerError, "Authentication service error")
		}
	}

	return echo.NewHTTPError(http.StatusInternalServerError, "Internal server error")
}
