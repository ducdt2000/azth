package middleware

import (
	"net/http"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/ducdt2000/azth/backend/internal/domain"
	"github.com/ducdt2000/azth/backend/internal/modules/auth/dto"
	"github.com/ducdt2000/azth/backend/internal/modules/auth/service"
	"github.com/ducdt2000/azth/backend/pkg/utils"
)

// AuthMiddleware provides authentication middleware functionality
type AuthMiddleware struct {
	authService service.AuthService
	logger      Logger
}

// Logger interface for middleware
type Logger interface {
	Info(msg string, fields ...interface{})
	Error(msg string, fields ...interface{})
	Warn(msg string, fields ...interface{})
	Debug(msg string, fields ...interface{})
}

// NewAuthMiddleware creates a new authentication middleware
func NewAuthMiddleware(authService service.AuthService, logger Logger) *AuthMiddleware {
	return &AuthMiddleware{
		authService: authService,
		logger:      logger,
	}
}

// RequireAuth middleware enforces authentication for protected routes
func (m *AuthMiddleware) RequireAuth() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			token := m.extractToken(c)
			if token == "" {
				m.logger.Warn("Authentication required - no token provided")
				return echo.NewHTTPError(http.StatusUnauthorized, "Authentication required")
			}

			// Handle different authentication modes
			if m.authService.IsJWTMode() {
				// JWT Mode
				claims, err := m.authService.ValidateJWT(c.Request().Context(), token)
				if err != nil {
					m.logger.Warn("JWT validation failed", "error", err)
					return m.handleAuthError(err)
				}

				// Set context values for JWT mode
				c.Set("auth_mode", "jwt")
				c.Set("user_id", claims.UserID.String())
				c.Set("tenant_id", claims.TenantID.String())
				c.Set("user_email", claims.Email)
				c.Set("user_username", claims.Username)
				c.Set("jwt_claims", claims)
			} else {
				// Session Mode
				session, err := m.authService.ValidateSession(c.Request().Context(), token)
				if err != nil {
					m.logger.Warn("Session validation failed", "error", err)
					return m.handleAuthError(err)
				}

				// Set context values for session mode
				c.Set("auth_mode", "session")
				c.Set("user_id", session.UserID.String())
				c.Set("tenant_id", session.TenantID.String())
				c.Set("session", session)
			}

			return next(c)
		}
	}
}

// OptionalAuth middleware extracts authentication info if present
func (m *AuthMiddleware) OptionalAuth() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			token := m.extractToken(c)
			if token == "" {
				return next(c)
			}

			// Handle different authentication modes
			if m.authService.IsJWTMode() {
				// JWT Mode
				claims, err := m.authService.ValidateJWT(c.Request().Context(), token)
				if err != nil {
					// Log error but don't fail request
					m.logger.Debug("Optional JWT validation failed", "error", err)
					return next(c)
				}

				// Set context values for JWT mode
				c.Set("auth_mode", "jwt")
				c.Set("user_id", claims.UserID.String())
				c.Set("tenant_id", claims.TenantID.String())
				c.Set("user_email", claims.Email)
				c.Set("user_username", claims.Username)
				c.Set("jwt_claims", claims)
			} else {
				// Session Mode
				session, err := m.authService.ValidateSession(c.Request().Context(), token)
				if err != nil {
					// Log error but don't fail request
					m.logger.Debug("Optional session validation failed", "error", err)
					return next(c)
				}

				// Set context values for session mode
				c.Set("auth_mode", "session")
				c.Set("user_id", session.UserID.String())
				c.Set("tenant_id", session.TenantID.String())
				c.Set("session", session)
			}

			return next(c)
		}
	}
}

// RequireTenant middleware enforces tenant-specific access
func (m *AuthMiddleware) RequireTenant(tenantID uuid.UUID) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			contextTenantID, ok := GetTenantIDFromContext(c)
			if !ok {
				m.logger.Warn("Tenant access required - no tenant in context")
				return echo.NewHTTPError(http.StatusForbidden, "Tenant access required")
			}

			if contextTenantID != tenantID.String() {
				m.logger.Warn("Tenant access denied", "required", tenantID, "provided", contextTenantID)
				return echo.NewHTTPError(http.StatusForbidden, "Access denied for this tenant")
			}

			return next(c)
		}
	}
}

// RequireRole middleware enforces role-based access control
func (m *AuthMiddleware) RequireRole(role string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// TODO: Implement role checking logic
			// This would typically involve checking user roles against the required role
			// For now, we'll just pass through
			m.logger.Debug("Role check requested", "required_role", role)
			return next(c)
		}
	}
}

// RequirePermission middleware enforces permission-based access control
func (m *AuthMiddleware) RequirePermission(permission string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// TODO: Implement permission checking logic
			// This would typically involve checking user permissions against the required permission
			// For now, we'll just pass through
			m.logger.Debug("Permission check requested", "required_permission", permission)
			return next(c)
		}
	}
}

// extractToken extracts the authentication token from the request
func (m *AuthMiddleware) extractToken(c echo.Context) string {
	// Try Authorization header first
	authHeader := c.Request().Header.Get("Authorization")
	if authHeader != "" {
		// Check for Bearer token
		if token := utils.ExtractTokenFromBearer(authHeader); token != "" {
			return token
		}
	}

	// Try cookie (for session mode)
	if cookie, err := c.Cookie("auth_token"); err == nil {
		return cookie.Value
	}

	// Try query parameter (less secure, for development/testing)
	if token := c.QueryParam("token"); token != "" {
		return token
	}

	return ""
}

// handleAuthError handles authentication errors and returns appropriate HTTP responses
func (m *AuthMiddleware) handleAuthError(err error) error {
	if authErr, ok := err.(*dto.AuthError); ok {
		switch authErr.Code {
		case dto.ErrCodeSessionExpired, dto.ErrCodeJWTExpired:
			return echo.NewHTTPError(http.StatusUnauthorized, "Token has expired")
		case dto.ErrCodeSessionNotFound, dto.ErrCodeInvalidToken, dto.ErrCodeInvalidJWT:
			return echo.NewHTTPError(http.StatusUnauthorized, "Invalid token")
		case dto.ErrCodeAccountLocked:
			return echo.NewHTTPError(http.StatusForbidden, "Account is locked")
		default:
			return echo.NewHTTPError(http.StatusUnauthorized, "Authentication failed")
		}
	}
	return echo.NewHTTPError(http.StatusUnauthorized, "Authentication failed")
}

// Context helper functions

// GetAuthModeFromContext extracts authentication mode from echo context
func GetAuthModeFromContext(c echo.Context) (string, bool) {
	mode, ok := c.Get("auth_mode").(string)
	return mode, ok
}

// GetSessionFromContext extracts session from echo context (session mode only)
func GetSessionFromContext(c echo.Context) (*domain.Session, bool) {
	session, ok := c.Get("session").(*domain.Session)
	return session, ok
}

// GetJWTClaimsFromContext extracts JWT claims from echo context (JWT mode only)
func GetJWTClaimsFromContext(c echo.Context) (*dto.JWTClaims, bool) {
	claims, ok := c.Get("jwt_claims").(*dto.JWTClaims)
	return claims, ok
}

// GetUserIDFromContext extracts user ID from echo context
func GetUserIDFromContext(c echo.Context) (string, bool) {
	userID, ok := c.Get("user_id").(string)
	return userID, ok
}

// GetTenantIDFromContext extracts tenant ID from echo context
func GetTenantIDFromContext(c echo.Context) (string, bool) {
	tenantID, ok := c.Get("tenant_id").(string)
	return tenantID, ok
}

// GetUserEmailFromContext extracts user email from echo context (JWT mode only)
func GetUserEmailFromContext(c echo.Context) (string, bool) {
	email, ok := c.Get("user_email").(string)
	return email, ok
}

// GetUserUsernameFromContext extracts username from echo context (JWT mode only)
func GetUserUsernameFromContext(c echo.Context) (string, bool) {
	username, ok := c.Get("user_username").(string)
	return username, ok
}

// Convenience functions that panic if not found (for use when you're sure auth is present)

// MustGetSessionFromContext extracts session from echo context or panics
func MustGetSessionFromContext(c echo.Context) *domain.Session {
	session, ok := GetSessionFromContext(c)
	if !ok {
		panic("session not found in context")
	}
	return session
}

// MustGetJWTClaimsFromContext extracts JWT claims from echo context or panics
func MustGetJWTClaimsFromContext(c echo.Context) *dto.JWTClaims {
	claims, ok := GetJWTClaimsFromContext(c)
	if !ok {
		panic("JWT claims not found in context")
	}
	return claims
}

// MustGetUserIDFromContext extracts user ID from echo context or panics
func MustGetUserIDFromContext(c echo.Context) string {
	userID, ok := GetUserIDFromContext(c)
	if !ok {
		panic("user ID not found in context")
	}
	return userID
}

// MustGetTenantIDFromContext extracts tenant ID from echo context or panics
func MustGetTenantIDFromContext(c echo.Context) string {
	tenantID, ok := GetTenantIDFromContext(c)
	if !ok {
		panic("tenant ID not found in context")
	}
	return tenantID
}

// IsAuthenticated checks if the request is authenticated
func IsAuthenticated(c echo.Context) bool {
	_, hasUserID := GetUserIDFromContext(c)
	return hasUserID
}

// IsJWTMode checks if the current authentication mode is JWT
func IsJWTMode(c echo.Context) bool {
	mode, ok := GetAuthModeFromContext(c)
	return ok && mode == "jwt"
}

// IsSessionMode checks if the current authentication mode is session
func IsSessionMode(c echo.Context) bool {
	mode, ok := GetAuthModeFromContext(c)
	return ok && mode == "session"
}
