package response

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

// Response represents a standardized API response structure
type Response struct {
	Success   bool        `json:"success" example:"true"`
	Code      string      `json:"code" example:"SUCCESS"`
	Message   string      `json:"message" example:"Operation completed successfully"`
	Data      interface{} `json:"data,omitempty"`
	Error     *ErrorInfo  `json:"error,omitempty"`
	Meta      *Meta       `json:"meta,omitempty"`
	Timestamp int64       `json:"timestamp" example:"1640995200"`
}

// ErrorInfo provides detailed error information
type ErrorInfo struct {
	Code    string      `json:"code" example:"VALIDATION_ERROR"`
	Message string      `json:"message" example:"Invalid input data"`
	Details interface{} `json:"details,omitempty"`
}

// Meta provides additional metadata for the response
type Meta struct {
	RequestID  string      `json:"request_id,omitempty" example:"req-123456"`
	Version    string      `json:"version,omitempty" example:"v1"`
	Pagination interface{} `json:"pagination,omitempty"`
}

// ResponseBuilder provides methods to build standardized responses
type ResponseBuilder struct {
	i18n *I18nManager
}

// NewResponseBuilder creates a new response builder with i18n support
func NewResponseBuilder(i18n *I18nManager) *ResponseBuilder {
	return &ResponseBuilder{
		i18n: i18n,
	}
}

// Success creates a successful response
func (rb *ResponseBuilder) Success(c echo.Context, code ResponseCode, data interface{}, meta ...*Meta) error {
	lang := rb.getLanguageFromContext(c)
	message := rb.i18n.GetMessage(lang, string(code))

	response := Response{
		Success:   true,
		Code:      string(code),
		Message:   message,
		Data:      data,
		Timestamp: GetCurrentTimestamp(),
	}

	if len(meta) > 0 {
		response.Meta = meta[0]
	}

	return c.JSON(http.StatusOK, response)
}

// Error creates an error response
func (rb *ResponseBuilder) Error(c echo.Context, httpStatus int, code ResponseCode, details interface{}, meta ...*Meta) error {
	lang := rb.getLanguageFromContext(c)
	message := rb.i18n.GetMessage(lang, string(code))

	response := Response{
		Success: false,
		Code:    string(code),
		Message: message,
		Error: &ErrorInfo{
			Code:    string(code),
			Message: message,
			Details: details,
		},
		Timestamp: GetCurrentTimestamp(),
	}

	if len(meta) > 0 {
		response.Meta = meta[0]
	}

	return c.JSON(httpStatus, response)
}

// Created creates a created response (201)
func (rb *ResponseBuilder) Created(c echo.Context, code ResponseCode, data interface{}, meta ...*Meta) error {
	lang := rb.getLanguageFromContext(c)
	message := rb.i18n.GetMessage(lang, string(code))

	response := Response{
		Success:   true,
		Code:      string(code),
		Message:   message,
		Data:      data,
		Timestamp: GetCurrentTimestamp(),
	}

	if len(meta) > 0 {
		response.Meta = meta[0]
	}

	return c.JSON(http.StatusCreated, response)
}

// BadRequest creates a bad request response (400)
func (rb *ResponseBuilder) BadRequest(c echo.Context, code ResponseCode, details interface{}, meta ...*Meta) error {
	return rb.Error(c, http.StatusBadRequest, code, details, meta...)
}

// Unauthorized creates an unauthorized response (401)
func (rb *ResponseBuilder) Unauthorized(c echo.Context, code ResponseCode, details interface{}, meta ...*Meta) error {
	return rb.Error(c, http.StatusUnauthorized, code, details, meta...)
}

// Forbidden creates a forbidden response (403)
func (rb *ResponseBuilder) Forbidden(c echo.Context, code ResponseCode, details interface{}, meta ...*Meta) error {
	return rb.Error(c, http.StatusForbidden, code, details, meta...)
}

// NotFound creates a not found response (404)
func (rb *ResponseBuilder) NotFound(c echo.Context, code ResponseCode, details interface{}, meta ...*Meta) error {
	return rb.Error(c, http.StatusNotFound, code, details, meta...)
}

// Conflict creates a conflict response (409)
func (rb *ResponseBuilder) Conflict(c echo.Context, code ResponseCode, details interface{}, meta ...*Meta) error {
	return rb.Error(c, http.StatusConflict, code, details, meta...)
}

// InternalServerError creates an internal server error response (500)
func (rb *ResponseBuilder) InternalServerError(c echo.Context, code ResponseCode, details interface{}, meta ...*Meta) error {
	return rb.Error(c, http.StatusInternalServerError, code, details, meta...)
}

// ServiceUnavailable creates a service unavailable response (503)
func (rb *ResponseBuilder) ServiceUnavailable(c echo.Context, code ResponseCode, details interface{}, meta ...*Meta) error {
	return rb.Error(c, http.StatusServiceUnavailable, code, details, meta...)
}

// WithPagination adds pagination metadata to the response
func (rb *ResponseBuilder) WithPagination(pagination interface{}) *Meta {
	return &Meta{
		Pagination: pagination,
	}
}

// WithRequestID adds request ID to the metadata
func (rb *ResponseBuilder) WithRequestID(requestID string) *Meta {
	return &Meta{
		RequestID: requestID,
	}
}

// WithVersion adds version to the metadata
func (rb *ResponseBuilder) WithVersion(version string) *Meta {
	return &Meta{
		Version: version,
	}
}

// getLanguageFromContext extracts language preference from context
func (rb *ResponseBuilder) getLanguageFromContext(c echo.Context) string {
	// Try to get language from Accept-Language header
	if lang := c.Request().Header.Get("Accept-Language"); lang != "" {
		return parseLanguage(lang)
	}

	// Try to get language from query parameter
	if lang := c.QueryParam("lang"); lang != "" {
		return lang
	}

	// Try to get language from custom header
	if lang := c.Request().Header.Get("X-Language"); lang != "" {
		return lang
	}

	// Default to English
	return "en"
}

// parseLanguage parses Accept-Language header and returns the primary language
func parseLanguage(acceptLang string) string {
	if len(acceptLang) >= 2 {
		return acceptLang[:2]
	}
	return "en"
}

// GetCurrentTimestamp returns current Unix timestamp
func GetCurrentTimestamp() int64 {
	return CurrentTimeProvider().Unix()
}
