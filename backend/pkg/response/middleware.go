package response

import (
	"crypto/rand"
	"encoding/hex"
	"strings"

	"github.com/labstack/echo/v4"
)

const (
	// Context keys
	RequestIDKey          = "request_id"
	LanguageKey           = "language"
	ResponseBuilderCtxKey = "response_builder"
)

// RequestIDMiddleware generates a unique request ID for each request
func RequestIDMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// Check if request ID already exists in header
			requestID := c.Request().Header.Get("X-Request-ID")
			if requestID == "" {
				// Generate new request ID
				requestID = generateRequestID()
			}

			// Set request ID in context and response header
			c.Set(RequestIDKey, requestID)
			c.Response().Header().Set("X-Request-ID", requestID)

			return next(c)
		}
	}
}

// LanguageMiddleware detects and sets the user's preferred language
func LanguageMiddleware(defaultLang string, supportedLangs []string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			lang := detectLanguage(c, defaultLang, supportedLangs)
			c.Set(LanguageKey, lang)
			c.Response().Header().Set("Content-Language", lang)
			return next(c)
		}
	}
}

// ResponseBuilderMiddleware injects the response builder into the context
func ResponseBuilderMiddleware(rb *ResponseBuilder) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			c.Set(ResponseBuilderCtxKey, rb)
			return next(c)
		}
	}
}

// CombinedMiddleware combines request ID, language detection, and response builder
func CombinedMiddleware(rb *ResponseBuilder, defaultLang string, supportedLangs []string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// Request ID
			requestID := c.Request().Header.Get("X-Request-ID")
			if requestID == "" {
				requestID = generateRequestID()
			}
			c.Set(RequestIDKey, requestID)
			c.Response().Header().Set("X-Request-ID", requestID)

			// Language detection
			lang := detectLanguage(c, defaultLang, supportedLangs)
			c.Set(LanguageKey, lang)
			c.Response().Header().Set("Content-Language", lang)

			// Response builder
			c.Set(ResponseBuilderCtxKey, rb)

			return next(c)
		}
	}
}

// generateRequestID generates a unique request ID
func generateRequestID() string {
	bytes := make([]byte, 8)
	_, _ = rand.Read(bytes)
	return "req-" + hex.EncodeToString(bytes)
}

// detectLanguage detects the user's preferred language
func detectLanguage(c echo.Context, defaultLang string, supportedLangs []string) string {
	// Priority order:
	// 1. Query parameter (?lang=en)
	// 2. Custom header (X-Language)
	// 3. Accept-Language header
	// 4. Default language

	// Check query parameter
	if lang := c.QueryParam("lang"); lang != "" {
		if isLanguageSupported(lang, supportedLangs) {
			return lang
		}
	}

	// Check custom header
	if lang := c.Request().Header.Get("X-Language"); lang != "" {
		if isLanguageSupported(lang, supportedLangs) {
			return lang
		}
	}

	// Check Accept-Language header
	if acceptLang := c.Request().Header.Get("Accept-Language"); acceptLang != "" {
		if lang := parseAcceptLanguage(acceptLang, supportedLangs); lang != "" {
			return lang
		}
	}

	// Return default language
	return defaultLang
}

// parseAcceptLanguage parses Accept-Language header and returns the best match
func parseAcceptLanguage(acceptLang string, supportedLangs []string) string {
	// Split by comma and process each language tag
	languages := strings.Split(acceptLang, ",")

	for _, lang := range languages {
		// Remove quality values (q=0.5)
		lang = strings.Split(strings.TrimSpace(lang), ";")[0]

		// Check exact match
		if isLanguageSupported(lang, supportedLangs) {
			return lang
		}

		// Check language prefix (e.g., "en-US" -> "en")
		if parts := strings.Split(lang, "-"); len(parts) > 1 {
			prefix := parts[0]
			if isLanguageSupported(prefix, supportedLangs) {
				return prefix
			}
		}
	}

	return ""
}

// isLanguageSupported checks if a language is in the supported languages list
func isLanguageSupported(lang string, supportedLangs []string) bool {
	for _, supported := range supportedLangs {
		if strings.EqualFold(lang, supported) {
			return true
		}
	}
	return false
}

// GetRequestID retrieves the request ID from context
func GetRequestID(c echo.Context) string {
	if id, ok := c.Get(RequestIDKey).(string); ok {
		return id
	}
	return ""
}

// GetLanguage retrieves the language from context
func GetLanguage(c echo.Context) string {
	if lang, ok := c.Get(LanguageKey).(string); ok {
		return lang
	}
	return "en" // fallback
}

// GetResponseBuilder retrieves the response builder from context
func GetResponseBuilder(c echo.Context) *ResponseBuilder {
	if rb, ok := c.Get(ResponseBuilderCtxKey).(*ResponseBuilder); ok {
		return rb
	}
	return nil
}

// MustGetResponseBuilder retrieves the response builder from context or panics
func MustGetResponseBuilder(c echo.Context) *ResponseBuilder {
	rb := GetResponseBuilder(c)
	if rb == nil {
		panic("response builder not found in context")
	}
	return rb
}
