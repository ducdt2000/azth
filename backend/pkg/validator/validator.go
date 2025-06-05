package validator

import (
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
)

// CustomValidator wraps the validator instance
type CustomValidator struct {
	validator *validator.Validate
}

// NewValidator creates a new custom validator
func NewValidator() *CustomValidator {
	v := validator.New()

	// Register custom tag name function
	v.RegisterTagNameFunc(func(fld reflect.StructField) string {
		name := strings.SplitN(fld.Tag.Get("json"), ",", 2)[0]
		if name == "-" {
			return ""
		}
		return name
	})

	// Register custom validation rules
	registerCustomValidations(v)

	return &CustomValidator{
		validator: v,
	}
}

// Validate validates a struct
func (cv *CustomValidator) Validate(i interface{}) error {
	if err := cv.validator.Struct(i); err != nil {
		return formatValidationErrors(err)
	}
	return nil
}

// registerCustomValidations registers custom validation rules
func registerCustomValidations(v *validator.Validate) {
	// Register username validation
	v.RegisterValidation("username", validateUsername)

	// Register strong password validation
	v.RegisterValidation("strongpassword", validateStrongPassword)

	// Register phone number validation
	v.RegisterValidation("phone", validatePhoneNumber)

	// Register slug validation
	v.RegisterValidation("slug", validateSlug)
}

// validateUsername validates username format
func validateUsername(fl validator.FieldLevel) bool {
	username := fl.Field().String()
	if len(username) < 3 || len(username) > 50 {
		return false
	}

	// Username should contain only alphanumeric characters, underscores, and hyphens
	for _, char := range username {
		if !((char >= 'a' && char <= 'z') ||
			(char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') ||
			char == '_' || char == '-') {
			return false
		}
	}

	// Should not start or end with special characters
	if username[0] == '_' || username[0] == '-' ||
		username[len(username)-1] == '_' || username[len(username)-1] == '-' {
		return false
	}

	return true
}

// validateStrongPassword validates password strength
func validateStrongPassword(fl validator.FieldLevel) bool {
	password := fl.Field().String()

	if len(password) < 8 {
		return false
	}

	var hasUpper, hasLower, hasNumber, hasSpecial bool

	for _, char := range password {
		switch {
		case char >= 'A' && char <= 'Z':
			hasUpper = true
		case char >= 'a' && char <= 'z':
			hasLower = true
		case char >= '0' && char <= '9':
			hasNumber = true
		case strings.ContainsRune("!@#$%^&*()_+-=[]{}|;:,.<>?", char):
			hasSpecial = true
		}
	}

	return hasUpper && hasLower && hasNumber && hasSpecial
}

// validatePhoneNumber validates phone number format
func validatePhoneNumber(fl validator.FieldLevel) bool {
	phone := fl.Field().String()

	// Simple phone validation - starts with + followed by digits
	if len(phone) < 8 || len(phone) > 20 {
		return false
	}

	if phone[0] != '+' {
		return false
	}

	for i := 1; i < len(phone); i++ {
		if phone[i] < '0' || phone[i] > '9' {
			return false
		}
	}

	return true
}

// validateSlug validates slug format
func validateSlug(fl validator.FieldLevel) bool {
	slug := fl.Field().String()

	if len(slug) < 2 || len(slug) > 100 {
		return false
	}

	// Slug should contain only lowercase letters, numbers, and hyphens
	for _, char := range slug {
		if !((char >= 'a' && char <= 'z') ||
			(char >= '0' && char <= '9') ||
			char == '-') {
			return false
		}
	}

	// Should not start or end with hyphen
	if slug[0] == '-' || slug[len(slug)-1] == '-' {
		return false
	}

	return true
}

// formatValidationErrors formats validation errors into a readable format
func formatValidationErrors(err error) error {
	var validationErrors validator.ValidationErrors
	if errors.As(err, &validationErrors) {
		var messages []string

		for _, err := range validationErrors {
			message := formatFieldError(err)
			messages = append(messages, message)
		}

		return fmt.Errorf("validation failed: %s", strings.Join(messages, ", "))
	}

	return err
}

// formatFieldError formats a single field error
func formatFieldError(err validator.FieldError) string {
	field := err.Field()
	tag := err.Tag()

	switch tag {
	case "required":
		return fmt.Sprintf("%s is required", field)
	case "email":
		return fmt.Sprintf("%s must be a valid email address", field)
	case "min":
		return fmt.Sprintf("%s must be at least %s characters long", field, err.Param())
	case "max":
		return fmt.Sprintf("%s must be at most %s characters long", field, err.Param())
	case "username":
		return fmt.Sprintf("%s must be a valid username (3-50 characters, alphanumeric, underscore, hyphen)", field)
	case "strongpassword":
		return fmt.Sprintf("%s must be a strong password (8+ characters with uppercase, lowercase, number, and special character)", field)
	case "phone":
		return fmt.Sprintf("%s must be a valid phone number (e.g., +1234567890)", field)
	case "slug":
		return fmt.Sprintf("%s must be a valid slug (lowercase letters, numbers, hyphens)", field)
	case "uuid":
		return fmt.Sprintf("%s must be a valid UUID", field)
	case "oneof":
		return fmt.Sprintf("%s must be one of: %s", field, err.Param())
	default:
		return fmt.Sprintf("%s is invalid", field)
	}
}

// SetupEchoValidator sets up the custom validator for Echo
func SetupEchoValidator(e *echo.Echo) {
	e.Validator = NewValidator()
}
