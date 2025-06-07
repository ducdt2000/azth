package response

import (
	"path/filepath"

	"go.uber.org/fx"
)

// ResponseConfig holds configuration for the response system
type ResponseConfig struct {
	LanguagesDir string
	DefaultLang  string
}

// NewResponseConfig creates a new response configuration with default values
func NewResponseConfig() *ResponseConfig {
	return &ResponseConfig{
		LanguagesDir: "locales",
		DefaultLang:  "en",
	}
}

// Module provides the response system as an fx module
var Module = fx.Module("response",
	fx.Provide(
		NewResponseConfig,
		NewI18nManager,
		NewResponseBuilder,
	),
)

// NewI18nManagerWithConfig creates a new i18n manager using the provided config
func NewI18nManagerWithConfig(config *ResponseConfig) (*I18nManager, error) {
	return NewI18nManager(config.LanguagesDir, config.DefaultLang)
}

// Provider provides the response system components for dependency injection
func Provider() fx.Option {
	return fx.Options(
		fx.Provide(
			NewResponseConfig,
			fx.Annotate(
				NewI18nManagerWithConfig,
				fx.ParamTags(`name:"response_config"`),
			),
			NewResponseBuilder,
		),
	)
}

// ProviderWithConfig provides the response system with custom configuration
func ProviderWithConfig(config *ResponseConfig) fx.Option {
	return fx.Options(
		fx.Supply(config),
		fx.Provide(
			fx.Annotate(
				func(cfg *ResponseConfig) (*I18nManager, error) {
					return NewI18nManager(cfg.LanguagesDir, cfg.DefaultLang)
				},
				fx.ParamTags(`name:"response_config"`),
			),
			NewResponseBuilder,
		),
	)
}

// WithCustomLanguagesDir sets a custom languages directory
func (c *ResponseConfig) WithCustomLanguagesDir(dir string) *ResponseConfig {
	c.LanguagesDir = dir
	return c
}

// WithDefaultLanguage sets the default language
func (c *ResponseConfig) WithDefaultLanguage(lang string) *ResponseConfig {
	c.DefaultLang = lang
	return c
}

// GetAbsoluteLanguagesDir returns the absolute path to the languages directory
func (c *ResponseConfig) GetAbsoluteLanguagesDir(baseDir string) string {
	if filepath.IsAbs(c.LanguagesDir) {
		return c.LanguagesDir
	}
	return filepath.Join(baseDir, c.LanguagesDir)
}
