package response

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/BurntSushi/toml"
)

// I18nManager manages internationalization for response messages
type I18nManager struct {
	messages    map[string]map[string]string // [language][code]message
	defaultLang string
	mu          sync.RWMutex
}

// NewI18nManager creates a new i18n manager
func NewI18nManager(langDir string, defaultLang string) (*I18nManager, error) {
	manager := &I18nManager{
		messages:    make(map[string]map[string]string),
		defaultLang: defaultLang,
	}

	err := manager.LoadLanguages(langDir)
	if err != nil {
		return nil, fmt.Errorf("failed to load languages: %w", err)
	}

	return manager, nil
}

// LoadLanguages loads all language files from the specified directory
func (i *I18nManager) LoadLanguages(langDir string) error {
	i.mu.Lock()
	defer i.mu.Unlock()

	// Walk through the language directory
	return filepath.Walk(langDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories and non-TOML files
		if info.IsDir() || !strings.HasSuffix(strings.ToLower(path), ".toml") {
			return nil
		}

		// Extract language code from filename (e.g., "en.toml" -> "en")
		filename := info.Name()
		lang := strings.TrimSuffix(filename, filepath.Ext(filename))

		// Load messages from TOML file
		messages, err := i.loadMessagesFromFile(path)
		if err != nil {
			return fmt.Errorf("failed to load messages from %s: %w", path, err)
		}

		i.messages[lang] = messages
		return nil
	})
}

// loadMessagesFromFile loads messages from a TOML file
func (i *I18nManager) loadMessagesFromFile(filePath string) (map[string]string, error) {
	// Structure for TOML file
	var config struct {
		Messages map[string]string `toml:"messages"`
	}

	// Decode TOML file
	if _, err := toml.DecodeFile(filePath, &config); err != nil {
		return nil, fmt.Errorf("failed to decode TOML file: %w", err)
	}

	return config.Messages, nil
}

// GetMessage retrieves a localized message for the given language and code
func (i *I18nManager) GetMessage(lang, code string) string {
	i.mu.RLock()
	defer i.mu.RUnlock()

	// Try to get message in requested language
	if langMessages, exists := i.messages[lang]; exists {
		if message, exists := langMessages[code]; exists {
			return message
		}
	}

	// Fall back to default language
	if lang != i.defaultLang {
		if langMessages, exists := i.messages[i.defaultLang]; exists {
			if message, exists := langMessages[code]; exists {
				return message
			}
		}
	}

	// Return the code itself if no message found
	return strings.ReplaceAll(code, "_", " ")
}

// GetAvailableLanguages returns a list of available languages
func (i *I18nManager) GetAvailableLanguages() []string {
	i.mu.RLock()
	defer i.mu.RUnlock()

	languages := make([]string, 0, len(i.messages))
	for lang := range i.messages {
		languages = append(languages, lang)
	}
	return languages
}

// AddMessage adds or updates a message for a specific language and code
func (i *I18nManager) AddMessage(lang, code, message string) {
	i.mu.Lock()
	defer i.mu.Unlock()

	if i.messages[lang] == nil {
		i.messages[lang] = make(map[string]string)
	}
	i.messages[lang][code] = message
}

// ReloadLanguages reloads all language files
func (i *I18nManager) ReloadLanguages(langDir string) error {
	i.mu.Lock()
	defer i.mu.Unlock()

	// Clear existing messages
	i.messages = make(map[string]map[string]string)

	// Reload from directory
	return i.LoadLanguages(langDir)
}

// HasLanguage checks if a language is supported
func (i *I18nManager) HasLanguage(lang string) bool {
	i.mu.RLock()
	defer i.mu.RUnlock()

	_, exists := i.messages[lang]
	return exists
}

// GetDefaultLanguage returns the default language
func (i *I18nManager) GetDefaultLanguage() string {
	return i.defaultLang
}

// SetDefaultLanguage sets the default language
func (i *I18nManager) SetDefaultLanguage(lang string) {
	i.defaultLang = lang
}
