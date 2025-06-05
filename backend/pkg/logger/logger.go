package logger

import (
	"io"
	"log/slog"
	"os"
	"strings"
)

// Logger wraps slog.Logger with additional methods
type Logger struct {
	*slog.Logger
}

// New creates a new logger with the specified level and format
func New(level, format string) *Logger {
	var logLevel slog.Level
	switch strings.ToLower(level) {
	case "debug":
		logLevel = slog.LevelDebug
	case "info":
		logLevel = slog.LevelInfo
	case "warn", "warning":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	default:
		logLevel = slog.LevelInfo
	}

	var handler slog.Handler
	var output io.Writer = os.Stdout

	opts := &slog.HandlerOptions{
		Level:     logLevel,
		AddSource: true,
	}

	switch strings.ToLower(format) {
	case "json":
		handler = slog.NewJSONHandler(output, opts)
	case "text":
		handler = slog.NewTextHandler(output, opts)
	default:
		handler = slog.NewJSONHandler(output, opts)
	}

	return &Logger{
		Logger: slog.New(handler),
	}
}

// Sync flushes any buffered log entries (compatibility method)
func (l *Logger) Sync() error {
	// slog automatically flushes, but we keep this for interface compatibility
	return nil
}

// Fatal logs a message at Fatal level and exits the program
func (l *Logger) Fatal(msg string, args ...interface{}) {
	l.Error(msg, args...)
	os.Exit(1)
}
