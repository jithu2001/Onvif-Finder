package main

import (
	"log"
	"os"
)

// ============================================================================
// LOGGING
// ============================================================================

// Logger provides structured logging with different levels
type Logger struct {
	verbose bool
}

// NewLogger creates a new logger instance
func NewLogger(verbose bool) *Logger {
	return &Logger{verbose: verbose}
}

// Info logs informational messages (always shown)
func (l *Logger) Info(format string, args ...interface{}) {
	log.Printf("[INFO] "+format, args...)
}

// Error logs error messages (always shown)
func (l *Logger) Error(format string, args ...interface{}) {
	log.Printf("[ERROR] "+format, args...)
}

// Debug logs debug messages (only if verbose mode is enabled)
func (l *Logger) Debug(format string, args ...interface{}) {
	if l.verbose {
		log.Printf("[DEBUG] "+format, args...)
	}
}

// Global logger instance
var logger = NewLogger(isVerboseMode())

// isVerboseMode checks if verbose logging is enabled via environment variables
func isVerboseMode() bool {
	return os.Getenv("VERBOSE") == "1" || os.Getenv("DEBUG") == "1"
}
