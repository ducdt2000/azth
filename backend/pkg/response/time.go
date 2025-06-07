package response

import "time"

// TimeProvider allows for dependency injection of time functions for testing
type TimeProvider func() time.Time

var currentTimeProvider TimeProvider = time.Now

// CurrentTimeProvider returns the current time provider function
func CurrentTimeProvider() time.Time {
	return currentTimeProvider()
}

// SetTimeProvider sets a custom time provider (mainly for testing)
func SetTimeProvider(provider TimeProvider) {
	currentTimeProvider = provider
}

// ResetTimeProvider resets the time provider to the default (time.Now)
func ResetTimeProvider() {
	currentTimeProvider = time.Now
}
