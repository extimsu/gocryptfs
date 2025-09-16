// Package processhardening provides process security hardening utilities
// to protect against memory dumps and improve security posture.
package processhardening

// ProcessHardening provides utilities for hardening the process
type ProcessHardening struct {
	enabled bool
}

// New creates a new ProcessHardening instance
func New() *ProcessHardening {
	return &ProcessHardening{
		enabled: true,
	}
}

// Disable disables process hardening (for testing)
func (ph *ProcessHardening) Disable() {
	ph.enabled = false
}

// IsEnabled returns whether process hardening is enabled
func (ph *ProcessHardening) IsEnabled() bool {
	return ph.enabled
}
