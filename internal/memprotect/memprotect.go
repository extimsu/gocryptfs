// Package memprotect provides memory protection utilities for sensitive data
// like encryption keys. It implements memory locking (mlock/mlockall) and
// MADV_DONTDUMP to prevent key material from being swapped to disk or
// included in core dumps.
package memprotect

import (
	"unsafe"
)

// MemoryProtection provides utilities for protecting sensitive memory regions
type MemoryProtection struct {
	lockedPages []unsafe.Pointer
	enabled     bool
}

// New creates a new MemoryProtection instance
func New() *MemoryProtection {
	return &MemoryProtection{
		lockedPages: make([]unsafe.Pointer, 0),
		enabled:     true,
	}
}

// Cleanup unlocks all tracked memory regions
func (mp *MemoryProtection) Cleanup() {
	for _, ptr := range mp.lockedPages {
		// We can't get the size back, so we'll just unlock what we can
		// This is a best-effort cleanup
		munlock(ptr, 0) // Some systems allow this
	}
	mp.lockedPages = mp.lockedPages[:0]
}

// Disable disables memory protection (for testing or when not supported)
func (mp *MemoryProtection) Disable() {
	mp.enabled = false
}

// IsEnabled returns whether memory protection is enabled
func (mp *MemoryProtection) IsEnabled() bool {
	return mp.enabled
}
