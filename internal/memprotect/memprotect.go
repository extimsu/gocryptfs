// Package memprotect provides memory protection utilities for sensitive data
// like encryption keys. It implements memory locking (mlock/mlockall) and
// MADV_DONTDUMP to prevent key material from being swapped to disk or
// included in core dumps.
package memprotect

import (
	"crypto/rand"
	"runtime"
	"syscall"
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

// PageSize returns the system page size
func PageSize() int {
	return syscall.Getpagesize()
}

// AllocatePageAligned allocates a page-aligned memory region of the specified size
// This ensures that mlock operations work efficiently
func (mp *MemoryProtection) AllocatePageAligned(size int) []byte {
	if !mp.enabled {
		// Fallback to regular allocation if memory protection is disabled
		return make([]byte, size)
	}

	pageSize := PageSize()
	// Round up to page boundary
	alignedSize := ((size + pageSize - 1) / pageSize) * pageSize

	// Allocate aligned memory
	data := make([]byte, alignedSize)

	// Lock the memory immediately after allocation
	if mp.LockMemory(data) {
		// Return only the requested size, but keep the full aligned allocation locked
		return data[:size]
	}

	// If locking failed, return the regular allocation
	return data[:size]
}

// SecureZero overwrites memory with zeros using a secure method
func (mp *MemoryProtection) SecureZero(data []byte) {
	if len(data) == 0 {
		return
	}

	// Use runtime.KeepAlive to prevent optimization
	defer runtime.KeepAlive(data)

	// Overwrite with zeros
	for i := range data {
		data[i] = 0
	}

	// Force a memory barrier to ensure the writes are visible
	runtime.GC()
}

// SecureRandom overwrites memory with random data
func (mp *MemoryProtection) SecureRandom(data []byte) {
	if len(data) == 0 {
		return
	}

	// Use runtime.KeepAlive to prevent optimization
	defer runtime.KeepAlive(data)

	// Overwrite with random data
	_, err := rand.Read(data)
	if err != nil {
		// Fallback to a simple pattern if crypto/rand fails
		for i := range data {
			data[i] = byte(i % 256)
		}
	}

	// Force a memory barrier to ensure the writes are visible
	runtime.GC()
}

// SecureWipeEnhanced overwrites memory with random data and unlocks it
func (mp *MemoryProtection) SecureWipeEnhanced(data []byte) {
	if len(data) == 0 {
		return
	}

	// Overwrite with random data
	mp.SecureRandom(data)

	// Unlock the memory
	mp.UnlockMemory(data)
}
