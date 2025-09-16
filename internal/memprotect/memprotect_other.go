//go:build !linux && !darwin

package memprotect

import (
	"unsafe"

	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

// LockMemory provides a fallback implementation for unsupported platforms
func (mp *MemoryProtection) LockMemory(data []byte) bool {
	if !mp.enabled || len(data) == 0 {
		return false
	}

	// On unsupported platforms, we can't actually lock memory
	// but we can still track it for cleanup purposes
	ptr := unsafe.Pointer(&data[0])
	mp.lockedPages = append(mp.lockedPages, ptr)

	tlog.Debug.Printf("MemoryProtection: Memory locking not supported on this platform, tracking %d bytes at %p", len(data), ptr)
	return false // Indicate that locking was not successful
}

// LockMemoryPageAligned provides a fallback implementation for unsupported platforms
func (mp *MemoryProtection) LockMemoryPageAligned(data []byte) bool {
	// Just use the regular LockMemory fallback
	return mp.LockMemory(data)
}

// UnlockMemory provides a fallback implementation for unsupported platforms
func (mp *MemoryProtection) UnlockMemory(data []byte) {
	if len(data) == 0 {
		return
	}

	ptr := unsafe.Pointer(&data[0])

	// Remove from tracking
	for i, p := range mp.lockedPages {
		if p == ptr {
			mp.lockedPages = append(mp.lockedPages[:i], mp.lockedPages[i+1:]...)
			break
		}
	}

	tlog.Debug.Printf("MemoryProtection: Memory unlocking not supported on this platform, untracked %d bytes at %p", len(data), ptr)
}

// LockAllMemory provides a fallback implementation for unsupported platforms
func (mp *MemoryProtection) LockAllMemory() bool {
	if !mp.enabled {
		return false
	}

	tlog.Debug.Printf("MemoryProtection: Memory locking not supported on this platform")
	return false
}

// UnlockAllMemory provides a fallback implementation for unsupported platforms
func (mp *MemoryProtection) UnlockAllMemory() {
	tlog.Debug.Printf("MemoryProtection: Memory unlocking not supported on this platform")
}
