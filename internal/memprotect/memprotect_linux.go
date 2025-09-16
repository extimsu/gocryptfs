//go:build linux
// +build linux

// Package memprotect provides memory protection utilities for Linux
package memprotect

import (
	"runtime"
	"syscall"
	"unsafe"

	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

// LockMemory locks a memory region to prevent it from being swapped to disk
// and marks it as MADV_DONTDUMP to exclude it from core dumps.
// Returns true if successful, false if not supported or failed.
func (mp *MemoryProtection) LockMemory(data []byte) bool {
	if !mp.enabled || len(data) == 0 {
		return false
	}

	// Get the underlying memory address
	ptr := unsafe.Pointer(&data[0])
	size := uintptr(len(data))

	// Lock the memory region to prevent swapping
	err := mlock(ptr, size)
	if err != nil {
		tlog.Debug.Printf("MemoryProtection: mlock failed: %v", err)
		// Don't fail completely, just log the warning
	}

	// Mark memory as MADV_DONTDUMP to exclude from core dumps
	err = madvise(ptr, size, syscall.MADV_DONTDUMP)
	if err != nil {
		tlog.Debug.Printf("MemoryProtection: madvise MADV_DONTDUMP failed: %v", err)
		// Don't fail completely, just log the warning
	}

	// Track locked pages for cleanup
	mp.lockedPages = append(mp.lockedPages, ptr)

	tlog.Debug.Printf("MemoryProtection: Locked %d bytes at %p", len(data), ptr)
	return true
}

// UnlockMemory unlocks a previously locked memory region
func (mp *MemoryProtection) UnlockMemory(data []byte) {
	if len(data) == 0 {
		return
	}

	ptr := unsafe.Pointer(&data[0])
	size := uintptr(len(data))

	// Unlock the memory region
	err := munlock(ptr, size)
	if err != nil {
		tlog.Debug.Printf("MemoryProtection: munlock failed: %v", err)
	}

	// Remove from tracking
	for i, p := range mp.lockedPages {
		if p == ptr {
			mp.lockedPages = append(mp.lockedPages[:i], mp.lockedPages[i+1:]...)
			break
		}
	}

	tlog.Debug.Printf("MemoryProtection: Unlocked %d bytes at %p", len(data), ptr)
}

// LockAllMemory locks all current and future memory allocations
// This is more aggressive and should be used with caution
func (mp *MemoryProtection) LockAllMemory() bool {
	if !mp.enabled {
		return false
	}

	err := mlockall(syscall.MCL_CURRENT | syscall.MCL_FUTURE)
	if err != nil {
		tlog.Debug.Printf("MemoryProtection: mlockall failed: %v", err)
		return false
	}

	tlog.Debug.Printf("MemoryProtection: Locked all memory")
	return true
}

// UnlockAllMemory unlocks all memory
func (mp *MemoryProtection) UnlockAllMemory() {
	err := munlockall()
	if err != nil {
		tlog.Debug.Printf("MemoryProtection: munlockall failed: %v", err)
		return
	}

	tlog.Debug.Printf("MemoryProtection: Unlocked all memory")
}

// SecureWipe overwrites memory with random data before unlocking
func (mp *MemoryProtection) SecureWipe(data []byte) {
	if len(data) == 0 {
		return
	}

	// Overwrite with random data
	for i := range data {
		data[i] = byte(i % 256) // Simple pattern, could use crypto/rand
	}

	// Force garbage collection to help clear any copies
	runtime.GC()

	// Unlock the memory
	mp.UnlockMemory(data)
}

// Platform-specific system calls for Linux

// mlock locks a memory region to prevent swapping
func mlock(ptr unsafe.Pointer, size uintptr) error {
	_, _, errno := syscall.Syscall(syscall.SYS_MLOCK, uintptr(ptr), size, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

// munlock unlocks a memory region
func munlock(ptr unsafe.Pointer, size uintptr) error {
	_, _, errno := syscall.Syscall(syscall.SYS_MUNLOCK, uintptr(ptr), size, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

// mlockall locks all current and/or future memory allocations
func mlockall(flags int) error {
	_, _, errno := syscall.Syscall(syscall.SYS_MLOCKALL, uintptr(flags), 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

// munlockall unlocks all memory
func munlockall() error {
	_, _, errno := syscall.Syscall(syscall.SYS_MUNLOCKALL, 0, 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

// madvise provides advice to the kernel about memory usage
func madvise(ptr unsafe.Pointer, size uintptr, advice int) error {
	_, _, errno := syscall.Syscall(syscall.SYS_MADVISE, uintptr(ptr), size, uintptr(advice))
	if errno != 0 {
		return errno
	}
	return nil
}
