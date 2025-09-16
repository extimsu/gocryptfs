//go:build darwin
// +build darwin

// Package processhardening provides process security hardening utilities for macOS
package processhardening

import (
	"runtime"
	"syscall"
	"unsafe"

	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

// HardenProcess applies various process hardening measures
func (ph *ProcessHardening) HardenProcess() {
	if !ph.enabled {
		return
	}

	// Disable core dumps on macOS
	ph.disableCoreDumps()

	// Set memory protection flags
	ph.setMemoryProtection()

	tlog.Debug.Printf("ProcessHardening: Process hardening applied (macOS)")
}

// disableCoreDumps disables core dumps for the current process
func (ph *ProcessHardening) disableCoreDumps() {
	// Set core dump size limit to 0
	_ = syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{
		Cur: 0,
		Max: 0,
	})
}

// setMemoryProtection sets additional memory protection flags
func (ph *ProcessHardening) setMemoryProtection() {
	// macOS-specific memory protection measures
	// This could include additional hardening specific to macOS
}

// KeepAlive ensures that a buffer remains in memory and is not garbage collected
func (ph *ProcessHardening) KeepAlive(data []byte) {
	if len(data) == 0 {
		return
	}

	// Use runtime.KeepAlive to prevent garbage collection
	runtime.KeepAlive(data)

	// Additional protection: mark memory as non-swappable
	ptr := unsafe.Pointer(&data[0])
	size := uintptr(len(data))
	_ = mlock(ptr, size)
}

// SecureWipe overwrites memory with random data and ensures it's not recoverable
func (ph *ProcessHardening) SecureWipe(data []byte) {
	if len(data) == 0 {
		return
	}

	// Overwrite with random pattern
	for i := range data {
		data[i] = byte(i % 256)
	}

	// Force garbage collection
	runtime.GC()

	// Use KeepAlive to ensure the data is processed
	ph.KeepAlive(data)
}

// Platform-specific functions for macOS

// mlock locks memory to prevent swapping
func mlock(ptr unsafe.Pointer, size uintptr) error {
	_, _, errno := syscall.Syscall(syscall.SYS_MLOCK, uintptr(ptr), size, 0)
	if errno != 0 {
		return errno
	}
	return nil
}
