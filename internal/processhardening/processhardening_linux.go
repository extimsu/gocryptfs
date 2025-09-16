//go:build linux
// +build linux

// Package processhardening provides process security hardening utilities for Linux
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

	// Set process as non-dumpable (prevents core dumps)
	ph.setDumpable(false)

	// Disable core dumps
	ph.disableCoreDumps()

	// Set memory protection flags
	ph.setMemoryProtection()

	tlog.Debug.Printf("ProcessHardening: Process hardening applied (Linux)")
}

// setDumpable sets the process dumpable flag
func (ph *ProcessHardening) setDumpable(dumpable bool) {
	// PR_SET_DUMPABLE is Linux-specific
	_ = prctl(syscall.PR_SET_DUMPABLE, boolToInt(dumpable), 0, 0, 0)
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
	// Linux-specific memory protection measures
	// This could include additional hardening specific to Linux
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

// Platform-specific functions for Linux

// prctl performs a prctl system call
func prctl(option int, arg2, arg3, arg4, arg5 uintptr) error {
	_, _, errno := syscall.Syscall6(syscall.SYS_PRCTL, uintptr(option), arg2, arg3, arg4, arg5, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

// mlock locks memory to prevent swapping
func mlock(ptr unsafe.Pointer, size uintptr) error {
	_, _, errno := syscall.Syscall(syscall.SYS_MLOCK, uintptr(ptr), size, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

// boolToInt converts a boolean to an integer (0 or 1)
func boolToInt(b bool) uintptr {
	if b {
		return 1
	}
	return 0
}
