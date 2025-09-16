package security

import (
	"fmt"
	"testing"

	"github.com/rfjakob/gocryptfs/v2/internal/memprotect"
)

// TestMemoryProtectionBasic tests basic memory protection functionality
func TestMemoryProtectionBasic(t *testing.T) {
	mp := memprotect.New()
	defer mp.Cleanup()

	// Test that memory protection is enabled by default
	if !mp.IsEnabled() {
		t.Error("Memory protection should be enabled by default")
	}

	// Test page size
	pageSize := memprotect.PageSize()
	if pageSize <= 0 {
		t.Error("Page size should be positive")
	}
	if pageSize&(pageSize-1) != 0 {
		t.Error("Page size should be a power of 2")
	}

	// Test disabling memory protection
	mp.Disable()
	if mp.IsEnabled() {
		t.Error("Memory protection should be disabled after calling Disable()")
	}
}

// TestMemoryProtectionAllocation tests page-aligned memory allocation
func TestMemoryProtectionAllocation(t *testing.T) {
	mp := memprotect.New()
	defer mp.Cleanup()

	// Test allocation of various sizes
	sizes := []int{1, 16, 32, 64, 128, 256, 512, 1024, 4096, 8192}

	for _, size := range sizes {
		data := mp.AllocatePageAligned(size)
		if len(data) != size {
			t.Errorf("Allocated size mismatch: expected %d, got %d", size, len(data))
		}

		// Test that we can write to the allocated memory
		for i := range data {
			data[i] = byte(i % 256)
		}

		// Test that we can read from the allocated memory
		for i := range data {
			expected := byte(i % 256)
			if data[i] != expected {
				t.Errorf("Memory content mismatch at index %d: expected %d, got %d", i, expected, data[i])
			}
		}
	}
}

// TestMemoryProtectionLocking tests memory locking functionality
func TestMemoryProtectionLocking(t *testing.T) {
	mp := memprotect.New()
	defer mp.Cleanup()

	// Test locking regular memory
	data := make([]byte, 1024)
	for i := range data {
		data[i] = byte(i % 256)
	}

	// Lock the memory
	success := mp.LockMemory(data)
	if !success {
		t.Log("Memory locking not supported on this platform")
		return
	}

	// Test that the data is still accessible
	for i := range data {
		expected := byte(i % 256)
		if data[i] != expected {
			t.Errorf("Memory content changed after locking at index %d: expected %d, got %d", i, expected, data[i])
		}
	}

	// Unlock the memory
	mp.UnlockMemory(data)

	// Test that the data is still accessible after unlocking
	for i := range data {
		expected := byte(i % 256)
		if data[i] != expected {
			t.Errorf("Memory content changed after unlocking at index %d: expected %d, got %d", i, expected, data[i])
		}
	}
}

// TestMemoryProtectionPageAligned tests page-aligned memory locking
func TestMemoryProtectionPageAligned(t *testing.T) {
	mp := memprotect.New()
	defer mp.Cleanup()

	// Test page-aligned locking
	data := make([]byte, 1024)
	for i := range data {
		data[i] = byte(i % 256)
	}

	// Lock the memory with page alignment
	success := mp.LockMemoryPageAligned(data)
	if !success {
		t.Log("Page-aligned memory locking not supported on this platform")
		return
	}

	// Test that the data is still accessible
	for i := range data {
		expected := byte(i % 256)
		if data[i] != expected {
			t.Errorf("Memory content changed after page-aligned locking at index %d: expected %d, got %d", i, expected, data[i])
		}
	}

	// Unlock the memory
	mp.UnlockMemory(data)
}

// TestMemoryProtectionSecureWipe tests secure memory wiping
func TestMemoryProtectionSecureWipe(t *testing.T) {
	mp := memprotect.New()
	defer mp.Cleanup()

	// Test secure zero
	data := make([]byte, 1024)
	for i := range data {
		data[i] = byte(i % 256)
	}

	mp.SecureZero(data)

	// Check that all bytes are zero
	for i, b := range data {
		if b != 0 {
			t.Errorf("SecureZero failed at index %d: expected 0, got %d", i, b)
		}
	}
}

// TestMemoryProtectionSecureRandom tests secure random memory overwriting
func TestMemoryProtectionSecureRandom(t *testing.T) {
	mp := memprotect.New()
	defer mp.Cleanup()

	// Test secure random
	data := make([]byte, 1024)
	for i := range data {
		data[i] = byte(i % 256)
	}

	originalData := make([]byte, len(data))
	copy(originalData, data)

	mp.SecureRandom(data)

	// Check that the data has changed (very high probability)
	changed := false
	for i := range data {
		if data[i] != originalData[i] {
			changed = true
			break
		}
	}

	if !changed {
		t.Error("SecureRandom did not change the data")
	}
}

// TestMemoryProtectionSecureWipeEnhanced tests enhanced secure wiping
func TestMemoryProtectionSecureWipeEnhanced(t *testing.T) {
	mp := memprotect.New()
	defer mp.Cleanup()

	// Test enhanced secure wipe
	data := make([]byte, 1024)
	for i := range data {
		data[i] = byte(i % 256)
	}

	originalData := make([]byte, len(data))
	copy(originalData, data)

	mp.SecureWipeEnhanced(data)

	// Check that the data has changed (very high probability)
	changed := false
	for i := range data {
		if data[i] != originalData[i] {
			changed = true
			break
		}
	}

	if !changed {
		t.Error("SecureWipeEnhanced did not change the data")
	}
}

// TestMemoryProtectionLockAllMemory tests locking all memory
func TestMemoryProtectionLockAllMemory(t *testing.T) {
	mp := memprotect.New()
	defer mp.Cleanup()

	// Test locking all memory
	success := mp.LockAllMemory()
	if !success {
		t.Log("Locking all memory not supported on this platform")
		return
	}

	// Test that we can still allocate and use memory
	data := make([]byte, 1024)
	for i := range data {
		data[i] = byte(i % 256)
	}

	// Test that the data is accessible
	for i := range data {
		expected := byte(i % 256)
		if data[i] != expected {
			t.Errorf("Memory content incorrect after locking all memory at index %d: expected %d, got %d", i, expected, data[i])
		}
	}

	// Unlock all memory
	mp.UnlockAllMemory()
}

// TestMemoryProtectionCleanup tests cleanup functionality
func TestMemoryProtectionCleanup(t *testing.T) {
	mp := memprotect.New()

	// Allocate and lock some memory
	data1 := make([]byte, 1024)
	data2 := make([]byte, 2048)

	mp.LockMemory(data1)
	mp.LockMemory(data2)

	// Cleanup should not panic
	mp.Cleanup()

	// Test that we can still use the memory after cleanup
	for i := range data1 {
		data1[i] = byte(i % 256)
	}
	for i := range data2 {
		data2[i] = byte(i % 256)
	}
}

// TestMemoryProtectionDisabled tests behavior when memory protection is disabled
func TestMemoryProtectionDisabled(t *testing.T) {
	mp := memprotect.New()
	mp.Disable()
	defer mp.Cleanup()

	// Test that allocation still works when disabled
	data := mp.AllocatePageAligned(1024)
	if len(data) != 1024 {
		t.Errorf("Allocation failed when disabled: expected 1024, got %d", len(data))
	}

	// Test that locking returns false when disabled
	success := mp.LockMemory(data)
	if success {
		t.Error("Locking should fail when memory protection is disabled")
	}

	// Test that secure operations still work when disabled
	mp.SecureZero(data)
	for i, b := range data {
		if b != 0 {
			t.Errorf("SecureZero failed when disabled at index %d: expected 0, got %d", i, b)
		}
	}
}

// TestMemoryProtectionPlatformSpecific tests platform-specific functionality
func TestMemoryProtectionPlatformSpecific(t *testing.T) {
	mp := memprotect.New()
	defer mp.Cleanup()

	// Test that we can detect the platform
	pageSize := memprotect.PageSize()
	t.Logf("Page size: %d bytes", pageSize)

	// Test that page size is reasonable
	if pageSize < 1024 || pageSize > 65536 {
		t.Errorf("Page size seems unreasonable: %d bytes", pageSize)
	}

	// Test that page size is a power of 2
	if pageSize&(pageSize-1) != 0 {
		t.Errorf("Page size is not a power of 2: %d", pageSize)
	}
}

// BenchmarkMemoryProtectionAllocation benchmarks memory allocation performance
func BenchmarkMemoryProtectionAllocation(b *testing.B) {
	mp := memprotect.New()
	defer mp.Cleanup()

	sizes := []int{1024, 4096, 16384, 65536}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("Size_%d", size), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				data := mp.AllocatePageAligned(size)
				// Prevent optimization
				_ = data
			}
		})
	}
}

// BenchmarkMemoryProtectionLocking benchmarks memory locking performance
func BenchmarkMemoryProtectionLocking(b *testing.B) {
	mp := memprotect.New()
	defer mp.Cleanup()

	sizes := []int{1024, 4096, 16384, 65536}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("Size_%d", size), func(b *testing.B) {
			data := make([]byte, size)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				mp.LockMemory(data)
				mp.UnlockMemory(data)
			}
		})
	}
}

// BenchmarkMemoryProtectionSecureWipe benchmarks secure wiping performance
func BenchmarkMemoryProtectionSecureWipe(b *testing.B) {
	mp := memprotect.New()
	defer mp.Cleanup()

	sizes := []int{1024, 4096, 16384, 65536}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("Size_%d", size), func(b *testing.B) {
			data := make([]byte, size)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				mp.SecureWipeEnhanced(data)
			}
		})
	}
}
