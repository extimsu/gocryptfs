package memprotect

import (
	"testing"
)

func TestMemoryProtection(t *testing.T) {
	mp := New()
	if mp == nil {
		t.Fatal("Failed to create MemoryProtection instance")
	}

	// Test basic functionality
	if !mp.IsEnabled() {
		t.Error("Memory protection should be enabled by default")
	}

	// Test with a small buffer
	testData := make([]byte, 1024)
	for i := range testData {
		testData[i] = byte(i % 256)
	}

	// Test locking
	success := mp.LockMemory(testData)
	if success {
		t.Log("Memory locking succeeded")
	} else {
		t.Log("Memory locking failed (may not be supported on this platform)")
	}

	// Test unlocking
	mp.UnlockMemory(testData)

	// Test secure wipe
	mp.SecureWipe(testData)

	// Test cleanup
	mp.Cleanup()
}

func TestMemoryProtectionDisable(t *testing.T) {
	mp := New()
	mp.Disable()

	if mp.IsEnabled() {
		t.Error("Memory protection should be disabled")
	}

	testData := make([]byte, 1024)
	success := mp.LockMemory(testData)
	if success {
		t.Error("Memory locking should fail when disabled")
	}
}

func TestMemoryProtectionEmptyData(t *testing.T) {
	mp := New()

	// Test with empty data
	success := mp.LockMemory(nil)
	if success {
		t.Error("Locking nil data should fail")
	}

	success = mp.LockMemory([]byte{})
	if success {
		t.Error("Locking empty data should fail")
	}

	// These should not panic
	mp.UnlockMemory(nil)
	mp.UnlockMemory([]byte{})
	mp.SecureWipe(nil)
	mp.SecureWipe([]byte{})
}

func TestMemoryProtectionMultipleLocks(t *testing.T) {
	mp := New()

	// Test multiple locks
	data1 := make([]byte, 1024)
	data2 := make([]byte, 2048)

	mp.LockMemory(data1)
	mp.LockMemory(data2)

	// Cleanup
	mp.Cleanup()
}

func BenchmarkMemoryProtection(b *testing.B) {
	mp := New()
	testData := make([]byte, 4096)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mp.LockMemory(testData)
		mp.UnlockMemory(testData)
	}
}

func BenchmarkSecureWipe(b *testing.B) {
	mp := New()
	testData := make([]byte, 4096)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Reset data
		for j := range testData {
			testData[j] = byte(j % 256)
		}
		mp.SecureWipe(testData)
	}
}
