package processhardening

import (
	"testing"
)

func TestProcessHardening(t *testing.T) {
	ph := New()
	if ph == nil {
		t.Fatal("Failed to create ProcessHardening instance")
	}

	// Test basic functionality
	if !ph.IsEnabled() {
		t.Error("Process hardening should be enabled by default")
	}

	// Test hardening process
	ph.HardenProcess()

	// Test with a small buffer
	testData := make([]byte, 1024)
	for i := range testData {
		testData[i] = byte(i % 256)
	}

	// Test KeepAlive
	ph.KeepAlive(testData)

	// Test SecureWipe
	ph.SecureWipe(testData)
}

func TestProcessHardeningDisable(t *testing.T) {
	ph := New()
	ph.Disable()

	if ph.IsEnabled() {
		t.Error("Process hardening should be disabled")
	}

	// These should not panic when disabled
	ph.HardenProcess()

	testData := make([]byte, 1024)
	ph.KeepAlive(testData)
	ph.SecureWipe(testData)
}

func TestProcessHardeningEmptyData(t *testing.T) {
	ph := New()

	// These should not panic
	ph.KeepAlive(nil)
	ph.KeepAlive([]byte{})
	ph.SecureWipe(nil)
	ph.SecureWipe([]byte{})
}

func BenchmarkProcessHardening(b *testing.B) {
	ph := New()
	testData := make([]byte, 4096)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ph.KeepAlive(testData)
	}
}

func BenchmarkSecureWipe(b *testing.B) {
	ph := New()
	testData := make([]byte, 4096)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Reset data
		for j := range testData {
			testData[j] = byte(j % 256)
		}
		ph.SecureWipe(testData)
	}
}
