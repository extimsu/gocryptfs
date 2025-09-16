package cpudetection

import (
	"testing"
)

func TestCPUDetector(t *testing.T) {
	cd := New()
	if cd == nil {
		t.Fatal("Failed to create CPUDetector instance")
	}

	features := cd.GetFeatures()
	if features == nil {
		t.Fatal("Failed to get CPU features")
	}

	// Test that we have an architecture
	if features.Arch == "" {
		t.Error("CPU architecture should not be empty")
	}

	// Test that we can get a recommended backend
	backend := cd.GetRecommendedBackend()
	if backend == "" {
		t.Error("Recommended backend should not be empty")
	}

	// Test that we can get a performance hint
	hint := cd.GetPerformanceHint()
	if hint == "" {
		t.Error("Performance hint should not be empty")
	}

	// Test architecture detection
	arch := cd.GetArchitecture()
	if arch == "" {
		t.Error("Architecture should not be empty")
	}

	// Test string representation
	str := cd.String()
	if str == "" {
		t.Error("String representation should not be empty")
	}

	t.Logf("Detected CPU: %s", cd.String())
	t.Logf("Recommended backend: %s", backend)
	t.Logf("Performance hint: %s", hint)
}

func TestCPUFeatures(t *testing.T) {
	cd := New()
	_ = cd.GetFeatures() // Get features but don't use them directly

	// Test that we can check for AES optimization
	aesOptimal := cd.IsOptimalForAES()
	t.Logf("Optimal for AES: %v", aesOptimal)

	// Test that we can check for ChaCha optimization
	chachaOptimal := cd.IsOptimalForChaCha()
	t.Logf("Optimal for ChaCha: %v", chachaOptimal)

	// Test that at least one optimization is available
	if !aesOptimal && !chachaOptimal {
		t.Error("At least one encryption optimization should be available")
	}
}

func TestBackendRecommendation(t *testing.T) {
	cd := New()
	backend := cd.GetRecommendedBackend()

	// Test that we get a valid backend
	validBackends := []string{
		"aes-gcm-openssl",
		"aes-gcm-go",
		"xchacha20-poly1305-go",
	}

	valid := false
	for _, validBackend := range validBackends {
		if backend == validBackend {
			valid = true
			break
		}
	}

	if !valid {
		t.Errorf("Invalid backend recommendation: %s", backend)
	}
}

func BenchmarkCPUDetector(b *testing.B) {
	cd := New()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cd.GetRecommendedBackend()
	}
}

func BenchmarkCPUFeatures(b *testing.B) {
	cd := New()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cd.GetFeatures()
	}
}
