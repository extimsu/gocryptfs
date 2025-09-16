package cryptocore

import (
	"fmt"
	"testing"
)

func TestAdaptivePrefetcher(t *testing.T) {
	ap := NewAdaptivePrefetcher()
	defer ap.Close()

	// Test basic functionality
	data := ap.Read(16)
	if len(data) != 16 {
		t.Errorf("Expected 16 bytes, got %d", len(data))
	}

	// Test multiple reads
	for i := 0; i < 100; i++ {
		data := ap.Read(32)
		if len(data) != 32 {
			t.Errorf("Expected 32 bytes, got %d", len(data))
		}
	}

	// Test prefetch size
	size := ap.GetPrefetchSize()
	if size < MinPrefetchSize || size > MaxPrefetchSize {
		t.Errorf("Prefetch size %d is outside valid range [%d, %d]",
			size, MinPrefetchSize, MaxPrefetchSize)
	}
}

func TestAdaptivePrefetcherSizeAdjustment(t *testing.T) {
	ap := NewAdaptivePrefetcher()
	defer ap.Close()

	// Set initial size
	ap.SetPrefetchSize(512)
	if ap.GetPrefetchSize() != 512 {
		t.Errorf("Expected prefetch size 512, got %d", ap.GetPrefetchSize())
	}

	// Test size limits
	ap.SetPrefetchSize(100) // Below minimum
	if ap.GetPrefetchSize() != MinPrefetchSize {
		t.Errorf("Expected prefetch size %d, got %d", MinPrefetchSize, ap.GetPrefetchSize())
	}

	ap.SetPrefetchSize(10000) // Above maximum
	if ap.GetPrefetchSize() != MaxPrefetchSize {
		t.Errorf("Expected prefetch size %d, got %d", MaxPrefetchSize, ap.GetPrefetchSize())
	}
}

func TestAdaptivePrefetcherProfiling(t *testing.T) {
	ap := NewAdaptivePrefetcher()
	defer ap.Close()

	// Enable profiling
	ap.EnableProfiling(true)

	// Generate some load
	for i := 0; i < 1000; i++ {
		ap.Read(16)
	}

	// Check stats
	stats := ap.GetStats()
	if stats["profiling_enabled"] != true {
		t.Error("Profiling should be enabled")
	}

	// Disable profiling
	ap.EnableProfiling(false)
	stats = ap.GetStats()
	if stats["profiling_enabled"] != false {
		t.Error("Profiling should be disabled")
	}
}

func TestGetOptimalPrefetchSize(t *testing.T) {
	size := GetOptimalPrefetchSize()
	if size < MinPrefetchSize || size > MaxPrefetchSize {
		t.Errorf("Optimal prefetch size %d is outside valid range [%d, %d]",
			size, MinPrefetchSize, MaxPrefetchSize)
	}
}

func TestGlobalAdaptivePrefetcher(t *testing.T) {
	// Test global prefetcher
	ap := GetAdaptivePrefetcher()
	if ap == nil {
		t.Fatal("Global adaptive prefetcher should not be nil")
	}

	// Test adaptive read
	data := AdaptiveRead(16)
	if len(data) != 16 {
		t.Errorf("Expected 16 bytes, got %d", len(data))
	}
}

func BenchmarkAdaptivePrefetcher(b *testing.B) {
	ap := NewAdaptivePrefetcher()
	defer ap.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ap.Read(16)
	}
}

func BenchmarkAdaptivePrefetcherSizes(b *testing.B) {
	sizes := []int{256, 512, 1024, 2048, 4096}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("size_%d", size), func(b *testing.B) {
			ap := NewAdaptivePrefetcher()
			ap.SetPrefetchSize(size)
			defer ap.Close()

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				ap.Read(16)
			}
		})
	}
}

func BenchmarkAdaptivePrefetcherVsOriginal(b *testing.B) {
	// Benchmark adaptive prefetcher
	b.Run("adaptive", func(b *testing.B) {
		ap := NewAdaptivePrefetcher()
		defer ap.Close()

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			ap.Read(16)
		}
	})

	// Benchmark original prefetcher
	b.Run("original", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			randPrefetcher.read(16)
		}
	})
}

func TestAdaptivePrefetcherConcurrency(t *testing.T) {
	ap := NewAdaptivePrefetcher()
	defer ap.Close()

	// Test concurrent access
	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				data := ap.Read(16)
				if len(data) != 16 {
					t.Errorf("Expected 16 bytes, got %d", len(data))
				}
			}
			done <- true
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}
}
