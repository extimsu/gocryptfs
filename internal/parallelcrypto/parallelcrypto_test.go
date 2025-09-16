package parallelcrypto

import (
	"sync"
	"testing"
	"time"
)

func TestParallelCrypto(t *testing.T) {
	pc := New()
	if pc == nil {
		t.Fatal("Failed to create ParallelCrypto instance")
	}

	// Test basic functionality
	if !pc.IsEnabled() {
		t.Error("Parallel crypto should be enabled by default")
	}

	// Test threshold detection
	if !pc.ShouldUseParallel(ParallelThreshold) {
		t.Error("Should use parallel for threshold number of blocks")
	}

	if pc.ShouldUseParallel(ParallelThreshold - 1) {
		t.Error("Should not use parallel for below threshold")
	}

	// Test worker count calculation
	workers := pc.GetOptimalWorkerCount(100)
	if workers < 1 {
		t.Error("Should have at least 1 worker")
	}

	// Test performance stats
	stats := pc.GetPerformanceStats()
	if stats["enabled"] != true {
		t.Error("Stats should show enabled=true")
	}
}

func TestParallelCryptoDisabled(t *testing.T) {
	pc := New()
	pc.Disable()

	if pc.IsEnabled() {
		t.Error("Parallel crypto should be disabled")
	}

	if pc.ShouldUseParallel(100) {
		t.Error("Should not use parallel when disabled")
	}

	workers := pc.GetOptimalWorkerCount(100)
	if workers != 1 {
		t.Error("Should have 1 worker when disabled")
	}
}

func TestProcessBlocksParallel(t *testing.T) {
	pc := New()

	// Test with small number of blocks (should be sequential)
	blockCount := ParallelThreshold - 1
	processed := 0

	pc.ProcessBlocksParallel(blockCount, func(startIdx, endIdx int) {
		processed += (endIdx - startIdx)
	})

	if processed != blockCount {
		t.Errorf("Expected %d blocks processed, got %d", blockCount, processed)
	}
}

func TestProcessBlocksParallelLarge(t *testing.T) {
	pc := New()

	// Test with large number of blocks (should be parallel)
	blockCount := ParallelThreshold * 2
	processed := 0
	var mu sync.Mutex

	pc.ProcessBlocksParallel(blockCount, func(startIdx, endIdx int) {
		mu.Lock()
		processed += (endIdx - startIdx)
		mu.Unlock()
	})

	if processed != blockCount {
		t.Errorf("Expected %d blocks processed, got %d", blockCount, processed)
	}
}

func TestProcessBlocksParallelWithResult(t *testing.T) {
	pc := New()

	blockCount := ParallelThreshold * 2
	results := pc.ProcessBlocksParallelWithResult(blockCount, func(startIdx, endIdx int) interface{} {
		return endIdx - startIdx
	})

	totalProcessed := 0
	for _, result := range results {
		if count, ok := result.(int); ok {
			totalProcessed += count
		}
	}

	if totalProcessed != blockCount {
		t.Errorf("Expected %d blocks processed, got %d", blockCount, totalProcessed)
	}
}

func BenchmarkProcessBlocksParallel(b *testing.B) {
	pc := New()
	blockCount := 100

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pc.ProcessBlocksParallel(blockCount, func(startIdx, endIdx int) {
			// Simulate some work
			time.Sleep(time.Microsecond)
		})
	}
}

func BenchmarkProcessBlocksSequential(b *testing.B) {
	pc := New()
	pc.Disable()
	blockCount := 100

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pc.ProcessBlocksParallel(blockCount, func(startIdx, endIdx int) {
			// Simulate some work
			time.Sleep(time.Microsecond)
		})
	}
}

func TestWorkerCountOptimization(t *testing.T) {
	pc := New()

	// Test various block counts
	testCases := []struct {
		blockCount  int
		expectedMin int
		expectedMax int
	}{
		{1, 1, 1},
		{ParallelThreshold - 1, 1, 1},
		{ParallelThreshold, 1, MaxParallelWorkers},
		{100, 1, MaxParallelWorkers},
		{1000, 1, MaxParallelWorkers},
	}

	for _, tc := range testCases {
		workers := pc.GetOptimalWorkerCount(tc.blockCount)
		if workers < tc.expectedMin || workers > tc.expectedMax {
			t.Errorf("Block count %d: expected workers between %d and %d, got %d",
				tc.blockCount, tc.expectedMin, tc.expectedMax, workers)
		}
	}
}
