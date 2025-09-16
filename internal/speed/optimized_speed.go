// Package speed provides optimized speed tests for enhanced crypto backends
package speed

import (
	"crypto/rand"
	"fmt"
	"time"

	"github.com/rfjakob/gocryptfs/v2/internal/cryptocore"
	"github.com/rfjakob/gocryptfs/v2/internal/parallelcrypto"
)

// RunOptimizedSpeedTests runs comprehensive speed tests including optimized backends
func RunOptimizedSpeedTests() {
	fmt.Println("=== Enhanced Crypto Performance Tests ===")
	fmt.Println()

	// Test optimized backends
	runOptimizedBackendTests()
	fmt.Println()

	// Test parallel processing improvements
	runParallelProcessingTests()
	fmt.Println()

	// Test batch processing
	runBatchProcessingTests()
	fmt.Println()

	// Test memory allocation optimizations
	runMemoryOptimizationTests()
	fmt.Println()

	// Test CPU-aware optimizations
	runCPUAwareTests()
}

// runOptimizedBackendTests tests the new optimized crypto backends
func runOptimizedBackendTests() {
	fmt.Println("--- Optimized Backend Performance ---")

	// Generate test key
	key := make([]byte, 32)
	rand.Read(key)

	// Test different backend types
	backends := []struct {
		name    string
		backend func([]byte) (interface{}, error)
	}{
		{"Standard GCM", func(k []byte) (interface{}, error) {
			cc := cryptocore.New(k, cryptocore.BackendGoGCM, 128, true)
			return cc, nil
		}},
		{"Optimized Backend", func(k []byte) (interface{}, error) {
			return cryptocore.NewOptimizedBackend(k)
		}},
	}

	// Test different data sizes
	sizes := []int{1024, 4096, 16384, 65536, 262144} // 1KB to 256KB

	for _, backend := range backends {
		fmt.Printf("%-20s: ", backend.name)

		// Create backend instance
		instance, err := backend.backend(key)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			continue
		}

		// Run benchmarks for different sizes
		totalMBps := 0.0
		validTests := 0

		for _, size := range sizes {
			mbps := benchmarkBackend(instance, size)
			if mbps > 0 {
				totalMBps += mbps
				validTests++
			}
		}

		if validTests > 0 {
			avgMBps := totalMBps / float64(validTests)
			fmt.Printf("%7.2f MB/s (avg)\n", avgMBps)
		} else {
			fmt.Printf("    N/A\n")
		}
	}
}

// benchmarkBackend benchmarks a specific backend with given data size
func benchmarkBackend(backend interface{}, size int) float64 {
	// Generate test data
	plaintext := make([]byte, size)
	rand.Read(plaintext)

	// Use correct nonce size for CryptoCore (16 bytes for 128-bit IV)
	nonce := make([]byte, 16)
	rand.Read(nonce)

	additionalData := make([]byte, 24)
	rand.Read(additionalData)

	// Run benchmark
	start := time.Now()
	iterations := 1000

	for i := 0; i < iterations; i++ {
		switch b := backend.(type) {
		case *cryptocore.CryptoCore:
			// Test with CryptoCore
			ciphertext := b.AEADCipher.Seal(nil, nonce, plaintext, additionalData)
			_, err := b.AEADCipher.Open(nil, nonce, ciphertext, additionalData)
			if err != nil {
				return 0
			}
		case *cryptocore.OptimizedBackend:
			// Test with OptimizedBackend
			ciphertext := b.Seal(nil, nonce, plaintext, additionalData)
			_, err := b.Open(nil, nonce, ciphertext, additionalData)
			if err != nil {
				return 0
			}
		default:
			return 0
		}
	}

	elapsed := time.Since(start)
	bytesProcessed := int64(size * iterations)
	mbps := float64(bytesProcessed) / elapsed.Seconds() / 1024 / 1024

	return mbps
}

// runParallelProcessingTests tests parallel processing improvements
func runParallelProcessingTests() {
	fmt.Println("--- Parallel Processing Performance ---")

	pc := parallelcrypto.New()

	// Test different block counts
	blockCounts := []int{1, 2, 4, 8, 16, 32, 64, 128, 256}

	fmt.Printf("%-15s %-10s %-15s %-15s\n", "Blocks", "Sequential", "Parallel", "Speedup")
	fmt.Println("--------------------------------------------------------")

	for _, blocks := range blockCounts {
		// Benchmark sequential processing
		seqTime := benchmarkSequential(blocks)

		// Benchmark parallel processing
		parTime := benchmarkParallel(pc, blocks)

		speedup := 1.0
		if parTime > 0 {
			speedup = seqTime / parTime
		}

		fmt.Printf("%-15d %-10.2f %-15.2f %-15.2fx\n",
			blocks, seqTime, parTime, speedup)
	}
}

// benchmarkSequential benchmarks sequential processing
func benchmarkSequential(blocks int) float64 {
	start := time.Now()

	// Simulate work
	for i := 0; i < blocks; i++ {
		// Simulate encryption work
		dummy := make([]byte, 4096)
		for j := range dummy {
			dummy[j] = byte(i + j)
		}
	}

	elapsed := time.Since(start)
	return elapsed.Seconds()
}

// benchmarkParallel benchmarks parallel processing
func benchmarkParallel(pc *parallelcrypto.ParallelCrypto, blocks int) float64 {
	start := time.Now()

	pc.ProcessBlocksOptimized(blocks, func(startIdx, endIdx int) {
		for i := startIdx; i < endIdx; i++ {
			// Simulate encryption work
			dummy := make([]byte, 4096)
			for j := range dummy {
				dummy[j] = byte(i + j)
			}
		}
	})

	elapsed := time.Since(start)
	return elapsed.Seconds()
}

// runBatchProcessingTests tests batch processing performance
func runBatchProcessingTests() {
	fmt.Println("--- Batch Processing Performance ---")

	pc := parallelcrypto.New()

	// Test different batch sizes
	batchSizes := []int{1, 2, 4, 8, 16, 32}

	fmt.Printf("%-15s %-15s %-15s %-15s\n", "Batch Size", "Sequential", "Batch", "Speedup")
	fmt.Println("--------------------------------------------------------")

	for _, batchSize := range batchSizes {
		// Benchmark sequential processing
		seqTime := benchmarkSequential(batchSize)

		// Benchmark batch processing
		batchTime := benchmarkBatch(pc, batchSize)

		speedup := 1.0
		if batchTime > 0 {
			speedup = seqTime / batchTime
		}

		fmt.Printf("%-15d %-15.2f %-15.2f %-15.2fx\n",
			batchSize, seqTime, batchTime, speedup)
	}
}

// benchmarkBatch benchmarks batch processing
func benchmarkBatch(pc *parallelcrypto.ParallelCrypto, blocks int) float64 {
	start := time.Now()

	pc.ProcessBlocksBatch(blocks, func(startIdx, endIdx int) {
		for i := startIdx; i < endIdx; i++ {
			// Simulate encryption work
			dummy := make([]byte, 4096)
			for j := range dummy {
				dummy[j] = byte(i + j)
			}
		}
	})

	elapsed := time.Since(start)
	return elapsed.Seconds()
}

// runMemoryOptimizationTests tests memory allocation optimizations
func runMemoryOptimizationTests() {
	fmt.Println("--- Memory Optimization Performance ---")

	// Test different allocation strategies
	strategies := []struct {
		name string
		fn   func(int) []byte
	}{
		{"Standard make()", func(size int) []byte {
			return make([]byte, size)
		}},
		{"Pre-allocated", func(size int) []byte {
			buf := make([]byte, 0, size*2) // Pre-allocate extra capacity
			return buf[:size]
		}},
		{"Pool-based", func(size int) []byte {
			// Simulate pool-based allocation
			if size <= 4096 {
				return make([]byte, 0, 4096)
			} else if size <= 16384 {
				return make([]byte, 0, 16384)
			} else {
				return make([]byte, 0, 65536)
			}
		}},
	}

	sizes := []int{1024, 4096, 16384, 65536}

	fmt.Printf("%-15s", "Strategy")
	for _, size := range sizes {
		fmt.Printf(" %-10s", fmt.Sprintf("%dKB", size/1024))
	}
	fmt.Println()
	fmt.Println("--------------------------------------------------------")

	for _, strategy := range strategies {
		fmt.Printf("%-15s", strategy.name)
		for _, size := range sizes {
			time := benchmarkAllocation(strategy.fn, size)
			fmt.Printf(" %-10.2f", time)
		}
		fmt.Println()
	}
}

// benchmarkAllocation benchmarks memory allocation
func benchmarkAllocation(allocFn func(int) []byte, size int) float64 {
	iterations := 10000
	start := time.Now()

	for i := 0; i < iterations; i++ {
		buf := allocFn(size)
		// Use the buffer to prevent optimization
		for j := range buf {
			buf[j] = byte(i + j)
		}
	}

	elapsed := time.Since(start)
	return elapsed.Seconds()
}

// runCPUAwareTests tests CPU-aware optimizations
func runCPUAwareTests() {
	fmt.Println("--- CPU-Aware Optimization Performance ---")

	pc := parallelcrypto.New()
	stats := pc.GetPerformanceStats()

	fmt.Printf("CPU Count: %v\n", stats["cpu_count"])
	fmt.Printf("Parallel Threshold: %v\n", stats["parallel_threshold"])
	fmt.Printf("Max Workers: %v\n", stats["max_workers"])
	fmt.Printf("AVX2 Support: %v\n", stats["avx2"])
	fmt.Printf("AES Support: %v\n", stats["aes"])

	// Test optimal worker count calculation
	fmt.Println("\nOptimal Worker Counts:")
	blockCounts := []int{1, 4, 8, 16, 32, 64, 128, 256, 512, 1024}

	for _, blocks := range blockCounts {
		workers := pc.GetOptimalWorkerCount(blocks)
		fmt.Printf("  %d blocks -> %d workers\n", blocks, workers)
	}
}
