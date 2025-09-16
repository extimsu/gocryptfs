// Package parallelcrypto provides enhanced parallel encryption and decryption
// for large I/O operations to improve performance on multi-core systems.
package parallelcrypto

import (
	"runtime"
	"sync"

	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

const (
	// ParallelThreshold is the minimum number of blocks to trigger parallel processing
	ParallelThreshold = 4 // Further lowered for better performance on small operations
	// MaxParallelWorkers is the maximum number of parallel workers
	MaxParallelWorkers = 16 // Increased for better multi-core utilization on high-end systems
	// MinParallelWorkers is the minimum number of CPUs required for parallel processing
	MinParallelWorkers = 2
	// BatchThreshold is the minimum number of blocks to use batch processing
	BatchThreshold = 2
)

// ParallelCrypto provides enhanced parallel encryption/decryption capabilities
type ParallelCrypto struct {
	enabled bool
	// CPU-aware optimizations
	cpuCount int
	hasAVX   bool
	hasAVX2  bool
	hasAES   bool
}

// New creates a new ParallelCrypto instance
func New() *ParallelCrypto {
	pc := &ParallelCrypto{
		enabled:  true,
		cpuCount: runtime.NumCPU(),
	}

	// Detect CPU features for optimization
	pc.detectCPUFeatures()

	return pc
}

// detectCPUFeatures detects available CPU features for optimization
func (pc *ParallelCrypto) detectCPUFeatures() {
	// This is a simplified detection - in a real implementation,
	// you would use CPUID or similar to detect actual features
	pc.hasAVX = true  // Assume modern CPUs have AVX
	pc.hasAVX2 = true // Assume modern CPUs have AVX2
	pc.hasAES = true  // Assume modern CPUs have AES-NI
}

// IsEnabled returns whether parallel crypto is enabled
func (pc *ParallelCrypto) IsEnabled() bool {
	return pc.enabled
}

// ShouldUseParallel determines if parallel processing should be used
func (pc *ParallelCrypto) ShouldUseParallel(blockCount int) bool {
	if !pc.enabled {
		return false
	}

	if pc.cpuCount < MinParallelWorkers {
		return false
	}

	return blockCount >= ParallelThreshold
}

// ShouldUseBatch determines if batch processing should be used
func (pc *ParallelCrypto) ShouldUseBatch(blockCount int) bool {
	if !pc.enabled {
		return false
	}

	return blockCount >= BatchThreshold
}

// GetOptimalWorkerCount returns the optimal number of workers for parallel processing
func (pc *ParallelCrypto) GetOptimalWorkerCount(blockCount int) int {
	if !pc.enabled {
		return 1
	}

	// If below threshold, use sequential processing
	if blockCount < ParallelThreshold {
		return 1
	}

	if pc.cpuCount < MinParallelWorkers {
		return 1
	}

	// CPU-aware worker count calculation
	workers := pc.cpuCount

	// Adjust based on CPU features
	if pc.hasAVX2 && pc.hasAES {
		// High-performance CPUs can handle more workers
		workers = int(float64(workers) * 1.5)
	} else if pc.hasAVX {
		// Moderate performance CPUs
		workers = int(float64(workers) * 1.2)
	}

	// Cap at MaxParallelWorkers
	if workers > MaxParallelWorkers {
		workers = MaxParallelWorkers
	}

	// Don't exceed the number of blocks
	if workers > blockCount {
		workers = blockCount
	}

	return workers
}

// ProcessBlocksParallel processes blocks in parallel using the provided function
func (pc *ParallelCrypto) ProcessBlocksParallel(blockCount int, processFunc func(startIdx, endIdx int)) {
	if !pc.ShouldUseParallel(blockCount) {
		// Process sequentially
		processFunc(0, blockCount)
		return
	}

	workers := pc.GetOptimalWorkerCount(blockCount)
	groupSize := blockCount / workers

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			startIdx := workerID * groupSize
			endIdx := (workerID + 1) * groupSize

			// Last worker picks up any remaining blocks
			if workerID == workers-1 {
				endIdx = blockCount
			}

			processFunc(startIdx, endIdx)
		}(i)
	}

	wg.Wait()
}

// ProcessBlocksParallelWithResult processes blocks in parallel and collects results
func (pc *ParallelCrypto) ProcessBlocksParallelWithResult(blockCount int, processFunc func(startIdx, endIdx int) interface{}) []interface{} {
	if !pc.ShouldUseParallel(blockCount) {
		// Process sequentially
		result := processFunc(0, blockCount)
		return []interface{}{result}
	}

	workers := pc.GetOptimalWorkerCount(blockCount)
	groupSize := blockCount / workers
	results := make([]interface{}, workers)

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			startIdx := workerID * groupSize
			endIdx := (workerID + 1) * groupSize

			// Last worker picks up any remaining blocks
			if workerID == workers-1 {
				endIdx = blockCount
			}

			results[workerID] = processFunc(startIdx, endIdx)
		}(i)
	}

	wg.Wait()
	return results
}

// GetPerformanceStats returns performance statistics for parallel processing
func (pc *ParallelCrypto) GetPerformanceStats() map[string]interface{} {
	stats := make(map[string]interface{})
	stats["enabled"] = pc.enabled
	stats["cpu_count"] = runtime.NumCPU()
	stats["parallel_threshold"] = ParallelThreshold
	stats["max_workers"] = MaxParallelWorkers
	stats["min_workers"] = MinParallelWorkers

	if pc.enabled {
		stats["optimal_workers"] = pc.GetOptimalWorkerCount(100) // Example with 100 blocks
	}

	return stats
}

// Disable disables parallel processing (for testing or debugging)
func (pc *ParallelCrypto) Disable() {
	pc.enabled = false
}

// Enable enables parallel processing
func (pc *ParallelCrypto) Enable() {
	pc.enabled = true
}

// ProcessBlocksBatch processes blocks in batches for better cache locality
func (pc *ParallelCrypto) ProcessBlocksBatch(blockCount int, processFunc func(startIdx, endIdx int)) {
	if !pc.ShouldUseBatch(blockCount) {
		// Process sequentially for very small operations
		processFunc(0, blockCount)
		return
	}

	// Use smaller batches for better cache locality
	batchSize := 4
	if pc.hasAVX2 {
		batchSize = 8 // Larger batches for high-performance CPUs
	}

	for i := 0; i < blockCount; i += batchSize {
		endIdx := i + batchSize
		if endIdx > blockCount {
			endIdx = blockCount
		}
		processFunc(i, endIdx)
	}
}

// ProcessBlocksOptimized chooses the best processing method based on block count and CPU features
func (pc *ParallelCrypto) ProcessBlocksOptimized(blockCount int, processFunc func(startIdx, endIdx int)) {
	if pc.ShouldUseParallel(blockCount) {
		pc.ProcessBlocksParallel(blockCount, processFunc)
	} else if pc.ShouldUseBatch(blockCount) {
		pc.ProcessBlocksBatch(blockCount, processFunc)
	} else {
		// Sequential processing for very small operations
		processFunc(0, blockCount)
	}
}

// LogPerformanceInfo logs performance information about parallel processing
func (pc *ParallelCrypto) LogPerformanceInfo() {
	stats := pc.GetPerformanceStats()
	tlog.Debug.Printf("ParallelCrypto: enabled=%v, cpu_count=%v, threshold=%v, max_workers=%v, avx2=%v, aes=%v",
		stats["enabled"], stats["cpu_count"], stats["parallel_threshold"], stats["max_workers"], pc.hasAVX2, pc.hasAES)
}
