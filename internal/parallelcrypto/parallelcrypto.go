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
	ParallelThreshold = 8 // Lowered from 32 for better performance
	// MaxParallelWorkers is the maximum number of parallel workers
	MaxParallelWorkers = 8 // Increased from 2 for better multi-core utilization
	// MinParallelWorkers is the minimum number of CPUs required for parallel processing
	MinParallelWorkers = 2
)

// ParallelCrypto provides enhanced parallel encryption/decryption capabilities
type ParallelCrypto struct {
	enabled bool
}

// New creates a new ParallelCrypto instance
func New() *ParallelCrypto {
	return &ParallelCrypto{
		enabled: true,
	}
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

	cpuCount := runtime.NumCPU()
	if cpuCount < MinParallelWorkers {
		return false
	}

	return blockCount >= ParallelThreshold
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

	cpuCount := runtime.NumCPU()
	if cpuCount < MinParallelWorkers {
		return 1
	}

	// Use up to MaxParallelWorkers, but not more than the number of blocks
	workers := cpuCount
	if workers > MaxParallelWorkers {
		workers = MaxParallelWorkers
	}
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

// LogPerformanceInfo logs performance information about parallel processing
func (pc *ParallelCrypto) LogPerformanceInfo() {
	stats := pc.GetPerformanceStats()
	tlog.Debug.Printf("ParallelCrypto: enabled=%v, cpu_count=%v, threshold=%v, max_workers=%v",
		stats["enabled"], stats["cpu_count"], stats["parallel_threshold"], stats["max_workers"])
}
