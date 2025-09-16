// Package cryptocore provides optimized crypto backends with enhanced performance
package cryptocore

import (
	"crypto/aes"
	"crypto/cipher"
	"runtime"
	"sync"

	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

// OptimizedBackend provides high-performance crypto operations
type OptimizedBackend struct {
	// Core crypto components
	block     cipher.Block
	gcm       cipher.AEAD
	simdGCM   *SIMDOptimizedGCM
	batchProc *BatchProcessor
	memPool   *MemoryPool

	// Performance optimizations
	hasAVX2  bool
	hasAESNI bool
	cpuCount int

	// Thread-safe pools for different buffer sizes
	smallPool  sync.Pool // 4KB buffers
	mediumPool sync.Pool // 16KB buffers
	largePool  sync.Pool // 64KB+ buffers
}

// NewOptimizedBackend creates a new optimized crypto backend
func NewOptimizedBackend(key []byte) (*OptimizedBackend, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	simdGCM, err := NewSIMDOptimizedGCM(key)
	if err != nil {
		return nil, err
	}

	ob := &OptimizedBackend{
		block:    block,
		gcm:      gcm,
		simdGCM:  simdGCM,
		cpuCount: runtime.NumCPU(),
		hasAVX2:  detectAVX2(),
		hasAESNI: detectAESNI(),
		memPool:  NewMemoryPool(),
	}

	// Initialize batch processor
	ob.batchProc = NewBatchProcessor(ob.simdGCM)

	// Initialize memory pools
	ob.initializePools()

	tlog.Debug.Printf("OptimizedBackend: CPUs=%d, AVX2=%v, AESNI=%v",
		ob.cpuCount, ob.hasAVX2, ob.hasAESNI)

	return ob, nil
}

// initializePools sets up memory pools for different buffer sizes
func (ob *OptimizedBackend) initializePools() {
	// Small pool for 4KB blocks
	ob.smallPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 0, 4096)
		},
	}

	// Medium pool for 16KB buffers
	ob.mediumPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 0, 16384)
		},
	}

	// Large pool for 64KB+ buffers
	ob.largePool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 0, 65536)
		},
	}
}

// GetBuffer returns an appropriately sized buffer from the pool
func (ob *OptimizedBackend) GetBuffer(size int) []byte {
	if size <= 4096 {
		buf := ob.smallPool.Get().([]byte)
		return buf[:0]
	} else if size <= 16384 {
		buf := ob.mediumPool.Get().([]byte)
		return buf[:0]
	} else {
		buf := ob.largePool.Get().([]byte)
		return buf[:0]
	}
}

// PutBuffer returns a buffer to the appropriate pool
func (ob *OptimizedBackend) PutBuffer(buf []byte) {
	if buf == nil {
		return
	}

	capacity := cap(buf)
	if capacity <= 4096 {
		ob.smallPool.Put(buf)
	} else if capacity <= 16384 {
		ob.mediumPool.Put(buf)
	} else {
		ob.largePool.Put(buf)
	}
}

// NonceSize returns the nonce size
func (ob *OptimizedBackend) NonceSize() int {
	return ob.gcm.NonceSize()
}

// Overhead returns the authentication tag size
func (ob *OptimizedBackend) Overhead() int {
	return ob.gcm.Overhead()
}

// Seal encrypts and authenticates plaintext with optimizations
func (ob *OptimizedBackend) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	// Choose the best implementation based on data size and CPU features
	if len(plaintext) >= 1024 && ob.hasAVX2 && ob.hasAESNI {
		// Use SIMD-optimized path for large blocks
		return ob.simdGCM.Seal(dst, nonce, plaintext, additionalData)
	}

	// Use standard GCM for smaller blocks
	// Handle nonce size conversion if needed
	if len(nonce) == 16 && ob.gcm.NonceSize() == 12 {
		// Convert 16-byte nonce to 12-byte for standard GCM
		nonce12 := nonce[:12]
		return ob.gcm.Seal(dst, nonce12, plaintext, additionalData)
	}

	return ob.gcm.Seal(dst, nonce, plaintext, additionalData)
}

// Open decrypts and verifies ciphertext with optimizations
func (ob *OptimizedBackend) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	// Choose the best implementation based on data size and CPU features
	if len(ciphertext) >= 1024 && ob.hasAVX2 && ob.hasAESNI {
		// Use SIMD-optimized path for large blocks
		return ob.simdGCM.Open(dst, nonce, ciphertext, additionalData)
	}

	// Use standard GCM for smaller blocks
	// Handle nonce size conversion if needed
	if len(nonce) == 16 && ob.gcm.NonceSize() == 12 {
		// Convert 16-byte nonce to 12-byte for standard GCM
		nonce12 := nonce[:12]
		return ob.gcm.Open(dst, nonce12, ciphertext, additionalData)
	}

	return ob.gcm.Open(dst, nonce, ciphertext, additionalData)
}

// BatchSeal encrypts multiple blocks in batch for better performance
func (ob *OptimizedBackend) BatchSeal(nonces [][]byte, plaintexts [][]byte, additionalData [][]byte) [][]byte {
	if len(nonces) == 0 {
		return nil
	}

	// Use batch processor for multiple blocks
	return ob.batchProc.ProcessBatchSeal(nonces, plaintexts, additionalData)
}

// BatchOpen decrypts multiple blocks in batch for better performance
func (ob *OptimizedBackend) BatchOpen(nonces [][]byte, ciphertexts [][]byte, additionalData [][]byte) ([][]byte, error) {
	if len(nonces) == 0 {
		return nil, nil
	}

	// Use batch processor for multiple blocks
	return ob.batchProc.ProcessBatchOpen(nonces, ciphertexts, additionalData)
}

// GetOptimalWorkerCount returns the optimal number of workers for parallel operations
func (ob *OptimizedBackend) GetOptimalWorkerCount(blockCount int) int {
	if blockCount < 4 {
		return 1
	}

	// Base worker count on CPU cores
	workers := ob.cpuCount

	// Adjust based on CPU features
	if ob.hasAVX2 && ob.hasAESNI {
		// High-performance CPUs can handle more workers
		workers = int(float64(workers) * 1.5)
	} else if ob.hasAVX2 {
		// Moderate performance CPUs
		workers = int(float64(workers) * 1.2)
	}

	// Cap at reasonable maximum
	if workers > 16 {
		workers = 16
	}

	// Don't exceed the number of blocks
	if workers > blockCount {
		workers = blockCount
	}

	return workers
}

// GetPerformanceStats returns performance statistics
func (ob *OptimizedBackend) GetPerformanceStats() map[string]interface{} {
	stats := make(map[string]interface{})
	stats["cpu_count"] = ob.cpuCount
	stats["has_avx2"] = ob.hasAVX2
	stats["has_aesni"] = ob.hasAESNI
	stats["nonce_size"] = ob.NonceSize()
	stats["overhead"] = ob.Overhead()

	// Example optimal worker count
	stats["optimal_workers_100_blocks"] = ob.GetOptimalWorkerCount(100)
	stats["optimal_workers_1000_blocks"] = ob.GetOptimalWorkerCount(1000)

	return stats
}

// Wipe securely clears sensitive data
func (ob *OptimizedBackend) Wipe() {
	// Clear the block cipher
	if ob.block != nil {
		// The block cipher doesn't expose its key, so we can't wipe it directly
		// The key should be wiped by the caller
		ob.block = nil
	}

	// Clear other components
	ob.gcm = nil
	ob.simdGCM = nil
	ob.batchProc = nil
	ob.memPool = nil
}
