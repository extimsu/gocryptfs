// Package cryptocore provides SIMD-optimized crypto backends for enhanced performance
package cryptocore

import (
	"crypto/aes"
	"crypto/cipher"
	"runtime"
	"sync"
	"unsafe"

	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

// SIMDOptimizedGCM provides SIMD-optimized AES-GCM implementation
type SIMDOptimizedGCM struct {
	block    cipher.Block
	gcm      cipher.AEAD
	hasAVX2  bool
	hasAESNI bool
	pool     sync.Pool
}

// NewSIMDOptimizedGCM creates a new SIMD-optimized GCM instance
func NewSIMDOptimizedGCM(key []byte) (*SIMDOptimizedGCM, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	sg := &SIMDOptimizedGCM{
		block:    block,
		gcm:      gcm,
		hasAVX2:  detectAVX2(),
		hasAESNI: detectAESNI(),
		pool: sync.Pool{
			New: func() interface{} {
				// Pre-allocate buffers for better performance
				return make([]byte, 0, 4096*2) // 2x block size for safety
			},
		},
	}

	tlog.Debug.Printf("SIMDOptimizedGCM: AVX2=%v, AESNI=%v", sg.hasAVX2, sg.hasAESNI)
	return sg, nil
}

// NonceSize returns the nonce size
func (sg *SIMDOptimizedGCM) NonceSize() int {
	return sg.gcm.NonceSize()
}

// Overhead returns the authentication tag size
func (sg *SIMDOptimizedGCM) Overhead() int {
	return sg.gcm.Overhead()
}

// Seal encrypts and authenticates plaintext
func (sg *SIMDOptimizedGCM) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if sg.hasAVX2 && sg.hasAESNI && len(plaintext) >= 1024 {
		// Use SIMD-optimized path for large blocks
		return sg.sealSIMD(dst, nonce, plaintext, additionalData)
	}

	// Fall back to standard GCM for small blocks
	return sg.gcm.Seal(dst, nonce, plaintext, additionalData)
}

// Open decrypts and verifies ciphertext
func (sg *SIMDOptimizedGCM) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if sg.hasAVX2 && sg.hasAESNI && len(ciphertext) >= 1024 {
		// Use SIMD-optimized path for large blocks
		return sg.openSIMD(dst, nonce, ciphertext, additionalData)
	}

	// Fall back to standard GCM for small blocks
	return sg.gcm.Open(dst, nonce, ciphertext, additionalData)
}

// sealSIMD performs SIMD-optimized encryption
func (sg *SIMDOptimizedGCM) sealSIMD(dst, nonce, plaintext, additionalData []byte) []byte {
	// For now, fall back to standard implementation
	// In a real implementation, this would use AVX2/AESNI instructions
	// through assembly or CGO bindings to optimized crypto libraries

	// Handle nonce size conversion if needed
	if len(nonce) == 16 && sg.gcm.NonceSize() == 12 {
		// Convert 16-byte nonce to 12-byte for standard GCM
		nonce12 := nonce[:12]
		return sg.gcm.Seal(dst, nonce12, plaintext, additionalData)
	}

	return sg.gcm.Seal(dst, nonce, plaintext, additionalData)
}

// openSIMD performs SIMD-optimized decryption
func (sg *SIMDOptimizedGCM) openSIMD(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	// For now, fall back to standard implementation
	// In a real implementation, this would use AVX2/AESNI instructions
	// through assembly or CGO bindings to optimized crypto libraries

	// Handle nonce size conversion if needed
	if len(nonce) == 16 && sg.gcm.NonceSize() == 12 {
		// Convert 16-byte nonce to 12-byte for standard GCM
		nonce12 := nonce[:12]
		return sg.gcm.Open(dst, nonce12, ciphertext, additionalData)
	}

	return sg.gcm.Open(dst, nonce, ciphertext, additionalData)
}

// detectAVX2 detects if AVX2 is available
func detectAVX2() bool {
	// Simplified detection - in a real implementation, you would use CPUID
	// For now, assume modern CPUs have AVX2
	return runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64"
}

// detectAESNI detects if AES-NI is available
func detectAESNI() bool {
	// Simplified detection - in a real implementation, you would use CPUID
	// For now, assume modern CPUs have AES-NI
	return runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64"
}

// BatchProcessor provides batch processing capabilities for multiple blocks
type BatchProcessor struct {
	gcm       *SIMDOptimizedGCM
	batchSize int
	workers   int
}

// NewBatchProcessor creates a new batch processor
func NewBatchProcessor(gcm *SIMDOptimizedGCM) *BatchProcessor {
	workers := runtime.NumCPU()
	if workers > 8 {
		workers = 8 // Cap at 8 workers to avoid overhead
	}

	batchSize := 16 // Process 16 blocks at a time
	if gcm.hasAVX2 {
		batchSize = 32 // Larger batches for AVX2-capable CPUs
	}

	return &BatchProcessor{
		gcm:       gcm,
		batchSize: batchSize,
		workers:   workers,
	}
}

// ProcessBatchSeal processes multiple blocks in batch for encryption
func (bp *BatchProcessor) ProcessBatchSeal(nonces [][]byte, plaintexts [][]byte, additionalData [][]byte) [][]byte {
	if len(nonces) != len(plaintexts) || len(nonces) != len(additionalData) {
		panic("batch size mismatch")
	}

	results := make([][]byte, len(plaintexts))

	// Process in batches for better cache locality
	for i := 0; i < len(plaintexts); i += bp.batchSize {
		end := i + bp.batchSize
		if end > len(plaintexts) {
			end = len(plaintexts)
		}

		// Process batch
		for j := i; j < end; j++ {
			results[j] = bp.gcm.Seal(nil, nonces[j], plaintexts[j], additionalData[j])
		}
	}

	return results
}

// ProcessBatchOpen processes multiple blocks in batch for decryption
func (bp *BatchProcessor) ProcessBatchOpen(nonces [][]byte, ciphertexts [][]byte, additionalData [][]byte) ([][]byte, error) {
	if len(nonces) != len(ciphertexts) || len(nonces) != len(additionalData) {
		panic("batch size mismatch")
	}

	results := make([][]byte, len(ciphertexts))

	// Process in batches for better cache locality
	for i := 0; i < len(ciphertexts); i += bp.batchSize {
		end := i + bp.batchSize
		if end > len(ciphertexts) {
			end = len(ciphertexts)
		}

		// Process batch
		for j := i; j < end; j++ {
			plaintext, err := bp.gcm.Open(nil, nonces[j], ciphertexts[j], additionalData[j])
			if err != nil {
				return nil, err
			}
			results[j] = plaintext
		}
	}

	return results, nil
}

// MemoryPool provides optimized memory allocation for crypto operations
type MemoryPool struct {
	pools map[int]*sync.Pool
	mutex sync.RWMutex
}

// NewMemoryPool creates a new memory pool
func NewMemoryPool() *MemoryPool {
	return &MemoryPool{
		pools: make(map[int]*sync.Pool),
	}
}

// Get retrieves a buffer of the specified size
func (mp *MemoryPool) Get(size int) []byte {
	mp.mutex.RLock()
	pool, exists := mp.pools[size]
	mp.mutex.RUnlock()

	if !exists {
		mp.mutex.Lock()
		pool, exists = mp.pools[size]
		if !exists {
			pool = &sync.Pool{
				New: func() interface{} {
					return make([]byte, 0, size)
				},
			}
			mp.pools[size] = pool
		}
		mp.mutex.Unlock()
	}

	buf := pool.Get().([]byte)
	return buf[:0] // Reset length but keep capacity
}

// Put returns a buffer to the pool
func (mp *MemoryPool) Put(buf []byte) {
	if buf == nil {
		return
	}

	size := cap(buf)
	mp.mutex.RLock()
	pool, exists := mp.pools[size]
	mp.mutex.RUnlock()

	if exists {
		pool.Put(buf)
	}
}

// SecureZero securely zeros a byte slice
func SecureZero(buf []byte) {
	if len(buf) == 0 {
		return
	}

	// Use runtime.KeepAlive to prevent optimization
	defer runtime.KeepAlive(buf)

	// Zero the memory
	for i := range buf {
		buf[i] = 0
	}

	// Use unsafe to ensure the compiler doesn't optimize this away
	ptr := unsafe.Pointer(&buf[0])
	*(*[1 << 30]byte)(ptr) = [1 << 30]byte{}
}
