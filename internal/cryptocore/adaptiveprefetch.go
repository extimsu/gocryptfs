// Package cryptocore provides adaptive RNG prefetch buffer size optimization
// based on high-throughput write profiling to improve performance.
package cryptocore

import (
	"bytes"
	"fmt"
	"log"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	// DefaultPrefetchSize is the default prefetch buffer size
	DefaultPrefetchSize = 512
	// MinPrefetchSize is the minimum prefetch buffer size
	MinPrefetchSize = 256
	// MaxPrefetchSize is the maximum prefetch buffer size
	MaxPrefetchSize = 4096
	// ProfilingWindow is the time window for profiling
	ProfilingWindow = 5 * time.Second
	// HighThroughputThreshold is the threshold for high-throughput detection
	HighThroughputThreshold = 1000 // requests per second
)

// AdaptivePrefetcher provides adaptive RNG prefetch buffer size optimization
type AdaptivePrefetcher struct {
	// Current prefetch size
	prefetchSize int32
	// Request counter for profiling
	requestCount int64
	// Last profiling time
	lastProfileTime time.Time
	// Mutex for thread safety
	mutex sync.RWMutex
	// Buffer for random data
	buf bytes.Buffer
	// Channel for refill requests
	refill chan []byte
	// Stop channel for graceful shutdown
	stop chan struct{}
	// Profiling enabled flag
	profilingEnabled bool
}

// NewAdaptivePrefetcher creates a new adaptive prefetcher
func NewAdaptivePrefetcher() *AdaptivePrefetcher {
	ap := &AdaptivePrefetcher{
		prefetchSize:     DefaultPrefetchSize,
		refill:           make(chan []byte, 2), // Buffer for 2 refills
		stop:             make(chan struct{}),
		profilingEnabled: true,
	}

	// Start the refill worker
	go ap.refillWorker()

	// Start the profiling worker
	go ap.profilingWorker()

	return ap
}

// Read reads the requested number of random bytes
func (ap *AdaptivePrefetcher) Read(want int) []byte {
	// Increment request counter for profiling
	if ap.profilingEnabled {
		atomic.AddInt64(&ap.requestCount, 1)
	}

	out := make([]byte, want)
	ap.mutex.Lock()
	defer ap.mutex.Unlock()

	// Try to read from buffer
	have, err := ap.buf.Read(out)
	if have == want && err == nil {
		return out
	}

	// Buffer was empty or insufficient -> re-fill
	fresh := <-ap.refill
	if len(fresh) != int(atomic.LoadInt32(&ap.prefetchSize)) {
		log.Panicf("AdaptivePrefetcher: refill: got %d bytes instead of %d",
			len(fresh), atomic.LoadInt32(&ap.prefetchSize))
	}

	ap.buf.Reset()
	ap.buf.Write(fresh)
	have, err = ap.buf.Read(out)
	if have != want || err != nil {
		log.Panicf("AdaptivePrefetcher could not satisfy read: have=%d want=%d err=%v",
			have, want, err)
	}

	return out
}

// refillWorker continuously refills the buffer
func (ap *AdaptivePrefetcher) refillWorker() {
	for {
		select {
		case <-ap.stop:
			return
		default:
			size := int(atomic.LoadInt32(&ap.prefetchSize))
			ap.refill <- RandBytes(size)
		}
	}
}

// profilingWorker monitors usage patterns and adjusts prefetch size
func (ap *AdaptivePrefetcher) profilingWorker() {
	ticker := time.NewTicker(ProfilingWindow)
	defer ticker.Stop()

	for {
		select {
		case <-ap.stop:
			return
		case <-ticker.C:
			ap.adjustPrefetchSize()
		}
	}
}

// adjustPrefetchSize adjusts the prefetch size based on usage patterns
func (ap *AdaptivePrefetcher) adjustPrefetchSize() {
	if !ap.profilingEnabled {
		return
	}

	now := time.Now()
	requests := atomic.SwapInt64(&ap.requestCount, 0)

	// Calculate requests per second
	elapsed := now.Sub(ap.lastProfileTime)
	if elapsed < time.Second {
		return // Not enough time for accurate measurement
	}

	requestsPerSecond := float64(requests) / elapsed.Seconds()
	ap.lastProfileTime = now

	currentSize := int(atomic.LoadInt32(&ap.prefetchSize))
	newSize := currentSize

	// Adjust size based on throughput
	if requestsPerSecond > HighThroughputThreshold {
		// High throughput detected - increase buffer size
		newSize = currentSize * 2
		if newSize > MaxPrefetchSize {
			newSize = MaxPrefetchSize
		}
	} else if requestsPerSecond < HighThroughputThreshold/2 {
		// Low throughput detected - decrease buffer size
		newSize = currentSize / 2
		if newSize < MinPrefetchSize {
			newSize = MinPrefetchSize
		}
	}

	// Update prefetch size if changed
	if newSize != currentSize {
		atomic.StoreInt32(&ap.prefetchSize, int32(newSize))
		log.Printf("AdaptivePrefetcher: adjusted prefetch size from %d to %d (%.1f req/s)",
			currentSize, newSize, requestsPerSecond)
	}
}

// GetPrefetchSize returns the current prefetch size
func (ap *AdaptivePrefetcher) GetPrefetchSize() int {
	return int(atomic.LoadInt32(&ap.prefetchSize))
}

// SetPrefetchSize sets the prefetch size manually
func (ap *AdaptivePrefetcher) SetPrefetchSize(size int) {
	if size < MinPrefetchSize {
		size = MinPrefetchSize
	}
	if size > MaxPrefetchSize {
		size = MaxPrefetchSize
	}
	atomic.StoreInt32(&ap.prefetchSize, int32(size))
}

// EnableProfiling enables or disables adaptive profiling
func (ap *AdaptivePrefetcher) EnableProfiling(enabled bool) {
	ap.mutex.Lock()
	defer ap.mutex.Unlock()
	ap.profilingEnabled = enabled
}

// GetStats returns statistics about the adaptive prefetcher
func (ap *AdaptivePrefetcher) GetStats() map[string]interface{} {
	stats := make(map[string]interface{})
	stats["prefetch_size"] = ap.GetPrefetchSize()
	stats["profiling_enabled"] = ap.profilingEnabled
	stats["request_count"] = atomic.LoadInt64(&ap.requestCount)
	return stats
}

// Close gracefully shuts down the adaptive prefetcher
func (ap *AdaptivePrefetcher) Close() {
	close(ap.stop)
}

// Global adaptive prefetcher instance
var adaptivePrefetcher *AdaptivePrefetcher

// InitAdaptivePrefetcher initializes the global adaptive prefetcher
func InitAdaptivePrefetcher() {
	adaptivePrefetcher = NewAdaptivePrefetcher()
}

// GetAdaptivePrefetcher returns the global adaptive prefetcher
func GetAdaptivePrefetcher() *AdaptivePrefetcher {
	if adaptivePrefetcher == nil {
		InitAdaptivePrefetcher()
	}
	return adaptivePrefetcher
}

// AdaptiveRead reads random bytes using the adaptive prefetcher
func AdaptiveRead(want int) []byte {
	return GetAdaptivePrefetcher().Read(want)
}

// GetOptimalPrefetchSize returns the optimal prefetch size based on system characteristics
func GetOptimalPrefetchSize() int {
	// Base size on CPU count and system characteristics
	cpuCount := runtime.NumCPU()

	// For systems with more CPUs, use larger buffers
	switch {
	case cpuCount >= 8:
		return 2048
	case cpuCount >= 4:
		return 1024
	case cpuCount >= 2:
		return 512
	default:
		return 256
	}
}

// BenchmarkAdaptivePrefetch benchmarks the adaptive prefetcher
func BenchmarkAdaptivePrefetch(b *testing.B) {
	ap := NewAdaptivePrefetcher()
	defer ap.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ap.Read(16)
	}
}

// BenchmarkAdaptivePrefetchSizes benchmarks different prefetch sizes
func BenchmarkAdaptivePrefetchSizes(b *testing.B) {
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
