// Package writecoalescing provides per-file write buffer for small-write coalescing
// before encryption to improve performance for applications that make many small writes.
package writecoalescing

import (
	"sync"
	"time"

	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

const (
	// DefaultCoalesceThreshold is the minimum size to trigger coalescing
	DefaultCoalesceThreshold = 1024 // 1KB
	// DefaultCoalesceTimeout is the maximum time to wait for more writes
	DefaultCoalesceTimeout = 10 * time.Millisecond
	// DefaultMaxCoalesceSize is the maximum size to coalesce before forcing a flush
	DefaultMaxCoalesceSize = 64 * 1024 // 64KB
)

// WriteBuffer represents a coalescing write buffer for a single file
type WriteBuffer struct {
	// Buffer holds the coalesced data
	Buffer []byte
	// Offset is the current write position
	Offset int64
	// LastWriteTime is when the last write occurred
	LastWriteTime time.Time
	// FlushCallback is called when the buffer needs to be flushed
	FlushCallback func(data []byte, offset int64) error
	// Mutex protects concurrent access
	Mutex sync.Mutex
	// Config holds the coalescing configuration
	Config *CoalesceConfig
}

// CoalesceConfig holds configuration for write coalescing
type CoalesceConfig struct {
	// Threshold is the minimum write size to trigger coalescing
	Threshold int
	// Timeout is the maximum time to wait for more writes
	Timeout time.Duration
	// MaxSize is the maximum buffer size before forcing a flush
	MaxSize int
	// Enabled controls whether coalescing is active
	Enabled bool
}

// DefaultConfig returns a default coalescing configuration
func DefaultConfig() *CoalesceConfig {
	return &CoalesceConfig{
		Threshold: DefaultCoalesceThreshold,
		Timeout:   DefaultCoalesceTimeout,
		MaxSize:   DefaultMaxCoalesceSize,
		Enabled:   true,
	}
}

// NewWriteBuffer creates a new write buffer with the given configuration
func NewWriteBuffer(config *CoalesceConfig, flushCallback func(data []byte, offset int64) error) *WriteBuffer {
	if config == nil {
		config = DefaultConfig()
	}

	return &WriteBuffer{
		Buffer:        make([]byte, 0, config.MaxSize),
		FlushCallback: flushCallback,
		Config:        config,
	}
}

// Write adds data to the buffer and potentially flushes it
func (wb *WriteBuffer) Write(data []byte, offset int64) error {
	if !wb.Config.Enabled {
		// If coalescing is disabled, flush immediately
		return wb.FlushCallback(data, offset)
	}

	wb.Mutex.Lock()
	defer wb.Mutex.Unlock()

	// If this is a large write, flush any existing buffer first
	if len(data) >= wb.Config.Threshold {
		if len(wb.Buffer) > 0 {
			err := wb.flushLocked()
			if err != nil {
				return err
			}
		}
		// For large writes, don't buffer - write directly
		return wb.FlushCallback(data, offset)
	}

	// Check if we need to flush due to timeout
	now := time.Now()
	if len(wb.Buffer) > 0 && now.Sub(wb.LastWriteTime) > wb.Config.Timeout {
		err := wb.flushLocked()
		if err != nil {
			return err
		}
	}

	// Check if we need to flush due to buffer size
	if len(wb.Buffer)+len(data) > wb.Config.MaxSize {
		err := wb.flushLocked()
		if err != nil {
			return err
		}
	}

	// Add data to buffer
	if len(wb.Buffer) == 0 {
		wb.Offset = offset
	}
	wb.Buffer = append(wb.Buffer, data...)
	wb.LastWriteTime = now

	return nil
}

// Flush forces a flush of the current buffer
func (wb *WriteBuffer) Flush() error {
	wb.Mutex.Lock()
	defer wb.Mutex.Unlock()
	return wb.flushLocked()
}

// flushLocked flushes the buffer (must be called with mutex held)
func (wb *WriteBuffer) flushLocked() error {
	if len(wb.Buffer) == 0 {
		return nil
	}

	// Make a copy of the buffer data
	data := make([]byte, len(wb.Buffer))
	copy(data, wb.Buffer)
	offset := wb.Offset

	// Clear the buffer
	wb.Buffer = wb.Buffer[:0]

	// Call the flush callback
	return wb.FlushCallback(data, offset)
}

// Close flushes any remaining data and closes the buffer
func (wb *WriteBuffer) Close() error {
	return wb.Flush()
}

// GetBufferSize returns the current buffer size
func (wb *WriteBuffer) GetBufferSize() int {
	wb.Mutex.Lock()
	defer wb.Mutex.Unlock()
	return len(wb.Buffer)
}

// GetConfig returns the coalescing configuration
func (wb *WriteBuffer) GetConfig() *CoalesceConfig {
	return wb.Config
}

// SetConfig updates the coalescing configuration
func (wb *WriteBuffer) SetConfig(config *CoalesceConfig) {
	wb.Mutex.Lock()
	defer wb.Mutex.Unlock()
	wb.Config = config
}

// WriteBufferManager manages write buffers for multiple files
type WriteBufferManager struct {
	// Buffers maps file identifiers to write buffers
	Buffers map[string]*WriteBuffer
	// Mutex protects the buffers map
	Mutex sync.RWMutex
	// Config is the default configuration for new buffers
	Config *CoalesceConfig
	// FlushCallback is the default flush callback
	FlushCallback func(fileID string, data []byte, offset int64) error
}

// NewWriteBufferManager creates a new write buffer manager
func NewWriteBufferManager(config *CoalesceConfig, flushCallback func(fileID string, data []byte, offset int64) error) *WriteBufferManager {
	if config == nil {
		config = DefaultConfig()
	}

	return &WriteBufferManager{
		Buffers:       make(map[string]*WriteBuffer),
		Config:        config,
		FlushCallback: flushCallback,
	}
}

// GetBuffer gets or creates a write buffer for the given file ID
func (wbm *WriteBufferManager) GetBuffer(fileID string) *WriteBuffer {
	wbm.Mutex.RLock()
	buffer, exists := wbm.Buffers[fileID]
	wbm.Mutex.RUnlock()

	if exists {
		return buffer
	}

	// Create a new buffer
	wbm.Mutex.Lock()
	defer wbm.Mutex.Unlock()

	// Check again in case another goroutine created it
	if buffer, exists := wbm.Buffers[fileID]; exists {
		return buffer
	}

	// Create flush callback for this specific file
	flushCallback := func(data []byte, offset int64) error {
		return wbm.FlushCallback(fileID, data, offset)
	}

	buffer = NewWriteBuffer(wbm.Config, flushCallback)
	wbm.Buffers[fileID] = buffer

	return buffer
}

// Write writes data to the buffer for the given file ID
func (wbm *WriteBufferManager) Write(fileID string, data []byte, offset int64) error {
	buffer := wbm.GetBuffer(fileID)
	return buffer.Write(data, offset)
}

// Flush flushes the buffer for the given file ID
func (wbm *WriteBufferManager) Flush(fileID string) error {
	wbm.Mutex.RLock()
	buffer, exists := wbm.Buffers[fileID]
	wbm.Mutex.RUnlock()

	if !exists {
		return nil
	}

	return buffer.Flush()
}

// FlushAll flushes all buffers
func (wbm *WriteBufferManager) FlushAll() error {
	wbm.Mutex.RLock()
	buffers := make([]*WriteBuffer, 0, len(wbm.Buffers))
	for _, buffer := range wbm.Buffers {
		buffers = append(buffers, buffer)
	}
	wbm.Mutex.RUnlock()

	var lastErr error
	for _, buffer := range buffers {
		if err := buffer.Flush(); err != nil {
			lastErr = err
		}
	}

	return lastErr
}

// Close closes and flushes all buffers
func (wbm *WriteBufferManager) Close() error {
	wbm.Mutex.Lock()
	defer wbm.Mutex.Unlock()

	var lastErr error
	for fileID, buffer := range wbm.Buffers {
		if err := buffer.Close(); err != nil {
			lastErr = err
		}
		delete(wbm.Buffers, fileID)
	}

	return lastErr
}

// GetStats returns statistics about the write buffer manager
func (wbm *WriteBufferManager) GetStats() map[string]interface{} {
	wbm.Mutex.RLock()
	defer wbm.Mutex.RUnlock()

	stats := make(map[string]interface{})
	stats["buffer_count"] = len(wbm.Buffers)
	stats["config"] = wbm.Config

	totalBufferSize := 0
	for _, buffer := range wbm.Buffers {
		totalBufferSize += buffer.GetBufferSize()
	}
	stats["total_buffer_size"] = totalBufferSize

	return stats
}

// LogStats logs statistics about the write buffer manager
func (wbm *WriteBufferManager) LogStats() {
	stats := wbm.GetStats()
	tlog.Debug.Printf("WriteBufferManager: buffer_count=%v, total_buffer_size=%v",
		stats["buffer_count"], stats["total_buffer_size"])
}
