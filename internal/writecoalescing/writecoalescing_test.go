package writecoalescing

import (
	"sync"
	"testing"
	"time"
)

func TestWriteBuffer(t *testing.T) {
	var flushedData []byte
	var flushCount int
	var mu sync.Mutex

	flushCallback := func(data []byte, offset int64) error {
		mu.Lock()
		defer mu.Unlock()
		flushedData = make([]byte, len(data))
		copy(flushedData, data)
		flushCount++
		return nil
	}

	config := &CoalesceConfig{
		Threshold: 1024,
		Timeout:   10 * time.Millisecond,
		MaxSize:   4096,
		Enabled:   true,
	}

	wb := NewWriteBuffer(config, flushCallback)

	// Test small write (should be buffered)
	err := wb.Write([]byte("hello"), 0)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// Should not be flushed yet
	mu.Lock()
	if flushCount != 0 {
		t.Error("Small write should not trigger immediate flush")
	}
	mu.Unlock()

	// Test large write (should trigger flush of buffer + direct write)
	err = wb.Write(make([]byte, 2048), 5)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// Should have flushed the small write (buffer) and the large write (direct)
	mu.Lock()
	if flushCount != 2 {
		t.Errorf("Expected 2 flushes, got %d", flushCount)
	}
	mu.Unlock()
}

func TestWriteBufferDisabled(t *testing.T) {
	var flushCount int
	var mu sync.Mutex

	flushCallback := func(data []byte, offset int64) error {
		mu.Lock()
		defer mu.Unlock()
		flushCount++
		return nil
	}

	config := &CoalesceConfig{
		Enabled: false,
	}

	wb := NewWriteBuffer(config, flushCallback)

	// Test small write (should be flushed immediately when disabled)
	err := wb.Write([]byte("hello"), 0)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// Should be flushed immediately
	mu.Lock()
	if flushCount != 1 {
		t.Errorf("Expected 1 flush, got %d", flushCount)
	}
	mu.Unlock()
}

func TestWriteBufferTimeout(t *testing.T) {
	var flushCount int
	var mu sync.Mutex

	flushCallback := func(data []byte, offset int64) error {
		mu.Lock()
		defer mu.Unlock()
		flushCount++
		return nil
	}

	config := &CoalesceConfig{
		Threshold: 1024,
		Timeout:   5 * time.Millisecond,
		MaxSize:   4096,
		Enabled:   true,
	}

	wb := NewWriteBuffer(config, flushCallback)

	// Write small data
	err := wb.Write([]byte("hello"), 0)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// Should not be flushed yet
	mu.Lock()
	if flushCount != 0 {
		t.Error("Small write should not trigger immediate flush")
	}
	mu.Unlock()

	// Wait for timeout
	time.Sleep(10 * time.Millisecond)

	// Write another small piece to trigger timeout flush
	err = wb.Write([]byte("world"), 5)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// Should have flushed due to timeout
	mu.Lock()
	if flushCount != 1 {
		t.Errorf("Expected 1 flush due to timeout, got %d", flushCount)
	}
	mu.Unlock()
}

func TestWriteBufferMaxSize(t *testing.T) {
	var flushCount int
	var mu sync.Mutex

	flushCallback := func(data []byte, offset int64) error {
		mu.Lock()
		defer mu.Unlock()
		flushCount++
		return nil
	}

	config := &CoalesceConfig{
		Threshold: 1024,
		Timeout:   100 * time.Millisecond,
		MaxSize:   100, // Small max size for testing
		Enabled:   true,
	}

	wb := NewWriteBuffer(config, flushCallback)

	// Write small data first
	err := wb.Write(make([]byte, 50), 0)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// Write more data that would exceed max size
	err = wb.Write(make([]byte, 60), 50)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// Should have flushed due to max size
	mu.Lock()
	if flushCount != 1 {
		t.Errorf("Expected 1 flush due to max size, got %d", flushCount)
	}
	mu.Unlock()
}

func TestWriteBufferManager(t *testing.T) {
	var flushedFiles []string
	var flushedData [][]byte
	var mu sync.Mutex

	flushCallback := func(fileID string, data []byte, offset int64) error {
		mu.Lock()
		defer mu.Unlock()
		flushedFiles = append(flushedFiles, fileID)
		flushedData = append(flushedData, make([]byte, len(data)))
		copy(flushedData[len(flushedData)-1], data)
		return nil
	}

	config := DefaultConfig()
	wbm := NewWriteBufferManager(config, flushCallback)

	// Write to different files
	err := wbm.Write("file1", []byte("hello"), 0)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	err = wbm.Write("file2", []byte("world"), 0)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// Flush all
	err = wbm.FlushAll()
	if err != nil {
		t.Fatalf("FlushAll failed: %v", err)
	}

	// Check that both files were flushed
	mu.Lock()
	if len(flushedFiles) != 2 {
		t.Errorf("Expected 2 flushed files, got %d", len(flushedFiles))
	}
	mu.Unlock()

	// Test stats
	stats := wbm.GetStats()
	if stats["buffer_count"].(int) != 2 {
		t.Errorf("Expected 2 buffers, got %d", stats["buffer_count"])
	}

	// Close manager
	err = wbm.Close()
	if err != nil {
		t.Fatalf("Close failed: %v", err)
	}
}

func BenchmarkWriteBuffer(b *testing.B) {
	flushCallback := func(data []byte, offset int64) error {
		return nil
	}

	config := DefaultConfig()
	wb := NewWriteBuffer(config, flushCallback)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		wb.Write([]byte("test data"), int64(i*10))
	}
}

func BenchmarkWriteBufferDisabled(b *testing.B) {
	flushCallback := func(data []byte, offset int64) error {
		return nil
	}

	config := &CoalesceConfig{
		Enabled: false,
	}
	wb := NewWriteBuffer(config, flushCallback)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		wb.Write([]byte("test data"), int64(i*10))
	}
}
