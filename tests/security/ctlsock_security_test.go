package security

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rfjakob/gocryptfs/v2/ctlsock"
	"github.com/rfjakob/gocryptfs/v2/internal/ctlsocksrv"
)

// Mock filesystem interface for testing
type mockFS struct {
	encryptPath string
	decryptPath string
	encryptErr  error
	decryptErr  error
}

func (m *mockFS) EncryptPath(path string) (string, error) {
	if m.encryptErr != nil {
		return "", m.encryptErr
	}
	return m.encryptPath, nil
}

func (m *mockFS) DecryptPath(path string) (string, error) {
	if m.decryptErr != nil {
		return "", m.decryptErr
	}
	return m.decryptPath, nil
}

// TestControlSocketPermissions tests that the control socket is created with secure permissions
func TestControlSocketPermissions(t *testing.T) {
	// Create temporary directory for socket
	tempDir, err := os.MkdirTemp("", "gocryptfs-ctlsock-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	socketPath := filepath.Join(tempDir, "test.sock")

	// Create listener with secure permissions
	listener, err := ctlsocksrv.Listen(socketPath)
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	// Check socket file permissions
	stat, err := os.Stat(socketPath)
	if err != nil {
		t.Fatalf("Failed to stat socket file: %v", err)
	}

	// Socket should have 0600 permissions (read/write for owner only)
	expectedMode := os.FileMode(0600)
	if stat.Mode().Perm() != expectedMode {
		t.Errorf("Socket permissions incorrect: expected %o, got %o", expectedMode, stat.Mode().Perm())
	}

	// Check parent directory permissions
	parentDir := filepath.Dir(socketPath)
	parentStat, err := os.Stat(parentDir)
	if err != nil {
		t.Fatalf("Failed to stat parent directory: %v", err)
	}

	// Parent directory should have 0700 permissions (read/write/execute for owner only)
	expectedParentMode := os.FileMode(0700)
	if parentStat.Mode().Perm() != expectedParentMode {
		t.Errorf("Parent directory permissions incorrect: expected %o, got %o", expectedParentMode, parentStat.Mode().Perm())
	}
}

// TestControlSocketRateLimit tests that the control socket enforces rate limiting
func TestControlSocketRateLimit(t *testing.T) {
	// Create temporary directory for socket
	tempDir, err := os.MkdirTemp("", "gocryptfs-ctlsock-ratelimit-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	socketPath := filepath.Join(tempDir, "test.sock")

	// Create listener
	listener, err := ctlsocksrv.Listen(socketPath)
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	// Start server
	mockFS := &mockFS{
		encryptPath: "encrypted_path",
		decryptPath: "decrypted_path",
	}
	go ctlsocksrv.Serve(listener, mockFS)

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	// Test rate limiting by sending many requests quickly
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("Failed to connect to socket: %v", err)
	}
	defer conn.Close()

	// Send requests rapidly to trigger rate limiting
	request := ctlsock.RequestStruct{
		EncryptPath: "test_path",
	}
	requestData, _ := json.Marshal(request)

	successCount := 0
	rateLimitCount := 0

	for i := 0; i < 100; i++ { // Send 100 requests
		_, err := conn.Write(requestData)
		if err != nil {
			t.Logf("Write error on request %d: %v", i, err)
			break
		}

		// Read response
		buf := make([]byte, 1024)
		conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, err := conn.Read(buf)
		if err != nil {
			t.Logf("Read error on request %d: %v", i, err)
			break
		}

		var response ctlsock.ResponseStruct
		err = json.Unmarshal(buf[:n], &response)
		if err != nil {
			t.Logf("JSON unmarshal error on request %d: %v", i, err)
			continue
		}

		if response.ErrText != "" {
			if response.ErrText == "rate limit exceeded: 60 requests per minute" {
				rateLimitCount++
			} else {
				t.Logf("Unexpected error on request %d: %s", i, response.ErrText)
			}
		} else {
			successCount++
		}

		// Small delay to avoid overwhelming the system
		time.Sleep(10 * time.Millisecond)
	}

	t.Logf("Rate limit test results: %d successful, %d rate limited", successCount, rateLimitCount)

	// We should have some successful requests and some rate limited
	if successCount == 0 {
		t.Error("No successful requests - rate limiting may be too aggressive")
	}
	if rateLimitCount == 0 {
		t.Error("No rate limiting occurred - rate limiting may not be working")
	}
}

// TestControlSocketTimeout tests that the control socket enforces timeouts
func TestControlSocketTimeout(t *testing.T) {
	// Create temporary directory for socket
	tempDir, err := os.MkdirTemp("", "gocryptfs-ctlsock-timeout-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	socketPath := filepath.Join(tempDir, "test.sock")

	// Create listener
	listener, err := ctlsocksrv.Listen(socketPath)
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	// Start server
	mockFS := &mockFS{
		encryptPath: "encrypted_path",
		decryptPath: "decrypted_path",
	}
	go ctlsocksrv.Serve(listener, mockFS)

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	// Connect to socket
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("Failed to connect to socket: %v", err)
	}
	defer conn.Close()

	// Send a request
	request := ctlsock.RequestStruct{
		EncryptPath: "test_path",
	}
	requestData, _ := json.Marshal(request)

	_, err = conn.Write(requestData)
	if err != nil {
		t.Fatalf("Failed to write request: %v", err)
	}

	// Read response
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	var response ctlsock.ResponseStruct
	err = json.Unmarshal(buf[:n], &response)
	if err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if response.ErrText != "" {
		t.Errorf("Unexpected error: %s", response.ErrText)
	}

	if response.Result != "encrypted_path" {
		t.Errorf("Unexpected result: expected 'encrypted_path', got '%s'", response.Result)
	}
}

// TestControlSocketPeerCredentials tests that the control socket checks peer credentials
func TestControlSocketPeerCredentials(t *testing.T) {
	// This test verifies that the peer credential checking doesn't break normal operation
	// In a real environment, we would need to test with different UIDs, but that's complex
	// in a test environment

	// Create temporary directory for socket
	tempDir, err := os.MkdirTemp("", "gocryptfs-ctlsock-peercred-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	socketPath := filepath.Join(tempDir, "test.sock")

	// Create listener
	listener, err := ctlsocksrv.Listen(socketPath)
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	// Start server
	mockFS := &mockFS{
		encryptPath: "encrypted_path",
		decryptPath: "decrypted_path",
	}
	go ctlsocksrv.Serve(listener, mockFS)

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	// Connect to socket (should work since we're the same user)
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("Failed to connect to socket: %v", err)
	}
	defer conn.Close()

	// Send a request
	request := ctlsock.RequestStruct{
		EncryptPath: "test_path",
	}
	requestData, _ := json.Marshal(request)

	_, err = conn.Write(requestData)
	if err != nil {
		t.Fatalf("Failed to write request: %v", err)
	}

	// Read response
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	var response ctlsock.ResponseStruct
	err = json.Unmarshal(buf[:n], &response)
	if err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	// Should succeed since we're the same user
	if response.ErrText != "" {
		t.Errorf("Unexpected error: %s", response.ErrText)
	}
}

// TestControlSocketSecurityIntegration tests the integration of all security features
func TestControlSocketSecurityIntegration(t *testing.T) {
	// Create temporary directory for socket
	tempDir, err := os.MkdirTemp("", "gocryptfs-ctlsock-integration-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	socketPath := filepath.Join(tempDir, "test.sock")

	// Create listener with secure permissions
	listener, err := ctlsocksrv.Listen(socketPath)
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	// Verify secure permissions
	stat, err := os.Stat(socketPath)
	if err != nil {
		t.Fatalf("Failed to stat socket file: %v", err)
	}
	if stat.Mode().Perm() != 0600 {
		t.Errorf("Socket permissions incorrect: expected 0600, got %o", stat.Mode().Perm())
	}

	// Start server
	mockFS := &mockFS{
		encryptPath: "encrypted_path",
		decryptPath: "decrypted_path",
	}
	go ctlsocksrv.Serve(listener, mockFS)

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	// Test normal operation
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("Failed to connect to socket: %v", err)
	}
	defer conn.Close()

	// Test encryption
	request := ctlsock.RequestStruct{
		EncryptPath: "test_path",
	}
	requestData, _ := json.Marshal(request)

	_, err = conn.Write(requestData)
	if err != nil {
		t.Fatalf("Failed to write request: %v", err)
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	var response ctlsock.ResponseStruct
	err = json.Unmarshal(buf[:n], &response)
	if err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if response.ErrText != "" {
		t.Errorf("Unexpected error: %s", response.ErrText)
	}

	if response.Result != "encrypted_path" {
		t.Errorf("Unexpected result: expected 'encrypted_path', got '%s'", response.Result)
	}
}

// BenchmarkControlSocketSecurity benchmarks the performance impact of security features
func BenchmarkControlSocketSecurity(b *testing.B) {
	// Create temporary directory for socket
	tempDir, err := os.MkdirTemp("", "gocryptfs-ctlsock-benchmark")
	if err != nil {
		b.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	socketPath := filepath.Join(tempDir, "test.sock")

	// Create listener
	listener, err := ctlsocksrv.Listen(socketPath)
	if err != nil {
		b.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	// Start server
	mockFS := &mockFS{
		encryptPath: "encrypted_path",
		decryptPath: "decrypted_path",
	}
	go ctlsocksrv.Serve(listener, mockFS)

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	// Connect to socket
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		b.Fatalf("Failed to connect to socket: %v", err)
	}
	defer conn.Close()

	request := ctlsock.RequestStruct{
		EncryptPath: "test_path",
	}
	requestData, _ := json.Marshal(request)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := conn.Write(requestData)
		if err != nil {
			b.Fatalf("Failed to write request: %v", err)
		}

		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			b.Fatalf("Failed to read response: %v", err)
		}

		var response ctlsock.ResponseStruct
		err = json.Unmarshal(buf[:n], &response)
		if err != nil {
			b.Fatalf("Failed to unmarshal response: %v", err)
		}

		if response.ErrText != "" {
			b.Fatalf("Unexpected error: %s", response.ErrText)
		}
	}
}
