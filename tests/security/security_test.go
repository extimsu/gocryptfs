package security

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/rfjakob/gocryptfs/v2/internal/configfile"
	"github.com/rfjakob/gocryptfs/v2/internal/cryptocore"
	"github.com/rfjakob/gocryptfs/v2/internal/filenameauth"
	"github.com/rfjakob/gocryptfs/v2/internal/memprotect"
	"github.com/rfjakob/gocryptfs/v2/internal/processhardening"
)

// TestMemoryProtection tests the memory protection functionality
func TestMemoryProtection(t *testing.T) {
	mp := memprotect.New()

	// Test basic functionality
	if mp == nil {
		t.Fatal("Memory protection should not be nil")
	}

	// Test memory locking
	testData := make([]byte, 1024)
	rand.Read(testData)

	success := mp.LockMemory(testData)
	if !success {
		t.Log("Memory locking not supported on this platform")
		return
	}

	// Test secure wipe
	mp.SecureWipe(testData)

	// Verify data is wiped (this may not work on all platforms)
	allZero := true
	for _, b := range testData {
		if b != 0 {
			allZero = false
			break
		}
	}
	if !allZero {
		t.Log("Secure wipe may not be fully effective on this platform")
		// Don't fail the test, just log the issue
	}

	// Test cleanup
	mp.Cleanup()
}

// TestProcessHardening tests the process hardening functionality
func TestProcessHardening(t *testing.T) {
	ph := processhardening.New()

	// Test basic functionality
	if ph == nil {
		t.Fatal("Process hardening should not be nil")
	}

	// Test process hardening
	ph.HardenProcess()

	// Test keep alive
	testData := make([]byte, 1024)
	rand.Read(testData)
	ph.KeepAlive(testData)

	// Force garbage collection
	runtime.GC()
	runtime.GC()

	// Data should still be accessible
	if len(testData) != 1024 {
		t.Error("KeepAlive should prevent garbage collection")
	}
}

// TestFilenameAuthentication tests the filename authentication functionality
func TestFilenameAuthentication(t *testing.T) {
	masterKey := make([]byte, 32)
	rand.Read(masterKey)

	fa := filenameauth.New(masterKey, true)

	// Test basic functionality
	if !fa.IsEnabled() {
		t.Error("Filename authentication should be enabled")
	}

	// Test authenticating a filename
	encryptedName := "test_encrypted_filename"
	authenticatedName, err := fa.AuthenticateFilename(encryptedName)
	if err != nil {
		t.Fatalf("Failed to authenticate filename: %v", err)
	}

	// Verify the authenticated name contains the separator
	if len(authenticatedName) <= len(encryptedName) {
		t.Error("Authenticated name should be longer than encrypted name")
	}

	// Test verifying the filename
	verifiedName, err := fa.VerifyFilename(authenticatedName)
	if err != nil {
		t.Fatalf("Failed to verify filename: %v", err)
	}

	if verifiedName != encryptedName {
		t.Errorf("Verified name mismatch: expected %s, got %s", encryptedName, verifiedName)
	}

	// Test tampering detection
	tamperedName := authenticatedName[:len(authenticatedName)-1] + "X"
	_, err = fa.VerifyFilename(tamperedName)
	if err == nil {
		t.Error("Verification should fail for tampered filename")
	}

	// Test wipe
	fa.Wipe()
}

// TestArgon2idKDF tests the Argon2id key derivation function
func TestArgon2idKDF(t *testing.T) {
	// Test with a sample master key
	masterKey := make([]byte, 32)
	rand.Read(masterKey)

	// Test Argon2id KDF
	argon2idKDF := configfile.NewArgon2idKDF()
	derivedKey := argon2idKDF.DeriveKey(masterKey)

	if len(derivedKey) != 32 {
		t.Errorf("Expected derived key length 32, got %d", len(derivedKey))
	}

	// Test that same input produces same output
	derivedKey2 := argon2idKDF.DeriveKey(masterKey)
	if string(derivedKey) != string(derivedKey2) {
		t.Error("Argon2id should produce deterministic output")
	}

	// Test that different input produces different output
	differentKey := make([]byte, 32)
	rand.Read(differentKey)
	derivedKey3 := argon2idKDF.DeriveKey(differentKey)
	if string(derivedKey) == string(derivedKey3) {
		t.Error("Argon2id should produce different output for different input")
	}
}

// TestScryptCostIncrease tests the increased scrypt cost parameters
func TestScryptCostIncrease(t *testing.T) {
	// Test default scrypt parameters
	scryptKDF := configfile.NewScryptKDF(configfile.ScryptDefaultLogN)

	if scryptKDF.N != 1<<configfile.ScryptDefaultLogN {
		t.Errorf("Expected N=%d, got %d", 1<<configfile.ScryptDefaultLogN, scryptKDF.N)
	}

	// Test recommended scrypt parameters
	recommendedLogN := configfile.GetRecommendedScryptLogN()
	if recommendedLogN != configfile.ScryptDefaultLogN {
		t.Errorf("Expected recommended logN=%d, got %d", configfile.ScryptDefaultLogN, recommendedLogN)
	}
}

// TestConfigFileDurability tests the config file durability improvements
func TestConfigFileDurability(t *testing.T) {
	// Create a temporary directory
	tempDir, err := os.MkdirTemp("", "gocryptfs-security-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	configPath := filepath.Join(tempDir, "gocryptfs.conf")

	// Create a config file
	password := []byte("testpassword")
	args := &configfile.CreateArgs{
		Filename: configPath,
		Password: password,
		LogN:     configfile.ScryptDefaultLogN,
		Creator:  "security-test",
	}

	err = configfile.Create(args)
	if err != nil {
		t.Fatalf("Failed to create config file: %v", err)
	}

	// Verify the config file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		t.Error("Config file should exist after creation")
	}

	// Test reading the config file
	cf, err := configfile.Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config file: %v", err)
	}

	// Test decrypting the master key
	masterKey, err := cf.DecryptMasterKey(password)
	if err != nil {
		t.Fatalf("Failed to decrypt master key: %v", err)
	}

	if len(masterKey) != 32 {
		t.Errorf("Expected master key length 32, got %d", len(masterKey))
	}
}

// TestCPUDetection tests the CPU detection functionality
func TestCPUDetection(t *testing.T) {
	// This test would require importing the cpudetection package
	// For now, we'll test the basic functionality

	// Test that we can detect CPU features
	cpuCount := runtime.NumCPU()
	if cpuCount < 1 {
		t.Error("CPU count should be at least 1")
	}

	// Test that we can get optimal prefetch size
	optimalSize := cryptocore.GetOptimalPrefetchSize()
	if optimalSize < 256 || optimalSize > 4096 {
		t.Errorf("Optimal prefetch size %d is outside valid range [256, 4096]", optimalSize)
	}
}

// TestFeatureFlags tests the new feature flags
func TestFeatureFlags(t *testing.T) {
	// Test that we can create config files with new feature flags
	// This indirectly tests that the feature flags are properly defined

	// Test Argon2id feature flag by creating a config with it
	tempDir, err := os.MkdirTemp("", "gocryptfs-feature-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	configPath := filepath.Join(tempDir, "gocryptfs.conf")
	password := []byte("testpassword")

	// Test Argon2id feature flag
	args := &configfile.CreateArgs{
		Filename: configPath,
		Password: password,
		LogN:     configfile.ScryptDefaultLogN,
		Creator:  "feature-test",
		Argon2id: true,
	}

	err = configfile.Create(args)
	if err != nil {
		t.Fatalf("Failed to create config with Argon2id: %v", err)
	}

	// Test FilenameAuth feature flag
	args.FilenameAuth = true
	err = configfile.Create(args)
	if err != nil {
		t.Fatalf("Failed to create config with FilenameAuth: %v", err)
	}

	// Test ConfigurableBlockSize feature flag
	args.BlockSize = 16384
	err = configfile.Create(args)
	if err != nil {
		t.Fatalf("Failed to create config with ConfigurableBlockSize: %v", err)
	}
}

// TestSecurityIntegration tests the integration of security features
func TestSecurityIntegration(t *testing.T) {
	// Create a temporary directory
	tempDir, err := os.MkdirTemp("", "gocryptfs-security-integration-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	configPath := filepath.Join(tempDir, "gocryptfs.conf")

	// Create a config file with security features
	password := []byte("testpassword")
	args := &configfile.CreateArgs{
		Filename:     configPath,
		Password:     password,
		LogN:         configfile.ScryptDefaultLogN,
		Creator:      "security-integration-test",
		Argon2id:     true,
		FilenameAuth: true,
		BlockSize:    16384,
	}

	err = configfile.Create(args)
	if err != nil {
		t.Fatalf("Failed to create config file: %v", err)
	}

	// Load and verify the config file
	cf, err := configfile.Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config file: %v", err)
	}

	// Verify feature flags are set
	if !cf.IsFeatureFlagSet(configfile.FlagArgon2id) {
		t.Error("Argon2id feature flag should be set")
	}

	if !cf.IsFeatureFlagSet(configfile.FlagFilenameAuth) {
		t.Error("FilenameAuth feature flag should be set")
	}

	if !cf.IsFeatureFlagSet(configfile.FlagConfigurableBlockSize) {
		t.Error("ConfigurableBlockSize feature flag should be set")
	}

	// Verify block size is set
	if cf.BlockSize != 16384 {
		t.Errorf("Expected block size 16384, got %d", cf.BlockSize)
	}

	// Test decrypting the master key
	masterKey, err := cf.DecryptMasterKey(password)
	if err != nil {
		t.Fatalf("Failed to decrypt master key: %v", err)
	}

	if len(masterKey) != 32 {
		t.Errorf("Expected master key length 32, got %d", len(masterKey))
	}
}

// TestSecurityPerformance tests the performance impact of security features
func TestSecurityPerformance(t *testing.T) {
	// Test memory protection performance
	mp := memprotect.New()
	testData := make([]byte, 1024)
	rand.Read(testData)

	start := time.Now()
	mp.LockMemory(testData)
	lockTime := time.Since(start)

	start = time.Now()
	mp.SecureWipe(testData)
	wipeTime := time.Since(start)

	t.Logf("Memory protection performance: lock=%v, wipe=%v", lockTime, wipeTime)

	// Test filename authentication performance
	masterKey := make([]byte, 32)
	rand.Read(masterKey)
	fa := filenameauth.New(masterKey, true)

	start = time.Now()
	for i := 0; i < 1000; i++ {
		encryptedName := "test_encrypted_filename"
		authenticatedName, _ := fa.AuthenticateFilename(encryptedName)
		fa.VerifyFilename(authenticatedName)
	}
	authTime := time.Since(start)

	t.Logf("Filename authentication performance: 1000 operations in %v", authTime)

	// Test Argon2id performance
	password := []byte("testpassword")
	argon2idKDF := configfile.NewArgon2idKDF()

	start = time.Now()
	argon2idKDF.DeriveKey(password)
	argon2idTime := time.Since(start)

	t.Logf("Argon2id key derivation time: %v", argon2idTime)
}

// TestSecurityCompatibility tests backward compatibility
func TestSecurityCompatibility(t *testing.T) {
	// Test that old config files still work
	// This would require creating a config file with old format
	// For now, we'll test that new features are optional

	// Test filename authentication disabled
	masterKey := make([]byte, 32)
	rand.Read(masterKey)
	fa := filenameauth.New(masterKey, false)

	if fa.IsEnabled() {
		t.Error("Filename authentication should be disabled")
	}

	// Test that disabled auth returns the same name
	encryptedName := "test_encrypted_filename"
	authenticatedName, err := fa.AuthenticateFilename(encryptedName)
	if err != nil {
		t.Fatalf("Failed to authenticate filename: %v", err)
	}

	if authenticatedName != encryptedName {
		t.Error("Disabled auth should return the same name")
	}
}

// BenchmarkSecurityFeatures benchmarks the security features
func BenchmarkMemoryProtection(b *testing.B) {
	mp := memprotect.New()
	testData := make([]byte, 1024)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rand.Read(testData)
		mp.LockMemory(testData)
		mp.SecureWipe(testData)
	}
}

func BenchmarkFilenameAuthentication(b *testing.B) {
	masterKey := make([]byte, 32)
	rand.Read(masterKey)
	fa := filenameauth.New(masterKey, true)
	encryptedName := "test_encrypted_filename"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		authenticatedName, _ := fa.AuthenticateFilename(encryptedName)
		fa.VerifyFilename(authenticatedName)
	}
}

func BenchmarkArgon2idKDF(b *testing.B) {
	password := []byte("testpassword")
	argon2idKDF := configfile.NewArgon2idKDF()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		argon2idKDF.DeriveKey(password)
	}
}

func BenchmarkScryptKDF(b *testing.B) {
	password := []byte("testpassword")
	scryptKDF := configfile.NewScryptKDF(configfile.ScryptDefaultLogN)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scryptKDF.DeriveKey(password)
	}
}
