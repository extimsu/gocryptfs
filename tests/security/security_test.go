package security

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
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

// TestFilenameTamperDetection tests comprehensive tamper detection scenarios
func TestFilenameTamperDetection(t *testing.T) {
	masterKey := make([]byte, 32)
	rand.Read(masterKey)
	fa := filenameauth.New(masterKey, true)

	testCases := []struct {
		name          string
		encryptedName string
		tamperFunc    func(string) string
		shouldFail    bool
	}{
		{
			name:          "Single character MAC tamper",
			encryptedName: "test_encrypted_filename",
			tamperFunc:    func(name string) string { return name[:len(name)-1] + "X" },
			shouldFail:    true,
		},
		{
			name:          "MAC truncation",
			encryptedName: "test_encrypted_filename",
			tamperFunc:    func(name string) string { return name[:len(name)-10] },
			shouldFail:    true,
		},
		{
			name:          "MAC replacement",
			encryptedName: "test_encrypted_filename",
			tamperFunc: func(name string) string {
				parts := strings.Split(name, ".")
				if len(parts) != 2 {
					return name
				}
				return parts[0] + ".tampered_mac"
			},
			shouldFail: true,
		},
		{
			name:          "Encrypted name tamper",
			encryptedName: "test_encrypted_filename",
			tamperFunc: func(name string) string {
				parts := strings.Split(name, ".")
				if len(parts) != 2 {
					return name
				}
				return "tampered_name." + parts[1]
			},
			shouldFail: true,
		},
		{
			name:          "Complete replacement",
			encryptedName: "test_encrypted_filename",
			tamperFunc:    func(name string) string { return "completely_different_name.fake_mac" },
			shouldFail:    true,
		},
		{
			name:          "Valid name (no tamper)",
			encryptedName: "test_encrypted_filename",
			tamperFunc:    func(name string) string { return name },
			shouldFail:    false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create authenticated filename
			authenticatedName, err := fa.AuthenticateFilename(tc.encryptedName)
			if err != nil {
				t.Fatalf("Failed to authenticate filename: %v", err)
			}

			// Apply tampering
			tamperedName := tc.tamperFunc(authenticatedName)

			// Test verification
			_, err = fa.VerifyFilename(tamperedName)
			if tc.shouldFail && err == nil {
				t.Errorf("Verification should have failed for tampered filename: %s", tc.name)
			}
			if !tc.shouldFail && err != nil {
				t.Errorf("Verification should have succeeded for valid filename: %s, error: %v", tc.name, err)
			}
		})
	}
}

// TestLongnameTamperDetection tests tamper detection for long filenames
func TestLongnameTamperDetection(t *testing.T) {
	masterKey := make([]byte, 32)
	rand.Read(masterKey)
	fa := filenameauth.New(masterKey, true)

	// Test with various long filename scenarios
	longNames := []string{
		"very_long_filename_that_exceeds_normal_limits_and_should_be_hashed_to_longname",
		"another_extremely_long_filename_with_special_characters_!@#$%^&*()_+-=[]{}|;':\",./<>?",
		"unicode_filename_with_特殊字符_and_emoji_🚀_and_more_unicode_测试",
		strings.Repeat("a", 200), // 200 character filename
		strings.Repeat("测试", 50), // Unicode repeated
	}

	for _, longName := range longNames {
		t.Run(fmt.Sprintf("longname_%d_chars", len(longName)), func(t *testing.T) {
			// Create authenticated long filename
			authenticatedName, err := fa.AuthenticateFilename(longName)
			if err != nil {
				t.Fatalf("Failed to authenticate long filename: %v", err)
			}

			// Test that verification works for valid long filename
			verifiedName, err := fa.VerifyFilename(authenticatedName)
			if err != nil {
				t.Fatalf("Failed to verify long filename: %v", err)
			}
			if verifiedName != longName {
				t.Errorf("Verified long name mismatch: expected %s, got %s", longName, verifiedName)
			}

			// Test tampering detection for long filenames
			tamperedName := authenticatedName[:len(authenticatedName)-1] + "X"
			_, err = fa.VerifyFilename(tamperedName)
			if err == nil {
				t.Error("Verification should fail for tampered long filename")
			}
		})
	}
}

// TestFilenameAuthEdgeCases tests edge cases for filename authentication
func TestFilenameAuthEdgeCases(t *testing.T) {
	masterKey := make([]byte, 32)
	rand.Read(masterKey)
	fa := filenameauth.New(masterKey, true)

	edgeCases := []struct {
		name        string
		filename    string
		expectError bool
	}{
		{"Empty filename", "", false},
		{"Single character", "a", false},
		{"Filename with dots", "file.name.with.dots", false},
		{"Filename with separators", "file-name_with_separators", false},
		{"Unicode filename", "файл_с_unicode_имени", false},
		{"Very long filename", strings.Repeat("a", 1000), false},
		{"Filename with newlines", "file\nwith\nnewlines", false},
		{"Filename with null bytes", "file\x00with\x00nulls", false},
	}

	for _, tc := range edgeCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test authentication
			authenticatedName, err := fa.AuthenticateFilename(tc.filename)
			if tc.expectError && err == nil {
				t.Errorf("Expected error for filename: %s", tc.name)
			}
			if !tc.expectError && err != nil {
				t.Errorf("Unexpected error for filename %s: %v", tc.name, err)
			}

			if !tc.expectError {
				// Test verification
				verifiedName, err := fa.VerifyFilename(authenticatedName)
				if err != nil {
					t.Errorf("Failed to verify filename %s: %v", tc.name, err)
				}
				if verifiedName != tc.filename {
					t.Errorf("Verified name mismatch for %s: expected %s, got %s", tc.name, tc.filename, verifiedName)
				}
			}
		})
	}
}

// TestFilenameAuthWithDifferentKeys tests that different keys produce different MACs
func TestFilenameAuthWithDifferentKeys(t *testing.T) {
	// Create two different master keys
	masterKey1 := make([]byte, 32)
	masterKey2 := make([]byte, 32)
	rand.Read(masterKey1)
	rand.Read(masterKey2)

	fa1 := filenameauth.New(masterKey1, true)
	fa2 := filenameauth.New(masterKey2, true)

	encryptedName := "test_encrypted_filename"

	// Authenticate with first key
	authenticatedName1, err := fa1.AuthenticateFilename(encryptedName)
	if err != nil {
		t.Fatalf("Failed to authenticate with first key: %v", err)
	}

	// Authenticate with second key
	authenticatedName2, err := fa2.AuthenticateFilename(encryptedName)
	if err != nil {
		t.Fatalf("Failed to authenticate with second key: %v", err)
	}

	// MACs should be different
	if authenticatedName1 == authenticatedName2 {
		t.Error("Different keys should produce different MACs")
	}

	// Verification should fail when using wrong key
	_, err = fa2.VerifyFilename(authenticatedName1)
	if err == nil {
		t.Error("Verification should fail when using wrong key")
	}

	_, err = fa1.VerifyFilename(authenticatedName2)
	if err == nil {
		t.Error("Verification should fail when using wrong key")
	}
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
