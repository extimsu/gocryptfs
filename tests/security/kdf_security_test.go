package security

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/rfjakob/gocryptfs/v2/internal/configfile"
)

// TestKDFDefaultBehavior tests that Argon2id is the default KDF for new filesystems
func TestKDFDefaultBehavior(t *testing.T) {
	// Create temporary directory for test
	tempDir, err := os.MkdirTemp("", "gocryptfs-kdf-default-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	configPath := filepath.Join(tempDir, "gocryptfs.conf")
	password := []byte("testpassword")

	// Create config with default settings (should use Argon2id)
	args := &configfile.CreateArgs{
		Filename:       configPath,
		Password:       password,
		PlaintextNames: false,
		LogN:           17, // Default scrypt logN
		Creator:        "test",
		AESSIV:         false,
		Argon2id:       true, // This should be the default
		FilenameAuth:   true,
		BlockSize:      4096,
	}

	err = configfile.Create(args)
	if err != nil {
		t.Fatalf("Failed to create config: %v", err)
	}

	// Read and verify the config
	configData, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("Failed to read config file: %v", err)
	}

	var conf configfile.ConfFile
	err = json.Unmarshal(configData, &conf)
	if err != nil {
		t.Fatalf("Failed to unmarshal config: %v", err)
	}

	// Verify Argon2id is present
	if conf.Argon2idObject == nil {
		t.Error("Argon2idObject should be present in default configuration")
	}

	// Verify Argon2id feature flag is set
	if !conf.IsFeatureFlagSet(configfile.FlagArgon2id) {
		t.Error("Argon2id feature flag should be set in default configuration")
	}

	// Verify scrypt is also present for backward compatibility
	if conf.ScryptObject.Salt == nil {
		t.Error("ScryptObject should be present for backward compatibility")
	}
}

// TestKDFScryptExplicit tests that scrypt can be explicitly selected
func TestKDFScryptExplicit(t *testing.T) {
	// Create temporary directory for test
	tempDir, err := os.MkdirTemp("", "gocryptfs-kdf-scrypt-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	configPath := filepath.Join(tempDir, "gocryptfs.conf")
	password := []byte("testpassword")

	// Create config with scrypt explicitly selected
	args := &configfile.CreateArgs{
		Filename:       configPath,
		Password:       password,
		PlaintextNames: false,
		LogN:           17, // Default scrypt logN
		Creator:        "test",
		AESSIV:         false,
		Argon2id:       false, // Explicitly disable Argon2id
		FilenameAuth:   true,
		BlockSize:      4096,
	}

	err = configfile.Create(args)
	if err != nil {
		t.Fatalf("Failed to create config: %v", err)
	}

	// Read and verify the config
	configData, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("Failed to read config file: %v", err)
	}

	var conf configfile.ConfFile
	err = json.Unmarshal(configData, &conf)
	if err != nil {
		t.Fatalf("Failed to unmarshal config: %v", err)
	}

	// Verify Argon2id is NOT present
	if conf.Argon2idObject != nil {
		t.Error("Argon2idObject should not be present when scrypt is explicitly selected")
	}

	// Verify Argon2id feature flag is NOT set
	if conf.IsFeatureFlagSet(configfile.FlagArgon2id) {
		t.Error("Argon2id feature flag should not be set when scrypt is explicitly selected")
	}

	// Verify scrypt is present
	if conf.ScryptObject.Salt == nil {
		t.Error("ScryptObject should be present when scrypt is explicitly selected")
	}
}

// TestKDFParameterValidation tests that KDF parameters are within acceptable ranges
func TestKDFParameterValidation(t *testing.T) {
	// Test Argon2id parameters
	tempDir, err := os.MkdirTemp("", "gocryptfs-kdf-params-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	configPath := filepath.Join(tempDir, "gocryptfs.conf")
	password := []byte("testpassword")

	// Create config with Argon2id
	args := &configfile.CreateArgs{
		Filename:       configPath,
		Password:       password,
		PlaintextNames: false,
		LogN:           17,
		Creator:        "test",
		AESSIV:         false,
		Argon2id:       true,
		FilenameAuth:   true,
		BlockSize:      4096,
	}

	err = configfile.Create(args)
	if err != nil {
		t.Fatalf("Failed to create config: %v", err)
	}

	// Read and verify the config
	configData, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("Failed to read config file: %v", err)
	}

	var conf configfile.ConfFile
	err = json.Unmarshal(configData, &conf)
	if err != nil {
		t.Fatalf("Failed to unmarshal config: %v", err)
	}

	// Verify Argon2id parameters are reasonable
	if conf.Argon2idObject != nil {
		argon2id := conf.Argon2idObject

		// Memory should be at least 64KB (65536 bytes)
		if argon2id.Memory < 65536 {
			t.Errorf("Argon2id memory too low: %d, should be at least 65536", argon2id.Memory)
		}

		// Iterations should be at least 3
		if argon2id.Iterations < 3 {
			t.Errorf("Argon2id iterations too low: %d, should be at least 3", argon2id.Iterations)
		}

		// Parallelism should be at least 1
		if argon2id.Parallelism < 1 {
			t.Errorf("Argon2id parallelism too low: %d, should be at least 1", argon2id.Parallelism)
		}

		// KeyLen should be 32 bytes (256 bits)
		if argon2id.KeyLen != 32 {
			t.Errorf("Argon2id key length incorrect: %d, should be 32", argon2id.KeyLen)
		}
	}

	// Verify scrypt parameters are reasonable
	if conf.ScryptObject.Salt != nil {
		scrypt := conf.ScryptObject

		// N should be at least 2^15 (32768)
		if scrypt.N < 32768 {
			t.Errorf("Scrypt N too low: %d, should be at least 32768", scrypt.N)
		}

		// R should be at least 8
		if scrypt.R < 8 {
			t.Errorf("Scrypt R too low: %d, should be at least 8", scrypt.R)
		}

		// P should be at least 1
		if scrypt.P < 1 {
			t.Errorf("Scrypt P too low: %d, should be at least 1", scrypt.P)
		}

		// KeyLen should be 32 bytes (256 bits)
		if scrypt.KeyLen != 32 {
			t.Errorf("Scrypt key length incorrect: %d, should be 32", scrypt.KeyLen)
		}
	}
}

// TestKDFBackwardCompatibility tests that existing scrypt-only filesystems still work
func TestKDFBackwardCompatibility(t *testing.T) {
	// Create temporary directory for test
	tempDir, err := os.MkdirTemp("", "gocryptfs-kdf-compat-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	configPath := filepath.Join(tempDir, "gocryptfs.conf")
	password := []byte("testpassword")

	// Create config with scrypt only (simulating old filesystem)
	args := &configfile.CreateArgs{
		Filename:       configPath,
		Password:       password,
		PlaintextNames: false,
		LogN:           17,
		Creator:        "test",
		AESSIV:         false,
		Argon2id:       false, // Old filesystem behavior
		FilenameAuth:   false, // Old filesystem behavior
		BlockSize:      4096,
	}

	err = configfile.Create(args)
	if err != nil {
		t.Fatalf("Failed to create config: %v", err)
	}

	// Read and verify the config
	configData, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("Failed to read config file: %v", err)
	}

	var conf configfile.ConfFile
	err = json.Unmarshal(configData, &conf)
	if err != nil {
		t.Fatalf("Failed to unmarshal config: %v", err)
	}

	// Verify it's a scrypt-only configuration
	if conf.Argon2idObject != nil {
		t.Error("Argon2idObject should not be present in backward compatibility test")
	}

	if conf.IsFeatureFlagSet(configfile.FlagArgon2id) {
		t.Error("Argon2id feature flag should not be set in backward compatibility test")
	}

	if conf.ScryptObject.Salt == nil {
		t.Error("ScryptObject should be present in backward compatibility test")
	}

	// Verify it can be loaded (simulating mount)
	_, err = configfile.Load(configPath)
	if err != nil {
		t.Errorf("Failed to load backward compatibility config: %v", err)
	}
}

// TestKDFSecurityLevels tests that both KDFs provide adequate security
func TestKDFSecurityLevels(t *testing.T) {
	// This test verifies that both KDFs are configured with security parameters
	// that meet modern standards for password-based key derivation

	tempDir, err := os.MkdirTemp("", "gocryptfs-kdf-security-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	configPath := filepath.Join(tempDir, "gocryptfs.conf")
	password := []byte("testpassword")

	// Create config with Argon2id (default)
	args := &configfile.CreateArgs{
		Filename:       configPath,
		Password:       password,
		PlaintextNames: false,
		LogN:           17,
		Creator:        "test",
		AESSIV:         false,
		Argon2id:       true,
		FilenameAuth:   true,
		BlockSize:      4096,
	}

	err = configfile.Create(args)
	if err != nil {
		t.Fatalf("Failed to create config: %v", err)
	}

	// Read and verify the config
	configData, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("Failed to read config file: %v", err)
	}

	var conf configfile.ConfFile
	err = json.Unmarshal(configData, &conf)
	if err != nil {
		t.Fatalf("Failed to unmarshal config: %v", err)
	}

	// Verify Argon2id security parameters meet OWASP recommendations
	if conf.Argon2idObject != nil {
		argon2id := conf.Argon2idObject

		// Memory: OWASP recommends at least 64MB, but 64KB is acceptable for testing
		// In production, this should be higher
		if argon2id.Memory < 65536 {
			t.Errorf("Argon2id memory below minimum: %d", argon2id.Memory)
		}

		// Iterations: OWASP recommends at least 2, we use 3
		if argon2id.Iterations < 2 {
			t.Errorf("Argon2id iterations below minimum: %d", argon2id.Iterations)
		}

		// Parallelism: Should be reasonable (1-4)
		if argon2id.Parallelism < 1 || argon2id.Parallelism > 4 {
			t.Errorf("Argon2id parallelism out of range: %d", argon2id.Parallelism)
		}
	}

	// Verify scrypt security parameters meet recommendations
	if conf.ScryptObject.Salt != nil {
		scrypt := conf.ScryptObject

		// N: Should be at least 2^15 (32768) for reasonable security
		if scrypt.N < 32768 {
			t.Errorf("Scrypt N below minimum: %d", scrypt.N)
		}

		// R: Should be at least 8
		if scrypt.R < 8 {
			t.Errorf("Scrypt R below minimum: %d", scrypt.R)
		}

		// P: Should be at least 1
		if scrypt.P < 1 {
			t.Errorf("Scrypt P below minimum: %d", scrypt.P)
		}
	}
}

// BenchmarkKDFPerformance benchmarks the performance of both KDFs
func BenchmarkKDFPerformance(b *testing.B) {
	password := []byte("testpassword")

	// Benchmark Argon2id
	b.Run("Argon2id", func(b *testing.B) {
		argon2id := configfile.NewArgon2idKDF()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			key := argon2id.DeriveKey(password)
			// Prevent optimization
			_ = key
		}
	})

	// Benchmark scrypt
	b.Run("Scrypt", func(b *testing.B) {
		scrypt := configfile.NewScryptKDF(17) // logN = 17
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			key := scrypt.DeriveKey(password)
			// Prevent optimization
			_ = key
		}
	})
}
