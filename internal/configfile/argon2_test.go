package configfile

import (
	"testing"
)

func TestArgon2idKDF(t *testing.T) {
	// Test basic Argon2id functionality
	kdf := NewArgon2idKDF()

	// Test parameter validation
	if err := kdf.validateParams(); err != nil {
		t.Errorf("Default Argon2id parameters should be valid: %v", err)
	}

	// Test key derivation
	password := []byte("test-password")
	key1 := kdf.DeriveKey(password)
	key2 := kdf.DeriveKey(password)

	// Same password should produce same key
	if len(key1) != len(key2) {
		t.Errorf("Derived keys should have same length: %d vs %d", len(key1), len(key2))
	}

	// Test that different passwords produce different keys
	password2 := []byte("different-password")
	key3 := kdf.DeriveKey(password2)

	if len(key1) == len(key3) {
		// Keys should be different
		equal := true
		for i := range key1 {
			if key1[i] != key3[i] {
				equal = false
				break
			}
		}
		if equal {
			t.Error("Different passwords should produce different keys")
		}
	}
}

func TestArgon2idKDFWithParams(t *testing.T) {
	// Test custom parameters
	memory := uint32(32 * 1024) // 32MB
	iterations := uint32(2)
	parallelism := uint8(2)

	kdf := NewArgon2idKDFWithParams(memory, iterations, parallelism)

	if kdf.Memory != memory {
		t.Errorf("Expected memory %d, got %d", memory, kdf.Memory)
	}
	if kdf.Iterations != iterations {
		t.Errorf("Expected iterations %d, got %d", iterations, kdf.Iterations)
	}
	if kdf.Parallelism != parallelism {
		t.Errorf("Expected parallelism %d, got %d", parallelism, kdf.Parallelism)
	}

	// Test parameter validation
	if err := kdf.validateParams(); err != nil {
		t.Errorf("Custom Argon2id parameters should be valid: %v", err)
	}
}

func TestArgon2idKDFValidation(t *testing.T) {
	// Test minimum parameter validation
	kdf := NewArgon2idKDF()

	// Test minimum memory
	kdf.Memory = Argon2idMinMemory - 1
	if err := kdf.validateParams(); err == nil {
		t.Error("Should reject memory below minimum")
	}
	kdf.Memory = Argon2idMinMemory // Reset

	// Test minimum iterations
	kdf.Iterations = Argon2idMinIterations - 1
	if err := kdf.validateParams(); err == nil {
		t.Error("Should reject iterations below minimum")
	}
	kdf.Iterations = Argon2idMinIterations // Reset

	// Test minimum parallelism
	kdf.Parallelism = Argon2idMinParallelism - 1
	if err := kdf.validateParams(); err == nil {
		t.Error("Should reject parallelism below minimum")
	}
	kdf.Parallelism = Argon2idMinParallelism // Reset

	// Test minimum salt length
	kdf.Salt = make([]byte, Argon2idMinSaltLen-1)
	if err := kdf.validateParams(); err == nil {
		t.Error("Should reject salt below minimum length")
	}
}

func TestGetRecommendedArgon2idParams(t *testing.T) {
	memory, iterations, parallelism := GetRecommendedArgon2idParams()

	if memory < Argon2idMinMemory {
		t.Errorf("Recommended memory %d should be at least minimum %d", memory, Argon2idMinMemory)
	}
	if iterations < Argon2idMinIterations {
		t.Errorf("Recommended iterations %d should be at least minimum %d", iterations, Argon2idMinIterations)
	}
	if parallelism < Argon2idMinParallelism {
		t.Errorf("Recommended parallelism %d should be at least minimum %d", parallelism, Argon2idMinParallelism)
	}
}
