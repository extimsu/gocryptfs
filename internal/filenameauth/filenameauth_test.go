package filenameauth

import (
	"testing"
)

func TestFilenameAuth(t *testing.T) {
	// Test with a sample master key
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i)
	}

	// Test enabled filename authentication
	fa := New(masterKey, true)
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

	// Test MAC length
	macLen := fa.GetMACLength()
	if macLen != FilenameAuthMACLen {
		t.Errorf("Expected MAC length %d, got %d", FilenameAuthMACLen, macLen)
	}

	// Test separator
	separator := fa.GetSeparator()
	if separator != FilenameAuthSeparator {
		t.Errorf("Expected separator %s, got %s", FilenameAuthSeparator, separator)
	}

	// Test wipe
	fa.Wipe()
}

func TestFilenameAuthDisabled(t *testing.T) {
	masterKey := make([]byte, 32)
	fa := New(masterKey, false)

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

	// Test verification
	verifiedName, err := fa.VerifyFilename(encryptedName)
	if err != nil {
		t.Fatalf("Failed to verify filename: %v", err)
	}

	if verifiedName != encryptedName {
		t.Error("Disabled auth verification should return the same name")
	}

	// Test MAC length
	macLen := fa.GetMACLength()
	if macLen != 0 {
		t.Errorf("Expected MAC length 0 when disabled, got %d", macLen)
	}
}

func TestFilenameAuthTampering(t *testing.T) {
	masterKey := make([]byte, 32)
	fa := New(masterKey, true)

	// Create an authenticated filename
	encryptedName := "test_encrypted_filename"
	authenticatedName, err := fa.AuthenticateFilename(encryptedName)
	if err != nil {
		t.Fatalf("Failed to authenticate filename: %v", err)
	}

	// Tamper with the MAC
	tamperedName := authenticatedName[:len(authenticatedName)-1] + "X"

	// Verification should fail
	_, err = fa.VerifyFilename(tamperedName)
	if err == nil {
		t.Error("Verification should fail for tampered filename")
	}

	// Tamper with the encrypted name
	parts := splitAuthenticatedName(authenticatedName)
	if len(parts) != 2 {
		t.Fatal("Failed to split authenticated name")
	}

	tamperedName2 := "tampered_name" + FilenameAuthSeparator + parts[1]
	_, err = fa.VerifyFilename(tamperedName2)
	if err == nil {
		t.Error("Verification should fail for tampered encrypted name")
	}
}

func TestSplitAuthenticatedName(t *testing.T) {
	// Test normal case
	authenticatedName := "encrypted_name.mac_value"
	parts := splitAuthenticatedName(authenticatedName)
	if len(parts) != 2 {
		t.Errorf("Expected 2 parts, got %d", len(parts))
	}
	if parts[0] != "encrypted_name" {
		t.Errorf("Expected 'encrypted_name', got '%s'", parts[0])
	}
	if parts[1] != "mac_value" {
		t.Errorf("Expected 'mac_value', got '%s'", parts[1])
	}

	// Test case with no separator
	noSepName := "no_separator"
	parts = splitAuthenticatedName(noSepName)
	if len(parts) != 1 {
		t.Errorf("Expected 1 part for name without separator, got %d", len(parts))
	}
	if parts[0] != noSepName {
		t.Errorf("Expected '%s', got '%s'", noSepName, parts[0])
	}

	// Test case with multiple separators (should use the last one)
	multiSepName := "name.with.multiple.separators"
	parts = splitAuthenticatedName(multiSepName)
	if len(parts) != 2 {
		t.Errorf("Expected 2 parts for name with multiple separators, got %d", len(parts))
	}
	if parts[0] != "name.with.multiple" {
		t.Errorf("Expected 'name.with.multiple', got '%s'", parts[0])
	}
	if parts[1] != "separators" {
		t.Errorf("Expected 'separators', got '%s'", parts[1])
	}
}

func BenchmarkFilenameAuth(b *testing.B) {
	masterKey := make([]byte, 32)
	fa := New(masterKey, true)
	encryptedName := "test_encrypted_filename"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		authenticatedName, _ := fa.AuthenticateFilename(encryptedName)
		fa.VerifyFilename(authenticatedName)
	}
}

func BenchmarkFilenameAuthDisabled(b *testing.B) {
	masterKey := make([]byte, 32)
	fa := New(masterKey, false)
	encryptedName := "test_encrypted_filename"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		authenticatedName, _ := fa.AuthenticateFilename(encryptedName)
		fa.VerifyFilename(authenticatedName)
	}
}
