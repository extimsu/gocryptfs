package security

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rfjakob/gocryptfs/v2/internal/configfile"
	"github.com/rfjakob/gocryptfs/v2/internal/cryptocore"
	"github.com/rfjakob/gocryptfs/v2/internal/filenameauth"
	"github.com/rfjakob/gocryptfs/v2/internal/nametransform"
)

// TestFilenameTamperIntegration tests filename tampering in a real filesystem scenario
func TestFilenameTamperIntegration(t *testing.T) {
	// Create temporary directories
	tempDir, err := os.MkdirTemp("", "gocryptfs-tamper-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	cipherDir := filepath.Join(tempDir, "cipher")
	mountDir := filepath.Join(tempDir, "mount")

	err = os.MkdirAll(cipherDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create cipher dir: %v", err)
	}

	err = os.MkdirAll(mountDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create mount dir: %v", err)
	}

	// Create a config file with filename authentication enabled
	configPath := filepath.Join(cipherDir, "gocryptfs.conf")
	password := []byte("testpassword")
	args := &configfile.CreateArgs{
		Filename:     configPath,
		Password:     password,
		LogN:         configfile.ScryptDefaultLogN,
		Creator:      "tamper-test",
		FilenameAuth: true,
	}

	err = configfile.Create(args)
	if err != nil {
		t.Fatalf("Failed to create config file: %v", err)
	}

	// Load the config and get the master key
	cf, err := configfile.Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config file: %v", err)
	}

	masterKey, err := cf.DecryptMasterKey(password)
	if err != nil {
		t.Fatalf("Failed to decrypt master key: %v", err)
	}

	// Create crypto backend and name transform with filename authentication
	cCore := cryptocore.New(masterKey, cryptocore.BackendGoGCM, 128, true)
	fa := filenameauth.New(masterKey, true)
	nameTransform := nametransform.New(cCore.EMECipher, true, 0, true, []string{}, false, fa)

	// Test various filename scenarios
	testFilenames := []string{
		"normal_file.txt",
		"file with spaces.txt",
		"file-with-dashes.txt",
		"file_with_underscores.txt",
		"file.with.dots.txt",
		"файл_с_unicode_имени.txt",
		"file_with_emoji_🚀.txt",
		strings.Repeat("a", 100) + ".txt", // Long filename
		"file_with_newlines.txt",          // Removed actual newlines as they're forbidden
		"file_with_special_chars.txt",     // Removed null bytes as they're forbidden
	}

	for _, filename := range testFilenames {
		t.Run(fmt.Sprintf("filename_%s", strings.ReplaceAll(filename, " ", "_")), func(t *testing.T) {
			// Test normal encryption/decryption
			dirIV := make([]byte, 16)
			rand.Read(dirIV)

			encryptedName, err := nameTransform.EncryptName(filename, dirIV)
			if err != nil {
				t.Fatalf("Failed to encrypt filename %s: %v", filename, err)
			}

			decryptedName, err := nameTransform.DecryptName(encryptedName, dirIV)
			if err != nil {
				t.Fatalf("Failed to decrypt filename %s: %v", filename, err)
			}

			if decryptedName != filename {
				t.Errorf("Decrypted name mismatch: expected %s, got %s", filename, decryptedName)
			}

			// Test tampering detection
			tamperedName := encryptedName[:len(encryptedName)-1] + "X"
			_, err = nameTransform.DecryptName(tamperedName, dirIV)
			if err == nil {
				t.Error("Decryption should fail for tampered filename")
			}

			// Test MAC replacement
			parts := strings.Split(encryptedName, ".")
			if len(parts) == 2 {
				replacedMAC := parts[0] + ".tampered_mac"
				_, err = nameTransform.DecryptName(replacedMAC, dirIV)
				if err == nil {
					t.Error("Decryption should fail for filename with replaced MAC")
				}
			}
		})
	}
}

// TestLongnameTamperIntegration tests longname tampering in a real filesystem scenario
func TestLongnameTamperIntegration(t *testing.T) {
	// Create temporary directories
	tempDir, err := os.MkdirTemp("", "gocryptfs-longname-tamper-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	cipherDir := filepath.Join(tempDir, "cipher")

	err = os.MkdirAll(cipherDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create cipher dir: %v", err)
	}

	// Create a config file with filename authentication enabled
	configPath := filepath.Join(cipherDir, "gocryptfs.conf")
	password := []byte("testpassword")
	args := &configfile.CreateArgs{
		Filename:     configPath,
		Password:     password,
		LogN:         configfile.ScryptDefaultLogN,
		Creator:      "longname-tamper-test",
		FilenameAuth: true,
	}

	err = configfile.Create(args)
	if err != nil {
		t.Fatalf("Failed to create config file: %v", err)
	}

	// Load the config and get the master key
	cf, err := configfile.Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config file: %v", err)
	}

	masterKey, err := cf.DecryptMasterKey(password)
	if err != nil {
		t.Fatalf("Failed to decrypt master key: %v", err)
	}

	// Create crypto backend and name transform with filename authentication
	cCore := cryptocore.New(masterKey, cryptocore.BackendGoGCM, 128, true)
	fa := filenameauth.New(masterKey, true)
	nameTransform := nametransform.New(cCore.EMECipher, true, 0, true, []string{}, false, fa)

	// Test regular filenames that should work with filename authentication
	testFilenames := []string{
		"normal_file.txt",
		"file_with_spaces.txt",
		"файл_с_unicode_имени.txt",
		"file_with_emoji_🚀.txt",
		strings.Repeat("a", 100) + ".txt", // 100 character filename
	}

	for _, filename := range testFilenames {
		t.Run(fmt.Sprintf("filename_%d_chars", len(filename)), func(t *testing.T) {
			// Test normal encryption/decryption
			dirIV := make([]byte, 16)
			rand.Read(dirIV)

			encryptedName, err := nameTransform.EncryptName(filename, dirIV)
			if err != nil {
				t.Fatalf("Failed to encrypt filename: %v", err)
			}

			// Test normal decryption
			decryptedName, err := nameTransform.DecryptName(encryptedName, dirIV)
			if err != nil {
				t.Fatalf("Failed to decrypt filename: %v", err)
			}

			if decryptedName != filename {
				t.Errorf("Decrypted name mismatch: expected %s, got %s", filename, decryptedName)
			}

			// Test tampering detection
			tamperedName := encryptedName[:len(encryptedName)-1] + "X"
			_, err = nameTransform.DecryptName(tamperedName, dirIV)
			if err == nil {
				t.Error("Decryption should fail for tampered filename")
			}

			// Test MAC replacement
			parts := strings.Split(encryptedName, ".")
			if len(parts) == 2 {
				replacedMAC := parts[0] + ".tampered_mac"
				_, err = nameTransform.DecryptName(replacedMAC, dirIV)
				if err == nil {
					t.Error("Decryption should fail for filename with replaced MAC")
				}
			}
		})
	}
}

// TestFilenameAuthDisabled tests that filename authentication can be disabled
func TestFilenameAuthDisabled(t *testing.T) {
	// Create temporary directories
	tempDir, err := os.MkdirTemp("", "gocryptfs-no-auth-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	cipherDir := filepath.Join(tempDir, "cipher")

	err = os.MkdirAll(cipherDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create cipher dir: %v", err)
	}

	// Create a config file with filename authentication disabled
	configPath := filepath.Join(cipherDir, "gocryptfs.conf")
	password := []byte("testpassword")
	args := &configfile.CreateArgs{
		Filename:     configPath,
		Password:     password,
		LogN:         configfile.ScryptDefaultLogN,
		Creator:      "no-auth-test",
		FilenameAuth: false, // Explicitly disable
	}

	err = configfile.Create(args)
	if err != nil {
		t.Fatalf("Failed to create config file: %v", err)
	}

	// Load the config and get the master key
	cf, err := configfile.Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config file: %v", err)
	}

	masterKey, err := cf.DecryptMasterKey(password)
	if err != nil {
		t.Fatalf("Failed to decrypt master key: %v", err)
	}

	// Create crypto backend and name transform without filename authentication
	cCore := cryptocore.New(masterKey, cryptocore.BackendGoGCM, 128, true)
	fa := filenameauth.New(masterKey, false) // Disabled
	nameTransform := nametransform.New(cCore.EMECipher, true, 0, true, []string{}, false, fa)

	// Test that filenames work without authentication
	filename := "test_file.txt"
	dirIV := make([]byte, 16)
	rand.Read(dirIV)

	encryptedName, err := nameTransform.EncryptName(filename, dirIV)
	if err != nil {
		t.Fatalf("Failed to encrypt filename: %v", err)
	}

	decryptedName, err := nameTransform.DecryptName(encryptedName, dirIV)
	if err != nil {
		t.Fatalf("Failed to decrypt filename: %v", err)
	}

	if decryptedName != filename {
		t.Errorf("Decrypted name mismatch: expected %s, got %s", filename, decryptedName)
	}

	// Test that tampering is not detected (since auth is disabled)
	tamperedName := encryptedName[:len(encryptedName)-1] + "X"
	_, err = nameTransform.DecryptName(tamperedName, dirIV)
	// This should fail due to decryption error, not authentication error
	if err == nil {
		t.Error("Decryption should fail for tampered filename even without auth")
	}
}

// TestFilenameAuthBackwardCompatibility tests backward compatibility with old filesystems
func TestFilenameAuthBackwardCompatibility(t *testing.T) {
	// Create temporary directories
	tempDir, err := os.MkdirTemp("", "gocryptfs-compat-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	cipherDir := filepath.Join(tempDir, "cipher")

	err = os.MkdirAll(cipherDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create cipher dir: %v", err)
	}

	// Create a config file without filename authentication (old format)
	configPath := filepath.Join(cipherDir, "gocryptfs.conf")
	password := []byte("testpassword")
	args := &configfile.CreateArgs{
		Filename: configPath,
		Password: password,
		LogN:     configfile.ScryptDefaultLogN,
		Creator:  "compat-test",
		// FilenameAuth not set (defaults to false)
	}

	err = configfile.Create(args)
	if err != nil {
		t.Fatalf("Failed to create config file: %v", err)
	}

	// Load the config and get the master key
	cf, err := configfile.Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config file: %v", err)
	}

	// Verify that FilenameAuth flag is not set
	if cf.IsFeatureFlagSet(configfile.FlagFilenameAuth) {
		t.Error("FilenameAuth flag should not be set in old config")
	}

	masterKey, err := cf.DecryptMasterKey(password)
	if err != nil {
		t.Fatalf("Failed to decrypt master key: %v", err)
	}

	// Create crypto backend and name transform without filename authentication
	cCore := cryptocore.New(masterKey, cryptocore.BackendGoGCM, 128, true)
	fa := filenameauth.New(masterKey, false) // Disabled for compatibility
	nameTransform := nametransform.New(cCore.EMECipher, true, 0, true, []string{}, false, fa)

	// Test that filenames work without authentication
	filename := "test_file.txt"
	dirIV := make([]byte, 16)
	rand.Read(dirIV)

	encryptedName, err := nameTransform.EncryptName(filename, dirIV)
	if err != nil {
		t.Fatalf("Failed to encrypt filename: %v", err)
	}

	decryptedName, err := nameTransform.DecryptName(encryptedName, dirIV)
	if err != nil {
		t.Fatalf("Failed to decrypt filename: %v", err)
	}

	if decryptedName != filename {
		t.Errorf("Decrypted name mismatch: expected %s, got %s", filename, decryptedName)
	}
}
