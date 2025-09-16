// Package filenameauth provides filename authentication using MAC (Message Authentication Code)
// to detect tampering with directory entries and provide integrity protection.
package filenameauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/rfjakob/gocryptfs/v2/internal/cryptocore"
)

const (
	// FilenameAuthMACLen is the length of the MAC in bytes
	FilenameAuthMACLen = 32 // SHA256 HMAC
	// FilenameAuthSeparator is used to separate the encrypted name from the MAC
	FilenameAuthSeparator = "."
)

// FilenameAuth provides filename authentication functionality
type FilenameAuth struct {
	enabled bool
	macKey  []byte
}

// New creates a new FilenameAuth instance
func New(masterKey []byte, enabled bool) *FilenameAuth {
	fa := &FilenameAuth{
		enabled: enabled,
	}

	if enabled {
		// Derive MAC key from master key using HKDF
		fa.macKey = deriveFilenameMACKey(masterKey)
	}

	return fa
}

// IsEnabled returns whether filename authentication is enabled
func (fa *FilenameAuth) IsEnabled() bool {
	return fa.enabled
}

// AuthenticateFilename adds a MAC to an encrypted filename
func (fa *FilenameAuth) AuthenticateFilename(encryptedName string) (string, error) {
	if !fa.enabled {
		return encryptedName, nil
	}

	// Calculate HMAC-SHA256 of the encrypted filename
	mac := fa.calculateMAC([]byte(encryptedName))

	// Encode MAC as base64
	macB64 := base64.URLEncoding.EncodeToString(mac)

	// Combine encrypted name and MAC
	authenticatedName := encryptedName + FilenameAuthSeparator + macB64

	return authenticatedName, nil
}

// VerifyFilename verifies the MAC of an authenticated filename
func (fa *FilenameAuth) VerifyFilename(authenticatedName string) (string, error) {
	if !fa.enabled {
		return authenticatedName, nil
	}

	// Split the authenticated name into encrypted name and MAC
	parts := splitAuthenticatedName(authenticatedName)
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid authenticated filename format")
	}

	encryptedName := parts[0]
	macB64 := parts[1]

	// Decode the MAC
	mac, err := base64.URLEncoding.DecodeString(macB64)
	if err != nil {
		return "", fmt.Errorf("failed to decode MAC: %v", err)
	}

	// Verify the MAC
	expectedMAC := fa.calculateMAC([]byte(encryptedName))
	if !hmac.Equal(mac, expectedMAC) {
		return "", fmt.Errorf("filename authentication failed: MAC mismatch")
	}

	return encryptedName, nil
}

// calculateMAC calculates HMAC-SHA256 of the given data
func (fa *FilenameAuth) calculateMAC(data []byte) []byte {
	h := hmac.New(sha256.New, fa.macKey)
	h.Write(data)
	return h.Sum(nil)
}

// deriveFilenameMACKey derives a MAC key from the master key using HKDF
func deriveFilenameMACKey(masterKey []byte) []byte {
	// Use HKDF to derive a key specifically for filename authentication
	// This ensures the MAC key is different from other derived keys
	info := []byte("gocryptfs-filename-auth-v1")
	return cryptocore.HKDFDerive(masterKey, info, FilenameAuthMACLen)
}

// splitAuthenticatedName splits an authenticated filename into encrypted name and MAC
func splitAuthenticatedName(authenticatedName string) []string {
	// Find the last occurrence of the separator
	lastSep := -1
	for i := len(authenticatedName) - 1; i >= 0; i-- {
		if authenticatedName[i] == FilenameAuthSeparator[0] {
			lastSep = i
			break
		}
	}

	if lastSep == -1 {
		return []string{authenticatedName}
	}

	return []string{
		authenticatedName[:lastSep],
		authenticatedName[lastSep+1:],
	}
}

// GetMACLength returns the length of the MAC in bytes
func (fa *FilenameAuth) GetMACLength() int {
	if !fa.enabled {
		return 0
	}
	return FilenameAuthMACLen
}

// GetSeparator returns the separator used between encrypted name and MAC
func (fa *FilenameAuth) GetSeparator() string {
	return FilenameAuthSeparator
}

// Wipe securely wipes the MAC key from memory
func (fa *FilenameAuth) Wipe() {
	if fa.macKey != nil {
		for i := range fa.macKey {
			fa.macKey[i] = 0
		}
		fa.macKey = nil
	}
}
