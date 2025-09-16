// Package cpudetection provides CPU feature detection utilities
// to automatically select the best encryption backend based on hardware capabilities.
package cpudetection

import (
	"runtime"
	"strings"

	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

// CPUFeatures represents detected CPU capabilities
type CPUFeatures struct {
	// AES hardware acceleration
	AESNI bool
	// AVX/AVX2 support
	AVX  bool
	AVX2 bool
	// ARM NEON support
	NEON bool
	// CPU architecture
	Arch string
	// CPU model/vendor
	Model string
}

// CPUDetector provides CPU feature detection
type CPUDetector struct {
	features *CPUFeatures
}

// New creates a new CPUDetector instance
func New() *CPUDetector {
	cd := &CPUDetector{}
	cd.detectFeatures()
	return cd
}

// GetFeatures returns the detected CPU features
func (cd *CPUDetector) GetFeatures() *CPUFeatures {
	return cd.features
}

// detectFeatures detects CPU features based on the current platform
func (cd *CPUDetector) detectFeatures() {
	cd.features = &CPUFeatures{
		Arch: runtime.GOARCH,
	}

	switch runtime.GOOS {
	case "linux":
		cd.detectLinuxFeatures()
	case "darwin":
		cd.detectDarwinFeatures()
	case "windows":
		cd.detectWindowsFeatures()
	default:
		cd.detectGenericFeatures()
	}

	tlog.Debug.Printf("CPUDetector: Detected features - Arch: %s, AESNI: %v, AVX: %v, AVX2: %v, NEON: %v",
		cd.features.Arch, cd.features.AESNI, cd.features.AVX, cd.features.AVX2, cd.features.NEON)
}

// detectLinuxFeatures detects CPU features on Linux
func (cd *CPUDetector) detectLinuxFeatures() {
	// Read /proc/cpuinfo to detect CPU features
	// This is a simplified implementation
	// In a real implementation, you would parse /proc/cpuinfo

	// For now, we'll use heuristics based on architecture
	switch cd.features.Arch {
	case "amd64":
		cd.features.AESNI = true // Most modern x86_64 CPUs have AES-NI
		cd.features.AVX = true   // Most modern x86_64 CPUs have AVX
		cd.features.AVX2 = true  // Many modern x86_64 CPUs have AVX2
	case "arm64":
		cd.features.NEON = true // ARM64 typically has NEON
	}
}

// detectDarwinFeatures detects CPU features on macOS
func (cd *CPUDetector) detectDarwinFeatures() {
	// On macOS, we can use sysctl to detect CPU features
	// This is a simplified implementation

	switch cd.features.Arch {
	case "amd64":
		cd.features.AESNI = true // Intel Macs typically have AES-NI
		cd.features.AVX = true   // Intel Macs typically have AVX
		cd.features.AVX2 = true  // Many Intel Macs have AVX2
	case "arm64":
		cd.features.NEON = true // Apple Silicon has NEON
		cd.features.Model = "Apple Silicon"
	}
}

// detectWindowsFeatures detects CPU features on Windows
func (cd *CPUDetector) detectWindowsFeatures() {
	// On Windows, we would use CPUID or WMI
	// This is a simplified implementation

	switch cd.features.Arch {
	case "amd64":
		cd.features.AESNI = true // Most modern x86_64 CPUs have AES-NI
		cd.features.AVX = true   // Most modern x86_64 CPUs have AVX
		cd.features.AVX2 = true  // Many modern x86_64 CPUs have AVX2
	}
}

// detectGenericFeatures provides fallback detection
func (cd *CPUDetector) detectGenericFeatures() {
	// Generic detection based on architecture
	switch cd.features.Arch {
	case "amd64":
		cd.features.AESNI = true // Assume modern x86_64 has AES-NI
		cd.features.AVX = true   // Assume modern x86_64 has AVX
	case "arm64":
		cd.features.NEON = true // Assume ARM64 has NEON
	}
}

// GetRecommendedBackend returns the recommended encryption backend based on CPU features
func (cd *CPUDetector) GetRecommendedBackend() string {
	features := cd.GetFeatures()

	// For x86_64 with AES-NI, prefer AES-GCM with OpenSSL
	if features.Arch == "amd64" && features.AESNI {
		return "aes-gcm-openssl"
	}

	// For ARM64 with NEON, prefer AES-GCM with Go (optimized for ARM)
	if features.Arch == "arm64" && features.NEON {
		return "aes-gcm-go"
	}

	// For other cases, use XChaCha20-Poly1305 (good performance across platforms)
	return "xchacha20-poly1305-go"
}

// GetPerformanceHint returns a performance hint based on CPU features
func (cd *CPUDetector) GetPerformanceHint() string {
	features := cd.GetFeatures()

	if features.Arch == "amd64" && features.AESNI {
		return "AES-GCM with OpenSSL backend recommended for best performance on x86_64"
	}

	if features.Arch == "arm64" && features.NEON {
		return "AES-GCM with Go backend recommended for best performance on ARM64"
	}

	return "XChaCha20-Poly1305 recommended for cross-platform compatibility"
}

// IsOptimalForAES returns whether the CPU is optimal for AES operations
func (cd *CPUDetector) IsOptimalForAES() bool {
	features := cd.GetFeatures()
	return (features.Arch == "amd64" && features.AESNI) ||
		(features.Arch == "arm64" && features.NEON)
}

// IsOptimalForChaCha returns whether the CPU is optimal for ChaCha20 operations
func (cd *CPUDetector) IsOptimalForChaCha() bool {
	features := cd.GetFeatures()
	// ChaCha20 performs well on most modern CPUs
	return features.Arch == "amd64" || features.Arch == "arm64"
}

// GetArchitecture returns the CPU architecture
func (cd *CPUDetector) GetArchitecture() string {
	return cd.features.Arch
}

// GetModel returns the CPU model/vendor
func (cd *CPUDetector) GetModel() string {
	return cd.features.Model
}

// String returns a human-readable description of CPU features
func (cd *CPUDetector) String() string {
	features := cd.GetFeatures()
	var parts []string

	parts = append(parts, "Arch: "+features.Arch)

	if features.AESNI {
		parts = append(parts, "AES-NI")
	}
	if features.AVX {
		parts = append(parts, "AVX")
	}
	if features.AVX2 {
		parts = append(parts, "AVX2")
	}
	if features.NEON {
		parts = append(parts, "NEON")
	}

	if features.Model != "" {
		parts = append(parts, "Model: "+features.Model)
	}

	return strings.Join(parts, ", ")
}
