# Security and Performance Improvements

This document tracks the implementation of security and performance improvements to gocryptfs.

## Implemented Improvements

### 1. HKDF Default Enablement ✅

**Status**: Already implemented (default since gocryptfs v1.3)

**Description**: HKDF (HMAC-based Key Derivation Function) is enabled by default for all new filesystems, providing better key compartmentalization.

**Implementation Details**:

- HKDF is automatically set for new filesystems in `internal/configfile/config_file.go:91`
- CLI flag defaults to `true` in `cli_args.go:182`
- Provides separate derived keys for different cryptographic purposes:
  - EME filename encryption
  - AES-GCM file content encryption  
  - AES-SIV file content encryption
  - XChaCha20-Poly1305 file content encryption

**Security Benefits**:

- Prevents key reuse across different cryptographic contexts
- Reduces risk of cross-protocol attacks
- Follows cryptographic best practices for key derivation

**Migration**: Existing filesystems without HKDF continue to work. Users can migrate by recreating the filesystem or using the `-passwd` command to update the config.

**Code References**:

- `internal/cryptocore/hkdf.go` - HKDF implementation
- `internal/configfile/config_file.go:91` - Default enablement
- `internal/configfile/feature_flags.go:26-31` - Feature flag definition

## Planned Improvements

### 2. Argon2id KDF Alternative ✅

**Status**: Implemented

**Description**: Added Argon2id as an alternative to scrypt for password-based key derivation.

**Implementation Details**:

- New `Argon2idKDF` struct with secure default parameters (64MB memory, 3 iterations, 4 parallelism)
- CLI flag `-argon2id` to enable Argon2id during filesystem initialization
- Feature flag `FlagArgon2id` for config file compatibility
- Automatic parameter validation with minimum security thresholds
- Integration with existing key derivation and encryption pipeline

**Security Benefits**:

- Better resistance to ASIC attacks compared to scrypt
- More modern KDF following current cryptographic best practices
- Configurable memory usage and iteration parameters
- Maintains same security properties as scrypt with different attack resistance profile

**Usage**: `gocryptfs -init -argon2id /path/to/cipherdir`

**Code References**:

- `internal/configfile/argon2.go` - Argon2id implementation
- `internal/configfile/feature_flags.go:37-38` - Feature flag definition
- `cli_args.go:34,191` - CLI flag support
- `init_dir.go:112` - Integration with filesystem initialization

### 3. Scrypt Cost Parameter Increase ✅

**Status**: Implemented

**Description**: Increased default scrypt cost parameter from logN=16 to logN=17 for better security.

**Implementation Details**:

- Updated `ScryptDefaultLogN` from 16 to 17 (doubles memory usage from 64MB to 128MB)
- Added `GetRecommendedScryptLogN()` function for future system-aware parameter selection
- Updated test expectations to reflect new default
- Maintains backward compatibility - existing filesystems continue to work
- Minimum threshold remains at logN=10 for compatibility

**Security Benefits**:

- Doubles the computational cost of brute force attacks
- Better resistance against modern hardware-accelerated attacks
- Maintains reasonable performance on modern systems
- Follows security best practices for password-based key derivation

**Performance Impact**:

- Doubles memory usage during key derivation (64MB → 128MB)
- Increases derivation time proportionally
- Still reasonable for modern systems with sufficient RAM

**Code References**:

- `internal/configfile/scrypt.go:20` - Updated default value
- `internal/configfile/scrypt.go:107-115` - Recommended parameters function
- `cli_args_test.go:124` - Updated test expectations

### 4. Filename Authentication

**Status**: Pending
**Description**: Add optional MAC per directory entry to detect tampering
**Benefits**: Integrity protection for directory structure

### 5. Memory Protection Hardening ✅

**Status**: Implemented

**Description**: Added memory locking (mlock/mlockall) and MADV_DONTDUMP to prevent key material from being swapped to disk or included in core dumps.

**Implementation Details**:

- New `memprotect` package with platform-specific implementations for macOS and Linux
- Memory locking using `mlock()` system calls to prevent swapping
- MADV_DONTDUMP flag to exclude sensitive memory from core dumps (Linux)
- Secure memory wiping with `SecureWipe()` function
- Automatic cleanup on application exit
- Integration with key derivation and encryption functions

**Security Benefits**:

- Prevents key material from being written to swap files
- Excludes sensitive memory from core dumps
- Reduces risk of key exposure through memory dumps
- Follows cryptographic best practices for key handling

**Code References**:

- `internal/memprotect/memprotect.go` - Core memory protection interface
- `internal/memprotect/memprotect_darwin.go` - macOS-specific implementation
- `internal/memprotect/memprotect_linux.go` - Linux-specific implementation
- `internal/configfile/config_file.go` - Integration with key handling

### 6. Config File Durability ✅

**Status**: Implemented

**Description**: Added fsync of parent directory after config file atomic rename for crash safety.

**Implementation Details**:

- Added parent directory fsync after `os.Rename()` in `WriteFile()` function
- Opens parent directory and calls `Sync()` to ensure metadata persistence
- Graceful error handling - logs warnings but doesn't fail the operation if fsync fails
- Handles cases where directory fsync is not supported (e.g., network filesystems)

**Security Benefits**:

- Prevents config file loss during system crashes
- Ensures atomic config file updates are properly persisted
- Critical for maintaining filesystem integrity after password changes
- Follows POSIX filesystem durability best practices

**Technical Details**:

- Uses `filepath.Dir()` to get parent directory path
- Opens directory with `os.Open()` and calls `Sync()`
- Non-blocking error handling - operation succeeds even if fsync fails
- Maintains backward compatibility with existing behavior

**Code References**:

- `internal/configfile/config_file.go:351-371` - Parent directory fsync implementation
- `internal/configfile/config_file.go:9` - Added filepath import

### 7. CPU-Aware Backend Selection ✅

**Status**: Implemented

**Description**: Implemented CPU feature detection and automatic selection of encryption backends based on hardware capabilities.

**Implementation Details**:

- New `cpudetection` package for CPU feature detection
- Automatic detection of AES-NI, AVX, AVX2, and NEON support
- Platform-specific detection for Linux, macOS, and Windows
- CLI flag `--cpu-aware` to enable automatic backend selection
- Intelligent backend selection based on CPU capabilities:
  - x86_64 with AES-NI: AES-GCM with OpenSSL backend
  - ARM64 with NEON: AES-GCM with Go backend
  - Other cases: XChaCha20-Poly1305 with Go backend

**Security Benefits**:

- Ensures optimal performance without compromising security
- Automatically selects the most secure and performant backend
- Reduces user configuration errors
- Provides consistent security across different hardware platforms

**Code References**:

- `internal/cpudetection/cpudetection.go` - CPU feature detection implementation
- `cli_args.go:193` - CLI flag registration
- `cli_args.go:284-311` - CPU-aware backend selection logic

### 8. Parallel Crypto Operations

**Status**: Pending
**Description**: Implement parallel block encryption/decryption for large I/O
**Benefits**: Better throughput for large file operations

### 9. Configurable Block Sizes

**Status**: Pending
**Description**: Add configurable block size (16-64KB) for new filesystems
**Benefits**: Better performance tuning for different workloads

### 10. Write Coalescing

**Status**: Pending
**Description**: Implement per-file write buffer for small-write coalescing
**Benefits**: Reduced encryption overhead for small writes

### 11. FUSE I/O Optimizations

**Status**: Pending
**Description**: Add writeback_cache and async_read options where safe
**Benefits**: Better I/O performance through kernel optimizations

## Testing and Validation

Each improvement includes:

- Comprehensive unit tests
- Performance benchmarks
- Security validation tests
- Backward compatibility verification

### Performance Benchmark Scripts

Created comprehensive benchmark tools for testing gocryptfs performance:

**Files Created:**

- `benchmark-crypto.sh` - Full-featured benchmark suite with multiple configurations
- `quick-benchmark.sh` - Simple performance test for basic metrics
- `BENCHMARK_README.md` - Comprehensive documentation and usage guide

**Features:**

- Multiple encryption backends (AES-GCM, AES-SIV, XChaCha20-Poly1305)
- Different key derivation functions (scrypt, Argon2id)
- Configurable test sizes and iteration counts
- Concurrent operation testing
- CSV output for analysis
- System information collection
- Automatic cleanup and error handling

**Usage Examples:**

```bash
# Basic benchmark
./benchmark-crypto.sh

# Test with XChaCha20-Poly1305 and Argon2id
./benchmark-crypto.sh -x -a

# Custom test parameters with output file
./benchmark-crypto.sh -c 10 -j 8 --sizes 1M,10M,100M -f results.csv

# Quick performance test
./quick-benchmark.sh
```

**Performance Metrics:**

- Write/read throughput (MB/s)
- Small file operations (files/s)
- Random access performance (ops/s)
- Concurrent operation scaling
- System resource utilization

## Documentation

- Threat model documentation
- Performance tuning guides
- Migration guides for breaking changes
