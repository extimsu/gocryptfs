# gocryptfs Threat Model

## Overview

This document outlines the threat model for gocryptfs, including the security guarantees provided, potential attack vectors, and limitations. Understanding this threat model is crucial for making informed decisions about when and how to use gocryptfs.

## Security Guarantees

### 1. Confidentiality

gocryptfs provides strong confidentiality guarantees for:

- **File Content**: All file data is encrypted using authenticated encryption (AES-GCM, XChaCha20-Poly1305, or AES-SIV)
- **File Names**: Filenames are encrypted using EME (ECB-Mix-ECB) mode (unless PlaintextNames is enabled)
- **Directory Structure**: Directory names and structure are encrypted
- **File Metadata**: File sizes, timestamps, and permissions are protected

**Enhanced Features:**
- **Memory Protection**: Key material is locked in memory using `mlock`/`mlockall` and marked as `MADV_DONTDUMP`
- **Process Hardening**: Core dumps are disabled and key buffers are protected from garbage collection
- **Filename Authentication**: Optional MAC authentication for filenames to detect tampering

### 2. Integrity

gocryptfs provides integrity protection through:

- **Authenticated Encryption**: All content encryption uses AEAD (Authenticated Encryption with Associated Data)
- **File Header Authentication**: Each file has an authenticated header
- **Directory IV Authentication**: Directory initialization vectors are authenticated
- **Filename Authentication**: Optional MAC authentication for filenames (new feature)

### 3. Availability

gocryptfs provides availability guarantees through:

- **Crash Safety**: Atomic operations and fsync on parent directories
- **Error Recovery**: Graceful handling of corrupted files and directories
- **Backward Compatibility**: Support for older filesystem versions

## Threat Vectors and Mitigations

### 1. Passive Attacks

#### **Traffic Analysis**
- **Threat**: An attacker can analyze encrypted traffic patterns
- **Mitigation**: 
  - Use consistent file sizes where possible
  - Consider padding small files
  - Use longnames for files with predictable names

#### **Metadata Leakage**
- **Threat**: File sizes, access patterns, and directory structure can leak information
- **Mitigation**:
  - Use consistent file sizes
  - Avoid predictable directory structures
  - Consider using longnames for sensitive files

#### **Timing Attacks**
- **Threat**: Attackers can infer information from timing patterns
- **Mitigation**:
  - Use constant-time operations where possible
  - CPU-aware backend selection helps avoid timing variations

### 2. Active Attacks

#### **Tampering with Encrypted Data**
- **Threat**: Attackers modify encrypted files or directories
- **Mitigation**:
  - Authenticated encryption detects tampering
  - Filename authentication (new feature) detects directory tampering
  - Regular integrity checks with `-fsck`

#### **Key Recovery Attacks**
- **Threat**: Attackers attempt to recover the master key
- **Mitigation**:
  - Strong password-based key derivation (scrypt/Argon2id)
  - Memory protection prevents key extraction from memory dumps
  - Process hardening prevents core dumps
  - Secure key wiping

#### **Side-Channel Attacks**
- **Threat**: Attackers use side channels (cache, timing, power) to extract keys
- **Mitigation**:
  - Constant-time operations where possible
  - CPU-aware backend selection
  - Memory protection reduces exposure

### 3. Implementation Attacks

#### **Buffer Overflows**
- **Threat**: Malicious input causes buffer overflows
- **Mitigation**:
  - Go's memory safety
  - Bounds checking
  - Input validation

#### **Race Conditions**
- **Threat**: Concurrent access causes data corruption
- **Mitigation**:
  - Atomic operations
  - Proper locking
  - Shared storage mode for concurrent access

## Limitations and Assumptions

### 1. Trusted Computing Base

gocryptfs assumes:
- **Operating System**: The OS kernel and filesystem are trusted
- **Hardware**: CPU, memory, and storage are trusted
- **Go Runtime**: The Go runtime and standard library are trusted
- **FUSE**: The FUSE implementation is trusted

### 2. Threat Model Limitations

#### **Not Protected Against:**
- **Physical Access**: If an attacker has physical access to the system while mounted
- **Root Compromise**: If the system is compromised with root privileges
- **Hardware Attacks**: Direct hardware attacks (cold boot, DMA, etc.)
- **Social Engineering**: Attacks against users (phishing, etc.)
- **Malware**: Malicious software running with user privileges

#### **Partial Protection:**
- **Memory Dumps**: Protected by memory locking and process hardening, but not bulletproof
- **Swap Files**: Memory locking helps, but swap can still contain sensitive data
- **Core Dumps**: Disabled by process hardening, but not guaranteed on all systems

### 3. Performance vs Security Trade-offs

#### **Security Features with Performance Impact:**
- **Memory Locking**: Prevents swapping but uses more RAM
- **Process Hardening**: Reduces debugging capabilities
- **Filename Authentication**: Adds overhead for directory operations
- **Strong KDF**: Argon2id is slower than scrypt but more secure

#### **Performance Features with Security Implications:**
- **PlaintextNames**: Disables filename encryption for performance
- **Writeback Cache**: May delay writes, affecting crash safety
- **Async Reads**: May affect order guarantees

## Best Practices

### 1. Configuration Recommendations

#### **For Maximum Security:**
```bash
# Use Argon2id for key derivation
gocryptfs -init -argon2id /path/to/cipherdir

# Enable filename authentication
gocryptfs -init -filename-auth /path/to/cipherdir

# Use CPU-aware backend selection
gocryptfs -init -cpu-aware /path/to/cipherdir

# Use larger block sizes for better performance
gocryptfs -init -blocksize 16384 /path/to/cipherdir
```

#### **For Maximum Performance:**
```bash
# Use XChaCha20-Poly1305 for better performance on some systems
gocryptfs -init -xchacha /path/to/cipherdir

# Enable FUSE optimizations
gocryptfs -writeback-cache -async-read /path/to/cipherdir /path/to/mountpoint

# Use larger block sizes
gocryptfs -init -blocksize 65536 /path/to/cipherdir
```

### 2. Operational Security

#### **Key Management:**
- Use strong, unique passwords
- Store master keys securely (paper backup)
- Rotate keys periodically
- Use FIDO2 tokens when available

#### **System Security:**
- Keep the system updated
- Use secure boot when available
- Minimize attack surface
- Monitor for suspicious activity

#### **Backup and Recovery:**
- Regular backups of encrypted data
- Test recovery procedures
- Store backups securely
- Document recovery processes

### 3. Monitoring and Auditing

#### **Log Monitoring:**
- Monitor gocryptfs logs for errors
- Watch for authentication failures
- Track mount/unmount events
- Monitor system resource usage

#### **Integrity Checking:**
- Regular filesystem checks with `-fsck`
- Monitor for unexpected file changes
- Verify backup integrity
- Check for tampering indicators

## Security Considerations for New Features

### 1. Filename Authentication

**Security Benefit**: Detects tampering with directory entries
**Limitations**: 
- Only protects against tampering, not confidentiality
- Adds overhead to directory operations
- May not detect all forms of tampering

### 2. Memory Protection

**Security Benefit**: Prevents key extraction from memory dumps
**Limitations**:
- Not available on all platforms
- May not protect against all memory attacks
- Can be disabled by system configuration

### 3. Process Hardening

**Security Benefit**: Reduces attack surface and prevents core dumps
**Limitations**:
- May affect debugging capabilities
- Not available on all platforms
- Can be bypassed by privileged processes

### 4. CPU-Aware Backend Selection

**Security Benefit**: Optimizes performance while maintaining security
**Limitations**:
- May not be optimal for all use cases
- Requires CPU feature detection
- May not be available on all platforms

## Conclusion

gocryptfs provides strong security guarantees for file and directory encryption, with enhanced features that improve both security and performance. However, it's important to understand the limitations and trade-offs involved.

The threat model shows that gocryptfs is well-suited for protecting data at rest and in transit, but users must be aware of the assumptions and limitations. Proper configuration, operational security, and regular monitoring are essential for maintaining security.

For high-security environments, consider additional security measures such as:
- Hardware security modules (HSMs)
- Secure boot and trusted platform modules (TPMs)
- Network security and access controls
- Regular security audits and penetration testing

## References

- [gocryptfs Security Documentation](Documentation/SECURITY.md)
- [File Format Specification](Documentation/file-format.md)
- [Performance Documentation](Documentation/performance.txt)
- [FUSE Security Considerations](https://github.com/libfuse/libfuse/wiki/Security-considerations)
- [Go Security Best Practices](https://golang.org/doc/security.html)
