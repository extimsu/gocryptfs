package configfile

import (
	"fmt"
	"os"

	"golang.org/x/crypto/argon2"

	"github.com/rfjakob/gocryptfs/v2/internal/cryptocore"
	"github.com/rfjakob/gocryptfs/v2/internal/exitcodes"
	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

const (
	// Argon2idDefaultMemory is the default memory usage in KB (64MB)
	Argon2idDefaultMemory = 64 * 1024
	// Argon2idDefaultIterations is the default number of iterations
	Argon2idDefaultIterations = 3
	// Argon2idDefaultParallelism is the default parallelism factor
	Argon2idDefaultParallelism = 4
	// Argon2idMinMemory is the minimum memory usage in KB (16MB)
	Argon2idMinMemory = 16 * 1024
	// Argon2idMinIterations is the minimum number of iterations
	Argon2idMinIterations = 1
	// Argon2idMinParallelism is the minimum parallelism factor
	Argon2idMinParallelism = 1
	// Argon2idMinSaltLen is the minimum salt length
	Argon2idMinSaltLen = 16
)

// Argon2idKDF is an instance of the Argon2id key derivation function.
type Argon2idKDF struct {
	// Salt is the random salt that is passed to Argon2id
	Salt []byte
	// Memory is the memory usage in KB
	Memory uint32
	// Iterations is the number of iterations
	Iterations uint32
	// Parallelism is the parallelism factor
	Parallelism uint8
	// KeyLen is the output data length
	KeyLen uint32
}

// NewArgon2idKDF returns a new instance of Argon2idKDF with secure defaults.
func NewArgon2idKDF() Argon2idKDF {
	var a Argon2idKDF
	a.Salt = cryptocore.RandBytes(cryptocore.KeyLen)
	a.Memory = Argon2idDefaultMemory
	a.Iterations = Argon2idDefaultIterations
	a.Parallelism = Argon2idDefaultParallelism
	a.KeyLen = cryptocore.KeyLen
	return a
}

// NewArgon2idKDFWithParams returns a new instance of Argon2idKDF with custom parameters.
func NewArgon2idKDFWithParams(memory uint32, iterations uint32, parallelism uint8) Argon2idKDF {
	var a Argon2idKDF
	a.Salt = cryptocore.RandBytes(cryptocore.KeyLen)
	a.Memory = memory
	a.Iterations = iterations
	a.Parallelism = parallelism
	a.KeyLen = cryptocore.KeyLen
	return a
}

// DeriveKey returns a new key from a supplied password using Argon2id.
func (a *Argon2idKDF) DeriveKey(pw []byte) []byte {
	if err := a.validateParams(); err != nil {
		tlog.Fatal.Println(err.Error())
		os.Exit(exitcodes.ScryptParams)
	}

	// Argon2id(password, salt, time, memory, parallelism, keyLen)
	key := argon2.IDKey(pw, a.Salt, a.Iterations, a.Memory, a.Parallelism, a.KeyLen)
	return key
}

// validateParams checks that all parameters are at or above hardcoded limits.
func (a *Argon2idKDF) validateParams() error {
	if a.Memory < Argon2idMinMemory {
		return fmt.Errorf("fatal: Argon2id memory below minimum: value=%d KB, min=%d KB", a.Memory, Argon2idMinMemory)
	}
	if a.Iterations < Argon2idMinIterations {
		return fmt.Errorf("fatal: Argon2id iterations below minimum: value=%d, min=%d", a.Iterations, Argon2idMinIterations)
	}
	if a.Parallelism < Argon2idMinParallelism {
		return fmt.Errorf("fatal: Argon2id parallelism below minimum: value=%d, min=%d", a.Parallelism, Argon2idMinParallelism)
	}
	if len(a.Salt) < Argon2idMinSaltLen {
		return fmt.Errorf("fatal: Argon2id salt length below minimum: value=%d, min=%d", len(a.Salt), Argon2idMinSaltLen)
	}
	if a.KeyLen < cryptocore.KeyLen {
		return fmt.Errorf("fatal: Argon2id key length below minimum: value=%d, min=%d", a.KeyLen, cryptocore.KeyLen)
	}
	return nil
}

// GetRecommendedParams returns recommended Argon2id parameters based on system capabilities.
// This is a simplified version - in a real implementation, you might want to benchmark
// the system to determine optimal parameters.
func GetRecommendedArgon2idParams() (memory uint32, iterations uint32, parallelism uint8) {
	// Conservative defaults that should work well on modern systems
	// Memory: 64MB (reasonable for most systems)
	// Iterations: 3 (good balance of security and performance)
	// Parallelism: 4 (utilizes multiple cores)
	return Argon2idDefaultMemory, Argon2idDefaultIterations, Argon2idDefaultParallelism
}
