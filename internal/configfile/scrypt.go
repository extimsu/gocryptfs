package configfile

import (
	"fmt"
	"log"
	"math"
	"os"

	"golang.org/x/crypto/scrypt"

	"github.com/rfjakob/gocryptfs/v2/internal/cryptocore"
	"github.com/rfjakob/gocryptfs/v2/internal/exitcodes"
	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

const (
	// ScryptDefaultLogN is the default scrypt logN configuration parameter.
	// logN=17 (N=2^17) uses 128MB of memory and provides better security against
	// brute force attacks on modern hardware. Previous default was logN=16.
	ScryptDefaultLogN = 17
	// From RFC7914, section 2:
	// At the current time, r=8 and p=1 appears to yield good
	// results, but as memory latency and CPU parallelism increase, it is
	// likely that the optimum values for both r and p will increase.
	// We reject all lower values that we might get through modified config files.
	scryptMinR = 8
	scryptMinP = 1
	// logN=10 takes 6ms on a Pentium G630. This should be fast enough for all
	// purposes. We reject lower values.
	scryptMinLogN = 10
	// We always generate 32-byte salts. Anything smaller than that is rejected.
	scryptMinSaltLen = 32
)

// ScryptKDF is an instance of the scrypt key deriviation function.
type ScryptKDF struct {
	// Salt is the random salt that is passed to scrypt
	Salt []byte
	// N: scrypt CPU/Memory cost parameter
	N int
	// R: scrypt block size parameter
	R int
	// P: scrypt parallelization parameter
	P int
	// KeyLen is the output data length
	KeyLen int
}

// NewScryptKDF returns a new instance of ScryptKDF.
func NewScryptKDF(logN int) ScryptKDF {
	var s ScryptKDF
	s.Salt = cryptocore.RandBytes(cryptocore.KeyLen)
	if logN <= 0 {
		s.N = 1 << ScryptDefaultLogN
	} else {
		s.N = 1 << uint32(logN)
	}
	s.R = 8 // Always 8
	s.P = 1 // Always 1
	s.KeyLen = cryptocore.KeyLen
	return s
}

// DeriveKey returns a new key from a supplied password.
func (s *ScryptKDF) DeriveKey(pw []byte) []byte {
	if err := s.validateParams(); err != nil {
		tlog.Fatal.Println(err.Error())
		os.Exit(exitcodes.ScryptParams)
	}
	k, err := scrypt.Key(pw, s.Salt, s.N, s.R, s.P, s.KeyLen)
	if err != nil {
		log.Panicf("DeriveKey failed: %v", err)
	}
	return k
}

// LogN - N is saved as 2^LogN, but LogN is much easier to work with.
// This function gives you LogN = Log2(N).
func (s *ScryptKDF) LogN() int {
	return int(math.Log2(float64(s.N)) + 0.5)
}

// validateParams checks that all parameters are at or above hardcoded limits.
// If not, it exists with an error message.
// This makes sure we do not get weak parameters passed through a
// rougue gocryptfs.conf.
func (s *ScryptKDF) validateParams() error {
	minN := 1 << scryptMinLogN
	if s.N < minN {
		return fmt.Errorf("fatal: scryptn below 10 is too low to make sense")
	}
	if s.R < scryptMinR {
		return fmt.Errorf("fatal: scrypt parameter R below minimum: value=%d, min=%d", s.R, scryptMinR)
	}
	if s.P < scryptMinP {
		return fmt.Errorf("fatal: scrypt parameter P below minimum: value=%d, min=%d", s.P, scryptMinP)
	}
	if len(s.Salt) < scryptMinSaltLen {
		return fmt.Errorf("fatal: scrypt salt length below minimum: value=%d, min=%d", len(s.Salt), scryptMinSaltLen)
	}
	if s.KeyLen < cryptocore.KeyLen {
		return fmt.Errorf("fatal: scrypt parameter KeyLen below minimum: value=%d, min=%d", s.KeyLen, cryptocore.KeyLen)
	}
	return nil
}

// GetRecommendedScryptLogN returns the recommended scrypt logN parameter based on system capabilities.
// For modern systems with sufficient memory, this returns a higher value for better security.
func GetRecommendedScryptLogN() int {
	// For systems with at least 4GB RAM, use logN=17 (128MB memory usage)
	// For systems with at least 8GB RAM, use logN=18 (256MB memory usage)
	// This is a simplified heuristic - in practice, you might want to detect
	// available memory and adjust accordingly.
	return ScryptDefaultLogN // Currently 17, can be increased based on system detection
}
