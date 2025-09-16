// Package speed implements the "-speed" command-line option,
// similar to "openssl speed".
// It benchmarks the crypto algorithms and libraries used by
// gocryptfs.
package speed

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"log"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/rfjakob/gocryptfs/v2/internal/cryptocore"
	"github.com/rfjakob/gocryptfs/v2/internal/siv_aead"
	"github.com/rfjakob/gocryptfs/v2/internal/stupidgcm"
)

// 128-bit file ID + 64 bit block number = 192 bits = 24 bytes
const adLen = 24

// gocryptfs uses fixed-size 4 kiB blocks
const gocryptfsBlockSize = 4096

// Run - run the speed the test and print the results.
func Run() {
	runBasicSpeedTest()
}

// RunEnhanced - run enhanced speed tests including decryption and block size scaling
func RunEnhanced() {
	runBasicSpeedTest()
	fmt.Println()
	runDecryptionSpeedTest()
	fmt.Println()
	runBlockSizeSpeedTest()
}

// runBasicSpeedTest - run the basic encryption speed test
func runBasicSpeedTest() {
	cpu := cpuModelName()
	if cpu == "" {
		cpu = "unknown"
	}
	aes := "; no AES-GCM acceleration"
	if stupidgcm.HasAESGCMHardwareSupport() {
		aes = "; with AES-GCM acceleration"
	}
	fmt.Printf("cpu: %s%s\n", cpu, aes)

	bTable := []struct {
		name      string
		f         func(*testing.B)
		preferred bool
	}{
		// AES-GCM variants
		{name: cryptocore.BackendOpenSSL.String(), f: bStupidGCM, preferred: stupidgcm.PreferOpenSSLAES256GCM()},
		{name: cryptocore.BackendGoGCM.String(), f: bGoGCM, preferred: !stupidgcm.PreferOpenSSLAES256GCM()},

		// AES-SIV
		{name: cryptocore.BackendAESSIV.String(), f: bAESSIV, preferred: false},

		// XChaCha20-Poly1305 variants
		{name: cryptocore.BackendXChaCha20Poly1305OpenSSL.String(), f: bStupidXchacha, preferred: stupidgcm.PreferOpenSSLXchacha20poly1305()},
		{name: cryptocore.BackendXChaCha20Poly1305.String(), f: bXchacha20poly1305, preferred: !stupidgcm.PreferOpenSSLXchacha20poly1305()},

		// ChaCha20-Poly1305 variants (additional methods not in main backends)
		{name: "ChaCha20-Poly1305-OpenSSL", f: bStupidChacha, preferred: false},
		{name: "ChaCha20-Poly1305-Go", f: bChacha20poly1305, preferred: false},
	}
	testing.Init()
	for _, b := range bTable {
		fmt.Printf("%-26s\t", b.name)
		mbs := mbPerSec(testing.Benchmark(b.f))
		if mbs > 0 {
			fmt.Printf("%7.2f MB/s", mbs)
		} else {
			fmt.Printf("    N/A")
		}
		if b.preferred {
			fmt.Printf("\t(selected in auto mode)\n")
		} else {
			fmt.Printf("\n")
		}
	}
}

func mbPerSec(r testing.BenchmarkResult) float64 {
	if r.Bytes <= 0 || r.T <= 0 || r.N <= 0 {
		return 0
	}
	return (float64(r.Bytes) * float64(r.N) / 1e6) / r.T.Seconds()
}

// Get "n" random bytes from /dev/urandom or panic
func randBytes(n int) []byte {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		log.Panic("Failed to read random bytes: " + err.Error())
	}
	return b
}

// bEncrypt benchmarks the encryption speed of cipher "c"
func bEncrypt(b *testing.B, c cipher.AEAD) {
	bEncryptBlockSize(b, c, gocryptfsBlockSize)
}

// bEncryptBlockSize benchmarks the encryption speed of cipher "c" at block size "blockSize"
func bEncryptBlockSize(b *testing.B, c cipher.AEAD, blockSize int) {
	authData := randBytes(adLen)
	iv := randBytes(c.NonceSize())
	in := make([]byte, blockSize)
	dst := make([]byte, len(in)+len(iv)+c.Overhead())
	copy(dst, iv)

	b.SetBytes(int64(len(in)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Reset dst buffer
		dst = dst[:len(iv)]
		// Encrypt and append to nonce
		c.Seal(dst, iv, in, authData)
	}
}

func bDecrypt(b *testing.B, c cipher.AEAD) {
	authData := randBytes(adLen)
	iv := randBytes(c.NonceSize())
	plain := randBytes(gocryptfsBlockSize)
	ciphertext := c.Seal(iv, iv, plain, authData)

	b.SetBytes(int64(len(plain)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Reset plain buffer
		plain = plain[:0]
		// Decrypt
		_, err := c.Open(plain, iv, ciphertext[c.NonceSize():], authData)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// bStupidGCM benchmarks stupidgcm's openssl GCM
func bStupidGCM(b *testing.B) {
	if stupidgcm.BuiltWithoutOpenssl {
		b.Skip("openssl has been disabled at compile-time")
	}
	bEncrypt(b, stupidgcm.NewAES256GCM(randBytes(32)))
}

// bGoGCM benchmarks Go stdlib GCM
func bGoGCM(b *testing.B) {
	bGoGCMBlockSize(b, gocryptfsBlockSize)
}

func bGoGCMBlockSize(b *testing.B, blockSize int) {
	gAES, err := aes.NewCipher(randBytes(32))
	if err != nil {
		b.Fatal(err)
	}
	gGCM, err := cipher.NewGCMWithNonceSize(gAES, 16)
	if err != nil {
		b.Fatal(err)
	}
	bEncryptBlockSize(b, gGCM, blockSize)
}

// bAESSIV benchmarks AES-SIV from github.com/aperturerobotics/jacobsa-crypto/siv
func bAESSIV(b *testing.B) {
	c := siv_aead.New(randBytes(64))
	bEncrypt(b, c)
}

// bXchacha20poly1305 benchmarks XChaCha20 from golang.org/x/crypto/chacha20poly1305
func bXchacha20poly1305(b *testing.B) {
	c, _ := chacha20poly1305.NewX(randBytes(32))
	bEncrypt(b, c)
}

// bStupidXchacha benchmarks OpenSSL XChaCha20
func bStupidXchacha(b *testing.B) {
	if stupidgcm.BuiltWithoutOpenssl {
		b.Skip("openssl has been disabled at compile-time")
	}
	bEncrypt(b, stupidgcm.NewXchacha20poly1305(randBytes(32)))
}

// bStupidChacha benchmarks OpenSSL ChaCha20-Poly1305
func bStupidChacha(b *testing.B) {
	if stupidgcm.BuiltWithoutOpenssl {
		b.Skip("openssl has been disabled at compile-time")
	}
	bEncrypt(b, stupidgcm.NewChacha20poly1305(randBytes(32)))
}

// bChacha20poly1305 benchmarks Go ChaCha20-Poly1305
func bChacha20poly1305(b *testing.B) {
	c, _ := chacha20poly1305.New(randBytes(32))
	bEncrypt(b, c)
}

// runDecryptionSpeedTest - run decryption speed tests
func runDecryptionSpeedTest() {
	fmt.Println("Decryption Performance:")
	fmt.Println("======================")

	dTable := []struct {
		name      string
		f         func(*testing.B)
		preferred bool
	}{
		// AES-GCM variants
		{name: cryptocore.BackendOpenSSL.String() + " (decrypt)", f: bStupidGCMDecrypt, preferred: stupidgcm.PreferOpenSSLAES256GCM()},
		{name: cryptocore.BackendGoGCM.String() + " (decrypt)", f: bGoGCMDecrypt, preferred: !stupidgcm.PreferOpenSSLAES256GCM()},

		// AES-SIV
		{name: cryptocore.BackendAESSIV.String() + " (decrypt)", f: bAESSIVDecrypt, preferred: false},

		// XChaCha20-Poly1305 variants
		{name: cryptocore.BackendXChaCha20Poly1305OpenSSL.String() + " (decrypt)", f: bStupidXchachaDecrypt, preferred: stupidgcm.PreferOpenSSLXchacha20poly1305()},
		{name: cryptocore.BackendXChaCha20Poly1305.String() + " (decrypt)", f: bXchacha20poly1305Decrypt, preferred: !stupidgcm.PreferOpenSSLXchacha20poly1305()},

		// ChaCha20-Poly1305 variants
		{name: "ChaCha20-Poly1305-OpenSSL (decrypt)", f: bStupidChachaDecrypt, preferred: false},
		{name: "ChaCha20-Poly1305-Go (decrypt)", f: bChacha20poly1305Decrypt, preferred: false},
	}

	testing.Init()
	for _, b := range dTable {
		fmt.Printf("%-35s\t", b.name)
		mbs := mbPerSec(testing.Benchmark(b.f))
		if mbs > 0 {
			fmt.Printf("%7.2f MB/s", mbs)
		} else {
			fmt.Printf("    N/A")
		}
		if b.preferred {
			fmt.Printf("\t(selected in auto mode)\n")
		} else {
			fmt.Printf("\n")
		}
	}
}

// runBlockSizeSpeedTest - run block size scaling tests
func runBlockSizeSpeedTest() {
	fmt.Println("Block Size Scaling (AES-GCM-256-Go):")
	fmt.Println("=====================================")

	blockSizes := []int{1024, 4096, 16384, 65536, 262144, 1048576}

	testing.Init()
	for _, size := range blockSizes {
		fmt.Printf("%-8d bytes\t", size)
		mbs := mbPerSec(testing.Benchmark(func(b *testing.B) { bGoGCMBlockSize(b, size) }))
		if mbs > 0 {
			fmt.Printf("%7.2f MB/s\n", mbs)
		} else {
			fmt.Printf("    N/A\n")
		}
	}
}

// Decryption benchmark functions
func bStupidGCMDecrypt(b *testing.B) {
	if stupidgcm.BuiltWithoutOpenssl {
		b.Skip("openssl has been disabled at compile-time")
	}
	bDecrypt(b, stupidgcm.NewAES256GCM(randBytes(32)))
}

func bGoGCMDecrypt(b *testing.B) {
	gAES, err := aes.NewCipher(randBytes(32))
	if err != nil {
		b.Fatal(err)
	}
	gGCM, err := cipher.NewGCMWithNonceSize(gAES, 16)
	if err != nil {
		b.Fatal(err)
	}
	bDecrypt(b, gGCM)
}

func bAESSIVDecrypt(b *testing.B) {
	bDecrypt(b, siv_aead.New(randBytes(64)))
}

func bXchacha20poly1305Decrypt(b *testing.B) {
	c, _ := chacha20poly1305.NewX(randBytes(32))
	bDecrypt(b, c)
}

func bStupidXchachaDecrypt(b *testing.B) {
	if stupidgcm.BuiltWithoutOpenssl {
		b.Skip("openssl has been disabled at compile-time")
	}
	bDecrypt(b, stupidgcm.NewXchacha20poly1305(randBytes(32)))
}

func bStupidChachaDecrypt(b *testing.B) {
	if stupidgcm.BuiltWithoutOpenssl {
		b.Skip("openssl has been disabled at compile-time")
	}
	bDecrypt(b, stupidgcm.NewChacha20poly1305(randBytes(32)))
}

func bChacha20poly1305Decrypt(b *testing.B) {
	c, _ := chacha20poly1305.New(randBytes(32))
	bDecrypt(b, c)
}
