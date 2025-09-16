// Package contentenc encrypts and decrypts file blocks.
package contentenc

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"log"
	"runtime"
	"sync"

	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/rfjakob/gocryptfs/v2/internal/cryptocore"
	"github.com/rfjakob/gocryptfs/v2/internal/parallelcrypto"
	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

const (
	// DefaultBS is the default plaintext block size
	DefaultBS = 4096
	// DefaultIVBits is the default length of IV, in bits.
	// We always use 128-bit IVs for file content, but the
	// master key in the config file is encrypted with a 96-bit IV for
	// gocryptfs v1.2 and earlier. v1.3 switched to 128 bit.
	DefaultIVBits = 128
)

// ContentEnc is used to encipher and decipher file content.
type ContentEnc struct {
	// Cryptographic primitives
	cryptoCore *cryptocore.CryptoCore
	// plainBS is the plaintext block size. Usually 4096 bytes.
	plainBS uint64
	// cipherBS is the ciphertext block size. Usually 4128 bytes.
	// `cipherBS - plainBS`is the per-block overhead
	// (use BlockOverhead() to calculate it for you!)
	cipherBS uint64
	// All-zero block of size cipherBS, for fast compares
	allZeroBlock []byte
	// All-zero block of size IVBitLen/8, for fast compares
	allZeroNonce []byte

	// Enhanced parallel crypto processing
	parallelCrypto *parallelcrypto.ParallelCrypto

	// Ciphertext block "sync.Pool" pool. Always returns cipherBS-sized byte
	// slices (usually 4128 bytes).
	cBlockPool bPool
	// Plaintext block pool. Always returns plainBS-sized byte slices
	// (usually 4096 bytes).
	pBlockPool bPool
	// Ciphertext request data pool. Always returns byte slices of size
	// fuse.MAX_KERNEL_WRITE + encryption overhead.
	// Used by Read() to temporarily store the ciphertext as it is read from
	// disk.
	CReqPool bPool
	// Plaintext request data pool. Slice have size fuse.MAX_KERNEL_WRITE.
	PReqPool bPool
}

// New returns an initialized ContentEnc instance.
func New(cc *cryptocore.CryptoCore, plainBS uint64) *ContentEnc {
	tlog.Debug.Printf("contentenc.New: plainBS=%d", plainBS)

	if fuse.MAX_KERNEL_WRITE%plainBS != 0 {
		log.Panicf("unaligned MAX_KERNEL_WRITE=%d", fuse.MAX_KERNEL_WRITE)
	}
	cipherBS := plainBS + uint64(cc.IVLen) + cryptocore.AuthTagLen
	// Take IV and GHASH overhead into account.
	cReqSize := int(fuse.MAX_KERNEL_WRITE / plainBS * cipherBS)
	// Unaligned reads (happens during fsck, could also happen with O_DIRECT?)
	// touch one additional ciphertext and plaintext block. Reserve space for the
	// extra block.
	cReqSize += int(cipherBS)
	pReqSize := fuse.MAX_KERNEL_WRITE + int(plainBS)
	c := &ContentEnc{
		cryptoCore:     cc,
		plainBS:        plainBS,
		cipherBS:       cipherBS,
		allZeroBlock:   make([]byte, cipherBS),
		allZeroNonce:   make([]byte, cc.IVLen),
		parallelCrypto: parallelcrypto.New(),
		cBlockPool:     newBPool(int(cipherBS)),
		CReqPool:       newBPool(cReqSize),
		pBlockPool:     newBPool(int(plainBS)),
		PReqPool:       newBPool(pReqSize),
	}
	return c
}

// PlainBS returns the plaintext block size
func (be *ContentEnc) PlainBS() uint64 {
	return be.plainBS
}

// CipherBS returns the ciphertext block size
func (be *ContentEnc) CipherBS() uint64 {
	return be.cipherBS
}

// DecryptBlocks decrypts a number of blocks
func (be *ContentEnc) DecryptBlocks(ciphertext []byte, firstBlockNo uint64, fileID []byte) ([]byte, error) {
	// Calculate number of blocks
	blockCount := len(ciphertext) / int(be.cipherBS)
	if blockCount == 0 {
		return []byte{}, nil
	}

	// Use optimized processing based on block count and CPU features
	if be.parallelCrypto.ShouldUseParallel(blockCount) {
		return be.decryptBlocksParallel(ciphertext, firstBlockNo, fileID, blockCount)
	} else if be.parallelCrypto.ShouldUseBatch(blockCount) {
		return be.decryptBlocksBatch(ciphertext, firstBlockNo, fileID, blockCount)
	}

	// Use sequential processing for very small operations
	return be.decryptBlocksSequential(ciphertext, firstBlockNo, fileID)
}

// decryptBlocksSequential performs sequential decryption (original logic)
func (be *ContentEnc) decryptBlocksSequential(ciphertext []byte, firstBlockNo uint64, fileID []byte) ([]byte, error) {
	cBuf := bytes.NewBuffer(ciphertext)
	var err error
	pBuf := bytes.NewBuffer(be.PReqPool.Get()[:0])
	blockNo := firstBlockNo
	for cBuf.Len() > 0 {
		cBlock := cBuf.Next(int(be.cipherBS))
		var pBlock []byte
		pBlock, err = be.DecryptBlock(cBlock, blockNo, fileID)
		if err != nil {
			break
		}
		pBuf.Write(pBlock)
		be.pBlockPool.Put(pBlock)
		blockNo++
	}
	// Return the buffer data and let the caller handle the pool
	return pBuf.Bytes(), err
}

// decryptBlocksParallel performs parallel decryption for large block counts
func (be *ContentEnc) decryptBlocksParallel(ciphertext []byte, firstBlockNo uint64, fileID []byte, blockCount int) ([]byte, error) {
	// Split ciphertext into blocks
	cipherBlocks := make([][]byte, blockCount)
	for i := 0; i < blockCount; i++ {
		start := i * int(be.cipherBS)
		end := start + int(be.cipherBS)
		cipherBlocks[i] = ciphertext[start:end]
	}

	// Decrypt blocks in parallel
	plainBlocks := make([][]byte, blockCount)
	var decryptErr error
	var mu sync.Mutex

	be.parallelCrypto.ProcessBlocksParallel(blockCount, func(startIdx, endIdx int) {
		for i := startIdx; i < endIdx; i++ {
			blockNo := firstBlockNo + uint64(i)
			plainBlock, err := be.DecryptBlock(cipherBlocks[i], blockNo, fileID)

			mu.Lock()
			if err != nil && decryptErr == nil {
				decryptErr = err
			}
			plainBlocks[i] = plainBlock
			mu.Unlock()
		}
	})

	if decryptErr != nil {
		// Clean up allocated blocks on error
		for _, block := range plainBlocks {
			if block != nil {
				be.pBlockPool.Put(block)
			}
		}
		return nil, decryptErr
	}

	// Pre-calculate total size for better memory allocation
	totalSize := 0
	for _, block := range plainBlocks {
		totalSize += len(block)
	}

	// Concatenate plaintext blocks with pre-allocated capacity
	pBuf := bytes.NewBuffer(be.PReqPool.Get()[:0])
	pBuf.Grow(totalSize) // Pre-allocate capacity for better performance

	for _, block := range plainBlocks {
		pBuf.Write(block)
		be.pBlockPool.Put(block)
	}

	return pBuf.Bytes(), nil
}

// decryptBlocksBatch performs batch decryption for medium-sized operations
func (be *ContentEnc) decryptBlocksBatch(ciphertext []byte, firstBlockNo uint64, fileID []byte, blockCount int) ([]byte, error) {
	// Split ciphertext into blocks
	cipherBlocks := make([][]byte, blockCount)
	for i := 0; i < blockCount; i++ {
		start := i * int(be.cipherBS)
		end := start + int(be.cipherBS)
		cipherBlocks[i] = ciphertext[start:end]
	}

	// Decrypt blocks in batches for better cache locality
	plainBlocks := make([][]byte, blockCount)
	var decryptErr error
	var mu sync.Mutex

	be.parallelCrypto.ProcessBlocksBatch(blockCount, func(startIdx, endIdx int) {
		for i := startIdx; i < endIdx; i++ {
			blockNo := firstBlockNo + uint64(i)
			plainBlock, err := be.DecryptBlock(cipherBlocks[i], blockNo, fileID)

			mu.Lock()
			if err != nil && decryptErr == nil {
				decryptErr = err
			}
			plainBlocks[i] = plainBlock
			mu.Unlock()
		}
	})

	if decryptErr != nil {
		// Clean up allocated blocks on error
		for _, block := range plainBlocks {
			if block != nil {
				be.pBlockPool.Put(block)
			}
		}
		return nil, decryptErr
	}

	// Pre-calculate total size for better memory allocation
	totalSize := 0
	for _, block := range plainBlocks {
		totalSize += len(block)
	}

	// Concatenate plaintext blocks with pre-allocated capacity
	pBuf := bytes.NewBuffer(be.PReqPool.Get()[:0])
	pBuf.Grow(totalSize) // Pre-allocate capacity for better performance

	for _, block := range plainBlocks {
		pBuf.Write(block)
		be.pBlockPool.Put(block)
	}

	return pBuf.Bytes(), nil
}

// concatAD concatenates the block number and the file ID to a byte blob
// that can be passed to AES-GCM as associated data (AD).
// Result is: aData = [blockNo.bigEndian fileID].
func concatAD(blockNo uint64, fileID []byte) (aData []byte) {
	if fileID != nil && len(fileID) != headerIDLen {
		// fileID is nil when decrypting the master key from the config file,
		// and for symlinks and xattrs.
		log.Panicf("wrong fileID length: %d", len(fileID))
	}
	const lenUint64 = 8
	// Preallocate space to save an allocation in append()
	aData = make([]byte, lenUint64, lenUint64+headerIDLen)
	binary.BigEndian.PutUint64(aData, blockNo)
	aData = append(aData, fileID...)
	return aData
}

// DecryptBlock - Verify and decrypt GCM block
//
// Corner case: A full-sized block of all-zero ciphertext bytes is translated
// to an all-zero plaintext block, i.e. file hole passthrough.
func (be *ContentEnc) DecryptBlock(ciphertext []byte, blockNo uint64, fileID []byte) ([]byte, error) {

	// Empty block?
	if len(ciphertext) == 0 {
		return ciphertext, nil
	}

	// All-zero block?
	if bytes.Equal(ciphertext, be.allZeroBlock) {
		tlog.Debug.Printf("DecryptBlock: file hole encountered")
		return make([]byte, be.plainBS), nil
	}

	if len(ciphertext) < be.cryptoCore.IVLen {
		tlog.Warn.Printf("DecryptBlock: Block is too short: %d bytes", len(ciphertext))
		return nil, errors.New("block is too short")
	}

	// Extract nonce
	nonce := ciphertext[:be.cryptoCore.IVLen]
	if bytes.Equal(nonce, be.allZeroNonce) {
		// Bug in tmpfs?
		// https://github.com/rfjakob/gocryptfs/issues/56
		// http://www.spinics.net/lists/kernel/msg2370127.html
		return nil, errors.New("all-zero nonce")
	}
	ciphertextOrig := ciphertext
	ciphertext = ciphertext[be.cryptoCore.IVLen:]

	// Decrypt
	plaintext := be.pBlockPool.Get()
	plaintext = plaintext[:0]
	aData := concatAD(blockNo, fileID)
	plaintext, err := be.cryptoCore.AEADCipher.Open(plaintext, nonce, ciphertext, aData)

	if err != nil {
		tlog.Debug.Printf("DecryptBlock: %s, len=%d", err.Error(), len(ciphertextOrig))
		tlog.Debug.Println(hex.Dump(ciphertextOrig))
		return nil, err
	}

	return plaintext, nil
}

// At some point, splitting the ciphertext into more groups will not improve
// performance, as spawning goroutines comes at a cost.
// 2 seems to work ok for now.
const encryptMaxSplit = 2

// encryptBlocksParallel splits the plaintext into parts and encrypts them
// in parallel.
func (be *ContentEnc) encryptBlocksParallel(plaintextBlocks [][]byte, ciphertextBlocks [][]byte, firstBlockNo uint64, fileID []byte) {
	ncpu := runtime.NumCPU()
	if ncpu > encryptMaxSplit {
		ncpu = encryptMaxSplit
	}
	groupSize := len(plaintextBlocks) / ncpu
	var wg sync.WaitGroup
	for i := 0; i < ncpu; i++ {
		wg.Add(1)
		go func(i int) {
			low := i * groupSize
			high := (i + 1) * groupSize
			if i == ncpu-1 {
				// Last part picks up any left-over blocks
				//
				// The last part could run in the original goroutine, but
				// doing that complicates the code, and, surprisingly,
				// incurs a 1 % performance penalty.
				high = len(plaintextBlocks)
			}
			be.doEncryptBlocks(plaintextBlocks[low:high], ciphertextBlocks[low:high], firstBlockNo+uint64(low), fileID)
			wg.Done()
		}(i)
	}
	wg.Wait()
}

// EncryptBlocks is like EncryptBlock but takes multiple plaintext blocks.
// Returns a byte slice from CReqPool - so don't forget to return it
// to the pool.
func (be *ContentEnc) EncryptBlocks(plaintextBlocks [][]byte, firstBlockNo uint64, fileID []byte) []byte {
	ciphertextBlocks := make([][]byte, len(plaintextBlocks))

	// Use optimized parallel encryption with CPU-aware processing
	be.parallelCrypto.ProcessBlocksOptimized(len(plaintextBlocks), func(startIdx, endIdx int) {
		for i := startIdx; i < endIdx; i++ {
			ciphertextBlocks[i] = be.EncryptBlock(plaintextBlocks[i], firstBlockNo+uint64(i), fileID)
		}
	})

	// Pre-calculate total size for better memory allocation
	totalSize := 0
	for _, block := range ciphertextBlocks {
		totalSize += len(block)
	}

	// Concatenate ciphertext into a single byte array with pre-allocated capacity
	tmp := be.CReqPool.Get()
	out := bytes.NewBuffer(tmp[:0])
	out.Grow(totalSize) // Pre-allocate capacity for better performance

	for _, v := range ciphertextBlocks {
		out.Write(v)
		// Return the memory to cBlockPool
		be.cBlockPool.Put(v)
	}
	return out.Bytes()
}

// doEncryptBlocks is called by EncryptBlocks to do the actual encryption work
func (be *ContentEnc) doEncryptBlocks(in [][]byte, out [][]byte, firstBlockNo uint64, fileID []byte) {
	for i, v := range in {
		out[i] = be.EncryptBlock(v, firstBlockNo+uint64(i), fileID)
	}
}

// EncryptBlock - Encrypt plaintext using a random nonce.
// blockNo and fileID are used as associated data.
// The output is nonce + ciphertext + tag.
func (be *ContentEnc) EncryptBlock(plaintext []byte, blockNo uint64, fileID []byte) []byte {
	// Get a fresh random nonce
	nonce := be.cryptoCore.IVGenerator.Get()
	return be.doEncryptBlock(plaintext, blockNo, fileID, nonce)
}

// EncryptBlockNonce - Encrypt plaintext using a nonce chosen by the caller.
// blockNo and fileID are used as associated data.
// The output is nonce + ciphertext + tag.
// This function can only be used in SIV mode.
func (be *ContentEnc) EncryptBlockNonce(plaintext []byte, blockNo uint64, fileID []byte, nonce []byte) []byte {
	if be.cryptoCore.AEADBackend != cryptocore.BackendAESSIV {
		log.Panic("deterministic nonces are only secure in SIV mode")
	}
	return be.doEncryptBlock(plaintext, blockNo, fileID, nonce)
}

// doEncryptBlock is the backend for EncryptBlock and EncryptBlockNonce.
// blockNo and fileID are used as associated data.
// The output is nonce + ciphertext + tag.
func (be *ContentEnc) doEncryptBlock(plaintext []byte, blockNo uint64, fileID []byte, nonce []byte) []byte {
	// Empty block?
	if len(plaintext) == 0 {
		return plaintext
	}
	if len(nonce) != be.cryptoCore.IVLen {
		log.Panic("wrong nonce length")
	}
	// Block is authenticated with block number and file ID
	aData := concatAD(blockNo, fileID)
	// Get a cipherBS-sized block of memory, copy the nonce into it and truncate to
	// nonce length
	cBlock := be.cBlockPool.Get()
	copy(cBlock, nonce)
	cBlock = cBlock[0:len(nonce)]
	// Encrypt plaintext and append to nonce
	ciphertext := be.cryptoCore.AEADCipher.Seal(cBlock, nonce, plaintext, aData)
	overhead := int(be.BlockOverhead())
	if len(plaintext)+overhead != len(ciphertext) {
		log.Panicf("unexpected ciphertext length: plaintext=%d, overhead=%d, ciphertext=%d",
			len(plaintext), overhead, len(ciphertext))
	}
	return ciphertext
}

// MergeBlocks - Merge newData into oldData at offset
// New block may be bigger than both newData and oldData
func (be *ContentEnc) MergeBlocks(oldData []byte, newData []byte, offset int) []byte {
	// Fastpath for small-file creation
	if len(oldData) == 0 && offset == 0 {
		return newData
	}

	// Make block of maximum size
	out := make([]byte, be.plainBS)

	// Copy old and new data into it
	copy(out, oldData)
	l := len(newData)
	copy(out[offset:offset+l], newData)

	// Crop to length
	outLen := len(oldData)
	newLen := offset + len(newData)
	if outLen < newLen {
		outLen = newLen
	}
	return out[0:outLen]
}

// Wipe tries to wipe secret keys from memory by overwriting them with zeros
// and/or setting references to nil.
func (be *ContentEnc) Wipe() {
	be.cryptoCore.Wipe()
	be.cryptoCore = nil
}
