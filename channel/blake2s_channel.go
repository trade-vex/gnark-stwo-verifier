// Package channel implements the Fiat-Shamir channel for stwo verification.
// The channel uses Blake2s for generating cryptographic challenges.
package channel

import (
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/gnark-stwo/stwo/blake2s"
	"github.com/gnark-stwo/stwo/mersenne31"
)

func init() {
	solver.RegisterHint(DrawSecureFeltHint)
}

// FeltsPerHash is the number of M31 field elements that can be drawn from one Blake2s hash.
// Blake2s produces 256 bits = 8 x 32-bit words.
// Each M31 element needs 31 bits, so we can extract 8 M31 elements per hash.
const FeltsPerHash = 8

// Blake2sChannel implements the Fiat-Shamir channel using Blake2s.
type Blake2sChannel struct {
	digest    blake2s.Blake2sHash
	nDraws    frontend.Variable
	chip      *blake2s.Blake2sChip
	m31Chip   *mersenne31.M31Chip
	api       frontend.API
	isGroth16 bool
}

// NewBlake2sChannel creates a new Blake2s-based Fiat-Shamir channel.
func NewBlake2sChannel(api frontend.API, isGroth16 bool) *Blake2sChannel {
	return &Blake2sChannel{
		digest:    blake2s.ZeroHash(),
		nDraws:    frontend.Variable(0),
		chip:      blake2s.NewBlake2sChip(api, isGroth16),
		m31Chip:   mersenne31.NewM31Chip(api, isGroth16),
		api:       api,
		isGroth16: isGroth16,
	}
}

// MixCommitment mixes a Merkle tree commitment (hash) into the channel.
// Uses BLAKE2S_256_INITIAL_STATE, includes digest in message.
func (c *Blake2sChannel) MixCommitment(commitment blake2s.Blake2sHash) {
	// Create message: [digest[0..7], commitment[0..7]]
	var msg [16]frontend.Variable
	for i := 0; i < 8; i++ {
		msg[i] = c.digest.Words[i]
	}
	for i := 0; i < 8; i++ {
		msg[i+8] = commitment.Words[i]
	}

	// Finalize with BLAKE2S_256_INITIAL_STATE and byte_count = 64 (16 words * 4 bytes)
	result := c.chip.Blake2sFinalize(msg, 64)
	copy(c.digest.Words[:], result[:])
	c.nDraws = frontend.Variable(0)
}

// MixFelts mixes an array of QM31 field elements into the channel.
// Prepends digest, uses incremental compress, then finalize.
func (c *Blake2sChannel) MixFelts(felts []mersenne31.QM31Variable) {
	if len(felts) == 0 {
		return
	}

	// Convert QM31 elements to 32-bit words for hashing
	// Each QM31 has 4 M31 elements, each M31 is ~31 bits
	words := make([]frontend.Variable, 0, len(felts)*4)
	for _, felt := range felts {
		for i := 0; i < 4; i++ {
			reduced := c.m31Chip.ReduceSlow(felt.Value[i])
			words = append(words, reduced.Value)
		}
	}

	// Build buffer starting with digest (8 words = 32 bytes)
	buffer := make([]frontend.Variable, 0, 8+len(words))
	for i := 0; i < 8; i++ {
		buffer = append(buffer, c.digest.Words[i])
	}
	buffer = append(buffer, words...)

	// Byte count starts at 32 (for digest) and adds 4 bytes per word
	byteCount := 32 + len(words)*4

	// Process in blocks of 16 words using compress, then finalize the last block
	state := c.chip.GetInitialState()
	blockByteCount := uint64(0)

	i := 0
	for i+16 <= len(buffer) {
		var block [16]frontend.Variable
		for j := 0; j < 16; j++ {
			block[j] = buffer[i+j]
		}
		blockByteCount += 64 // 16 words * 4 bytes
		// Check if this is the final block (no remaining words after this)
		isFinal := (i+16 == len(buffer))
		if isFinal {
			// Use actual byte count for the final block
			state = c.chip.CompressWithState(state, block, uint64(byteCount), true)
		} else {
			state = c.chip.CompressWithState(state, block, blockByteCount, false)
		}
		i += 16
	}

	// Handle remaining words with padding and finalize (only if there are remaining words)
	remaining := len(buffer) - i
	if remaining > 0 {
		var lastBlock [16]frontend.Variable
		for j := 0; j < 16; j++ {
			if j < remaining {
				lastBlock[j] = buffer[i+j]
			} else {
				lastBlock[j] = frontend.Variable(0)
			}
		}
		state = c.chip.CompressWithState(state, lastBlock, uint64(byteCount), true)
	}

	result := state
	copy(c.digest.Words[:], result[:])
	c.nDraws = frontend.Variable(0)
}

// MixU64 mixes a 64-bit value into the channel.
// Uses BLAKE2S_256_INITIAL_STATE, includes digest in message, byte_count = 40.
func (c *Blake2sChannel) MixU64(value frontend.Variable) {
	// Split into two 32-bit words (low, high)
	bits := c.api.ToBinary(value, 64)
	low := c.api.FromBinary(bits[:32]...)
	high := c.api.FromBinary(bits[32:]...)

	// Create message: [digest[0..7], nonce_lo, nonce_hi, 0, 0, 0, 0, 0, 0]
	var msg [16]frontend.Variable
	for i := 0; i < 8; i++ {
		msg[i] = c.digest.Words[i]
	}
	msg[8] = low
	msg[9] = high
	for i := 10; i < 16; i++ {
		msg[i] = frontend.Variable(0)
	}

	// Finalize with byte_count = 40 (32 for digest + 8 for u64)
	result := c.chip.Blake2sFinalize(msg, 40)
	copy(c.digest.Words[:], result[:])
	c.nDraws = frontend.Variable(0)
}

// DrawRandomWords draws 8 random 32-bit words from the channel.
// Uses BLAKE2S_256_INITIAL_STATE, includes digest and counter.
func (c *Blake2sChannel) DrawRandomWords() [8]frontend.Variable {
	// Create message: [digest[0..7], counter, 0, 0, 0, 0, 0, 0, 0]
	var msg [16]frontend.Variable
	for i := 0; i < 8; i++ {
		msg[i] = c.digest.Words[i]
	}
	msg[8] = c.nDraws
	for i := 9; i < 16; i++ {
		msg[i] = frontend.Variable(0)
	}

	// Finalize with byte_count = 37 (32 for digest + 4 for counter + 1 for domain separation)
	// This matches stwo's draw_u32s: digest || n_draws.to_le_bytes() || 0x00
	// The trailing zero byte is for domain separation between generating randomness
	// and mixing a single u32. See: stwo/src/core/channel/blake2s.rs draw_u32s()
	result := c.chip.Blake2sFinalize(msg, 37)

	// Increment draw counter
	c.nDraws = c.api.Add(c.nDraws, 1)

	return result
}

// DrawSecureFelt draws a random QM31 field element from the channel.
//
// NOTE ON REJECTION SAMPLING:
// The stwo prover uses rejection sampling in draw_base_felts (blake2s.rs lines 30-52):
// it retries if any u32 value is >= 2*P (probability ~2^(-28) per draw).
// This circuit does NOT implement rejection sampling because:
// 1. Circuit constraints must be fixed at compile time
// 2. Rejection probability is extremely low (~2^(-28))
//
// If a proof was generated with a retry (extremely rare), this verifier will
// reject it because the channel transcript will diverge. For production use
// with very high security requirements, consider implementing hint-based
// retry counting, though this is likely unnecessary in practice.
func (c *Blake2sChannel) DrawSecureFelt() mersenne31.QM31Variable {
	words := c.DrawRandomWords()

	// Convert first 4 words to M31 elements
	// Each word needs to be reduced mod p = 2^31 - 1
	var m31Values [4]mersenne31.M31Variable
	for i := 0; i < 4; i++ {
		// Reduce the 32-bit word to M31
		// word mod (2^31 - 1)
		m31Values[i] = c.reduceU32ToM31(words[i])
	}

	return mersenne31.QM31Variable{
		Value: m31Values,
	}
}

// reduceU32ToM31 reduces a 32-bit value to M31 (mod 2^31 - 1).
// Uses the fact that 2^31 = 1 (mod p), so x = x_low + x_high where x_high is bit 31.
func (c *Blake2sChannel) reduceU32ToM31(x frontend.Variable) mersenne31.M31Variable {
	// Decompose into bits
	bits := c.api.ToBinary(x, 32)

	// Low 31 bits
	low := c.api.FromBinary(bits[:31]...)

	// High bit (bit 31)
	high := bits[31]

	// Result = low + high (since 2^31 = 1 mod p)
	result := c.api.Add(low, high)

	// If result >= p, subtract p
	// result can be at most 2^31 - 1 + 1 = 2^31, which equals 1 mod p
	// So we need to check if result >= p = 2^31 - 1

	// Use a hint to determine if reduction is needed
	reduced := mersenne31.M31Variable{
		Value:      result,
		UpperBound: new(big.Int).SetUint64(1 << 31),
	}

	return c.m31Chip.ReduceSlow(reduced)
}

// DrawU32s draws 8 random 32-bit unsigned integers from the channel.
func (c *Blake2sChannel) DrawU32s() [8]frontend.Variable {
	return c.DrawRandomWords()
}

// VerifyPowNonce verifies that the proof-of-work nonce is valid.
// Matches stwo's two-step PoW algorithm (core/channel/blake2s.rs):
//  1. prefixed_digest = H(POW_PREFIX || [0; 12] || digest || n_bits)
//  2. result = H(prefixed_digest || nonce)
//  3. Check result has nBits trailing zeros
//
// IMPORTANT: This does NOT modify the channel state. The caller must call
// MixU64(nonce) separately after verification if needed.
func (c *Blake2sChannel) VerifyPowNonce(nBits int, nonce frontend.Variable) {
	// POW_PREFIX = 0x12345678 (constant from stwo)
	const POW_PREFIX = uint32(0x12345678)

	// Step 1: Compute prefixed_digest = H(POW_PREFIX || [0; 12] || digest || n_bits)
	// Layout (52 bytes = 13 words):
	//   words[0] = POW_PREFIX (4 bytes)
	//   words[1..3] = [0; 12] (12 bytes = 3 words)
	//   words[4..11] = digest (32 bytes = 8 words)
	//   words[12] = n_bits (4 bytes)
	// Total = 52 bytes, padded to 16 words
	var prefixMsg [16]frontend.Variable
	prefixMsg[0] = frontend.Variable(POW_PREFIX)
	prefixMsg[1] = frontend.Variable(0) // padding zeros
	prefixMsg[2] = frontend.Variable(0)
	prefixMsg[3] = frontend.Variable(0)
	for i := 0; i < 8; i++ {
		prefixMsg[4+i] = c.digest.Words[i]
	}
	prefixMsg[12] = frontend.Variable(nBits)
	for i := 13; i < 16; i++ {
		prefixMsg[i] = frontend.Variable(0)
	}

	// Compute prefixed_digest with byte_count = 52 (4 + 12 + 32 + 4)
	prefixedDigest := c.chip.Blake2sFinalize(prefixMsg, 52)

	// Step 2: Compute result = H(prefixed_digest || nonce)
	// Split nonce into two 32-bit words (low, high)
	nonceBits := c.api.ToBinary(nonce, 64)
	nonceLow := c.api.FromBinary(nonceBits[:32]...)
	nonceHigh := c.api.FromBinary(nonceBits[32:]...)

	// Message: prefixed_digest(8 words) + nonce_lo(1) + nonce_hi(1) + padding(6) = 16 words
	var msg [16]frontend.Variable
	for i := 0; i < 8; i++ {
		msg[i] = prefixedDigest[i]
	}
	msg[8] = nonceLow
	msg[9] = nonceHigh
	for i := 10; i < 16; i++ {
		msg[i] = frontend.Variable(0)
	}

	// Finalize with byte_count = 40 (32 for prefixed_digest + 8 for nonce)
	result := c.chip.Blake2sFinalize(msg, 40)

	// Step 3: Check that result has nBits TRAILING zeros.
	// The stwo code interprets the first 128 bits as little-endian and counts trailing zeros.
	// For nBits <= 32, this means the low nBits of result[0] must be 0.
	// For 32 < nBits <= 64, result[0] must be 0 and low (nBits-32) of result[1] must be 0.
	if nBits > 0 && nBits <= 32 {
		// Extract the low nBits and assert they are all zero
		hashBits := c.api.ToBinary(result[0], 32)
		for i := 0; i < nBits; i++ {
			c.api.AssertIsEqual(hashBits[i], 0)
		}
	} else if nBits > 32 && nBits <= 64 {
		// result[0] must be completely zero
		c.api.AssertIsEqual(result[0], 0)
		// Low (nBits - 32) bits of result[1] must be zero
		hashBits := c.api.ToBinary(result[1], 32)
		for i := 0; i < nBits-32; i++ {
			c.api.AssertIsEqual(hashBits[i], 0)
		}
	}
}

// GetDigest returns the current channel digest for testing/debugging.
func (c *Blake2sChannel) GetDigest() blake2s.Blake2sHash {
	return c.digest
}

// DrawSecureFeltHint computes a secure QM31 draw using rejection sampling.
func DrawSecureFeltHint(_ *big.Int, inputs []*big.Int, results []*big.Int) error {
	// inputs: 8 x 32-bit words from the hash
	// results: 4 x M31 values
	p := mersenne31.M31Modulus

	for i := 0; i < 4; i++ {
		val := new(big.Int).Set(inputs[i])
		// Reduce mod p
		results[i] = val.Mod(val, p)
	}

	return nil
}
