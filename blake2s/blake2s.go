// Package blake2s implements the Blake2s hash function in gnark circuits.
package blake2s

import (
	"encoding/binary"

	"github.com/consensys/gnark/frontend"
	"golang.org/x/crypto/blake2s"
)

// Blake2sHash represents a 256-bit Blake2s hash output.
// Stored as 8 x 32-bit words.
// Note: We use a struct wrapper instead of a bare [8]frontend.Variable to work around
// a gnark schema bug where arrayElementType doesn't handle Leaf types when len(fields) > 0.
// See: https://github.com/Consensys/gnark/blob/master/frontend/schema/schema.go#L154
type Blake2sHash struct {
	Words [8]frontend.Variable
}

// Blake2sChip provides Blake2s operations in gnark circuits.
type Blake2sChip struct {
	api       frontend.API
	isGroth16 bool
}

// NewBlake2sChip creates a new Blake2sChip for the given gnark API.
func NewBlake2sChip(api frontend.API, isGroth16 bool) *Blake2sChip {
	return &Blake2sChip{
		api:       api,
		isGroth16: isGroth16,
	}
}

// ZeroHash returns a zero hash (all zeros).
func ZeroHash() Blake2sHash {
	var h Blake2sHash
	for i := 0; i < 8; i++ {
		h.Words[i] = frontend.Variable(0)
	}
	return h
}

// NewHashFromConstants creates a Blake2sHash from uint32 constants.
func NewHashFromConstants(values [8]uint32) Blake2sHash {
	var h Blake2sHash
	for i := 0; i < 8; i++ {
		h.Words[i] = frontend.Variable(values[i])
	}
	return h
}

// Compress performs the Blake2s compression function.
// state: current hash state (8 x 32-bit words)
// msg: message block (16 x 32-bit words)
// t: byte counter (64-bit, split into low/high 32-bit words)
// final: whether this is the final block
func (c *Blake2sChip) Compress(
	state [8]frontend.Variable,
	msg [16]frontend.Variable,
	tLow, tHigh frontend.Variable,
	final bool,
) [8]frontend.Variable {
	// Initialize working vector v
	var v [16]frontend.Variable

	// v[0..7] = state[0..7]
	for i := 0; i < 8; i++ {
		v[i] = state[i]
	}

	// v[8..15] = IV[0..7]
	for i := 0; i < 8; i++ {
		v[8+i] = frontend.Variable(IV[i])
	}

	// v[12] ^= tLow
	v[12] = c.xor32(v[12], tLow)

	// v[13] ^= tHigh
	v[13] = c.xor32(v[13], tHigh)

	// v[14] ^= 0xFFFFFFFF if final
	if final {
		v[14] = c.xor32(v[14], frontend.Variable(0xFFFFFFFF))
	}

	// 10 rounds of mixing
	for round := 0; round < NumRounds; round++ {
		sigma := SIGMA[round]

		// Column mixing
		c.g(&v, 0, 4, 8, 12, msg[sigma[0]], msg[sigma[1]])
		c.g(&v, 1, 5, 9, 13, msg[sigma[2]], msg[sigma[3]])
		c.g(&v, 2, 6, 10, 14, msg[sigma[4]], msg[sigma[5]])
		c.g(&v, 3, 7, 11, 15, msg[sigma[6]], msg[sigma[7]])

		// Diagonal mixing
		c.g(&v, 0, 5, 10, 15, msg[sigma[8]], msg[sigma[9]])
		c.g(&v, 1, 6, 11, 12, msg[sigma[10]], msg[sigma[11]])
		c.g(&v, 2, 7, 8, 13, msg[sigma[12]], msg[sigma[13]])
		c.g(&v, 3, 4, 9, 14, msg[sigma[14]], msg[sigma[15]])
	}

	// Finalize: state[i] ^= v[i] ^ v[i+8]
	var newState [8]frontend.Variable
	for i := 0; i < 8; i++ {
		tmp := c.xor32(v[i], v[i+8])
		newState[i] = c.xor32(state[i], tmp)
	}

	return newState
}

// g is the Blake2s mixing function (quarter round).
// It modifies v[a], v[b], v[c], v[d] in place.
func (c *Blake2sChip) g(v *[16]frontend.Variable, a, b, cd, d int, x, y frontend.Variable) {
	// v[a] = v[a] + v[b] + x
	v[a] = c.add32(v[a], c.add32(v[b], x))

	// v[d] = ROTR(v[d] ^ v[a], 16)
	v[d] = c.rotr32(c.xor32(v[d], v[a]), R1)

	// v[c] = v[c] + v[d]
	v[cd] = c.add32(v[cd], v[d])

	// v[b] = ROTR(v[b] ^ v[c], 12)
	v[b] = c.rotr32(c.xor32(v[b], v[cd]), R2)

	// v[a] = v[a] + v[b] + y
	v[a] = c.add32(v[a], c.add32(v[b], y))

	// v[d] = ROTR(v[d] ^ v[a], 8)
	v[d] = c.rotr32(c.xor32(v[d], v[a]), R3)

	// v[c] = v[c] + v[d]
	v[cd] = c.add32(v[cd], v[d])

	// v[b] = ROTR(v[b] ^ v[c], 7)
	v[b] = c.rotr32(c.xor32(v[b], v[cd]), R4)
}

// add32 computes (a + b) mod 2^32.
func (c *Blake2sChip) add32(a, b frontend.Variable) frontend.Variable {
	sum := c.api.Add(a, b)
	// Reduce mod 2^32 using bit decomposition
	bits := c.api.ToBinary(sum, 33)
	// Reconstruct from low 32 bits
	return c.api.FromBinary(bits[:32]...)
}

// xor32 computes a XOR b for 32-bit values.
// XOR is expensive in R1CS - requires full bit decomposition.
func (c *Blake2sChip) xor32(a, b frontend.Variable) frontend.Variable {
	aBits := c.api.ToBinary(a, 32)
	bBits := c.api.ToBinary(b, 32)

	resultBits := make([]frontend.Variable, 32)
	for i := 0; i < 32; i++ {
		// XOR: a^b = a + b - 2*a*b
		resultBits[i] = c.api.Sub(
			c.api.Add(aBits[i], bBits[i]),
			c.api.Mul(c.api.Mul(aBits[i], bBits[i]), 2),
		)
	}

	return c.api.FromBinary(resultBits...)
}

// rotr32 computes right rotation of a 32-bit value by n bits.
func (c *Blake2sChip) rotr32(x frontend.Variable, n int) frontend.Variable {
	bits := c.api.ToBinary(x, 32)

	// Rotate bits to the right
	rotatedBits := make([]frontend.Variable, 32)
	for i := 0; i < 32; i++ {
		rotatedBits[i] = bits[(i+n)%32]
	}

	return c.api.FromBinary(rotatedBits...)
}

// Hash computes the Blake2s hash of an arbitrary-length message.
// The message is padded with zeros to a multiple of 64 bytes.
func (c *Blake2sChip) Hash(msg []frontend.Variable) Blake2sHash {
	// Initialize state with IV
	var state [8]frontend.Variable
	for i := 0; i < 8; i++ {
		state[i] = frontend.Variable(IV[i])
	}

	msgLen := len(msg)
	numBlocks := (msgLen + BlockWords - 1) / BlockWords
	if numBlocks == 0 {
		numBlocks = 1
	}

	bytesProcessed := uint64(0)

	for blockIdx := 0; blockIdx < numBlocks; blockIdx++ {
		// Prepare message block
		var block [16]frontend.Variable
		for i := 0; i < 16; i++ {
			wordIdx := blockIdx*16 + i
			if wordIdx < msgLen {
				block[i] = msg[wordIdx]
			} else {
				block[i] = frontend.Variable(0)
			}
		}

		// Update byte counter
		bytesInBlock := 64
		if blockIdx == numBlocks-1 {
			// Last block: count only actual bytes
			remainingWords := msgLen - blockIdx*16
			if remainingWords > 0 {
				bytesInBlock = remainingWords * 4
			}
		}
		bytesProcessed += uint64(bytesInBlock)

		tLow := frontend.Variable(bytesProcessed & 0xFFFFFFFF)
		tHigh := frontend.Variable(bytesProcessed >> 32)

		isFinal := blockIdx == numBlocks-1

		state = c.Compress(state, block, tLow, tHigh, isFinal)
	}

	var result Blake2sHash
	copy(result.Words[:], state[:])
	return result
}

// CompressWithState performs compression with a custom initial state.
// Used for Merkle tree hashing with domain separation.
func (c *Blake2sChip) CompressWithState(
	initialState [8]frontend.Variable,
	msg [16]frontend.Variable,
	byteCount uint64,
	final bool,
) [8]frontend.Variable {
	tLow := frontend.Variable(byteCount & 0xFFFFFFFF)
	tHigh := frontend.Variable(byteCount >> 32)
	return c.Compress(initialState, msg, tLow, tHigh, final)
}

// HashLeaf hashes a leaf node in the Merkle tree using domain-separated state.
func (c *Blake2sChip) HashLeaf(data []frontend.Variable) Blake2sHash {
	var state [8]frontend.Variable
	for i := 0; i < 8; i++ {
		state[i] = frontend.Variable(LeafInitialState[i])
	}

	// Pad data to 16 words
	var block [16]frontend.Variable
	for i := 0; i < 16; i++ {
		if i < len(data) {
			block[i] = data[i]
		} else {
			block[i] = frontend.Variable(0)
		}
	}

	// byteCount = 64 (prefix bytes already processed in LeafInitialState) + actual data bytes
	byteCount := uint64(64 + len(data)*4)
	state = c.CompressWithState(state, block, byteCount, true)

	var result Blake2sHash
	copy(result.Words[:], state[:])
	return result
}

// HashNode hashes an internal node in the Merkle tree.
// Combines two child hashes into a parent hash.
func (c *Blake2sChip) HashNode(left, right Blake2sHash) Blake2sHash {
	var state [8]frontend.Variable
	for i := 0; i < 8; i++ {
		state[i] = frontend.Variable(NodeInitialState[i])
	}

	// Combine left and right hashes into message block
	var block [16]frontend.Variable
	for i := 0; i < 8; i++ {
		block[i] = left.Words[i]
		block[8+i] = right.Words[i]
	}

	// byteCount = 64 (prefix bytes already processed in NodeInitialState) + 64 (child hashes)
	byteCount := uint64(128)
	state = c.CompressWithState(state, block, byteCount, true)

	var result Blake2sHash
	copy(result.Words[:], state[:])
	return result
}

// AssertEqual asserts that two Blake2s hashes are equal.
func (c *Blake2sChip) AssertEqual(a, b Blake2sHash) {
	for i := 0; i < 8; i++ {
		c.api.AssertIsEqual(a.Words[i], b.Words[i])
	}
}

// Select returns a if cond is true, else b.
func (c *Blake2sChip) Select(cond frontend.Variable, a, b Blake2sHash) Blake2sHash {
	var result Blake2sHash
	for i := 0; i < 8; i++ {
		result.Words[i] = c.api.Select(cond, a.Words[i], b.Words[i])
	}
	return result
}

// GetInitialState returns the Blake2s256 initial state for Fiat-Shamir operations.
func (c *Blake2sChip) GetInitialState() [8]frontend.Variable {
	var state [8]frontend.Variable
	for i := 0; i < 8; i++ {
		state[i] = frontend.Variable(Blake2s256InitialState[i])
	}
	return state
}

// Blake2sFinalize performs Blake2s finalization with Blake2s256InitialState.
// This is used by the Fiat-Shamir channel for mixing and drawing random values.
func (c *Blake2sChip) Blake2sFinalize(msg [16]frontend.Variable, byteCount int) [8]frontend.Variable {
	var state [8]frontend.Variable
	for i := 0; i < 8; i++ {
		state[i] = frontend.Variable(Blake2s256InitialState[i])
	}

	tLow := frontend.Variable(byteCount)
	tHigh := frontend.Variable(0)

	return c.Compress(state, msg, tLow, tHigh, true)
}

// ========================================
// Native (non-circuit) implementations for testing
// ========================================

// compressNative performs Blake2s compression on native uint32 values.
func compressNative(state [8]uint32, msg [16]uint32, tLow, tHigh uint32, isLastBlock bool) [8]uint32 {
	// Initialize working vector
	var v [16]uint32
	for i := 0; i < 8; i++ {
		v[i] = state[i]
	}
	for i := 0; i < 8; i++ {
		v[8+i] = Blake2s256InitialState[i]
	}

	// Mix in counters
	v[12] ^= tLow
	v[13] ^= tHigh

	// Finalization flag
	if isLastBlock {
		v[14] ^= 0xFFFFFFFF
	}

	// 10 rounds
	for round := 0; round < 10; round++ {
		sigma := SIGMA[round]

		// Column step
		v[0], v[4], v[8], v[12] = gNative(v[0], v[4], v[8], v[12], msg[sigma[0]], msg[sigma[1]])
		v[1], v[5], v[9], v[13] = gNative(v[1], v[5], v[9], v[13], msg[sigma[2]], msg[sigma[3]])
		v[2], v[6], v[10], v[14] = gNative(v[2], v[6], v[10], v[14], msg[sigma[4]], msg[sigma[5]])
		v[3], v[7], v[11], v[15] = gNative(v[3], v[7], v[11], v[15], msg[sigma[6]], msg[sigma[7]])

		// Diagonal step
		v[0], v[5], v[10], v[15] = gNative(v[0], v[5], v[10], v[15], msg[sigma[8]], msg[sigma[9]])
		v[1], v[6], v[11], v[12] = gNative(v[1], v[6], v[11], v[12], msg[sigma[10]], msg[sigma[11]])
		v[2], v[7], v[8], v[13] = gNative(v[2], v[7], v[8], v[13], msg[sigma[12]], msg[sigma[13]])
		v[3], v[4], v[9], v[14] = gNative(v[3], v[4], v[9], v[14], msg[sigma[14]], msg[sigma[15]])
	}

	// Finalize
	var result [8]uint32
	for i := 0; i < 8; i++ {
		result[i] = state[i] ^ v[i] ^ v[8+i]
	}
	return result
}

// gNative is the Blake2s G mixing function.
func gNative(a, b, c, d, x, y uint32) (uint32, uint32, uint32, uint32) {
	a = a + b + x
	d = rotr32(d^a, 16)
	c = c + d
	b = rotr32(b^c, 12)
	a = a + b + y
	d = rotr32(d^a, 8)
	c = c + d
	b = rotr32(b^c, 7)
	return a, b, c, d
}

func rotr32(x uint32, n int) uint32 {
	return (x >> n) | (x << (32 - n))
}

// LEAF_PREFIX is "leaf" followed by 60 zeros (64 bytes total)
var leafPrefix = func() []byte {
	p := make([]byte, 64)
	copy(p, []byte("leaf"))
	return p
}()

// NODE_PREFIX is "node" followed by 60 zeros (64 bytes total)
var nodePrefix = func() []byte {
	p := make([]byte, 64)
	copy(p, []byte("node"))
	return p
}()

// HashLeafNative computes a leaf hash using the standard Blake2s library.
func HashLeafNative(data []uint32) [8]uint32 {
	h, _ := blake2s.New256(nil)
	h.Write(leafPrefix)
	for _, v := range data {
		var buf [4]byte
		binary.LittleEndian.PutUint32(buf[:], v)
		h.Write(buf[:])
	}
	hash := h.Sum(nil)

	var result [8]uint32
	for i := 0; i < 8; i++ {
		result[i] = binary.LittleEndian.Uint32(hash[i*4 : i*4+4])
	}
	return result
}

// HashNodeNative computes a node hash using the standard Blake2s library.
func HashNodeNative(left, right [8]uint32) [8]uint32 {
	h, _ := blake2s.New256(nil)
	h.Write(nodePrefix)

	// Write left child hash
	for i := 0; i < 8; i++ {
		var buf [4]byte
		binary.LittleEndian.PutUint32(buf[:], left[i])
		h.Write(buf[:])
	}

	// Write right child hash
	for i := 0; i < 8; i++ {
		var buf [4]byte
		binary.LittleEndian.PutUint32(buf[:], right[i])
		h.Write(buf[:])
	}

	hash := h.Sum(nil)

	var result [8]uint32
	for i := 0; i < 8; i++ {
		result[i] = binary.LittleEndian.Uint32(hash[i*4 : i*4+4])
	}
	return result
}
