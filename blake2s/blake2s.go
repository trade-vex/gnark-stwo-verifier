// Package blake2s implements the Blake2s hash function in gnark circuits.
package blake2s

import (
	"github.com/consensys/gnark/frontend"
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

// HashLeaf hashes a leaf node in the Merkle tree (column values only, no children).
// Uses LeafInitialState which is the state after compressing the 64-byte LEAF_PREFIX.
// This matches stwo's hash_node(None, column_values) = Blake2s(LEAF_PREFIX || values).
func (c *Blake2sChip) HashLeaf(data []frontend.Variable) Blake2sHash {
	var state [8]frontend.Variable
	for i := 0; i < 8; i++ {
		// LeafInitialState = result of Compress(IV, LEAF_PREFIX, 64, false)
		// where LEAF_PREFIX = "leaf" + 60 zero bytes
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

	// byteCount = 64 (prefix) + actual data bytes (4 bytes per M31 value)
	byteCount := uint64(64 + len(data)*4)
	state = c.CompressWithState(state, block, byteCount, true)

	var result Blake2sHash
	copy(result.Words[:], state[:])
	return result
}

// HashNode hashes an internal node in the Merkle tree.
// Combines two child hashes into a parent hash (no column values at internal layers).
// Uses NodeInitialState which is the state after compressing the 64-byte NODE_PREFIX.
// This matches stwo's hash_node(Some(left, right), []) = Blake2s(NODE_PREFIX || left || right).
func (c *Blake2sChip) HashNode(left, right Blake2sHash) Blake2sHash {
	var state [8]frontend.Variable
	for i := 0; i < 8; i++ {
		// NodeInitialState = result of Compress(IV, NODE_PREFIX, 64, false)
		// where NODE_PREFIX = "node" + 60 zero bytes
		state[i] = frontend.Variable(NodeInitialState[i])
	}

	// Combine left and right hashes into message block
	var block [16]frontend.Variable
	for i := 0; i < 8; i++ {
		block[i] = left.Words[i]
		block[8+i] = right.Words[i]
	}

	// byteCount = 64 (prefix) + 64 (left + right hashes) = 128
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

