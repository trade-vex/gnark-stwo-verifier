// Package blake2s implements the Blake2s hash function in gnark circuits.
// Blake2s is used in stwo for Merkle tree commitments and Fiat-Shamir channel.
package blake2s

// Blake2s Initialization Vector (IV)
var IV = [8]uint32{
	0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
	0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
}

// SIGMA is the message schedule permutation for Blake2s
// 10 rounds of 16 indices each
var SIGMA = [10][16]int{
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
	{11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
	{7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
	{9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
	{2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
	{12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
	{13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
	{6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
	{10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
}

// Blake2s parameters
const (
	// Number of rounds in Blake2s compression
	NumRounds = 10

	// Block size in bytes
	BlockSize = 64

	// Hash output size in bytes
	HashSize = 32

	// Number of 32-bit words in state
	StateSize = 8

	// Number of 32-bit words in block
	BlockWords = 16
)

// Rotation amounts for Blake2s G function
const (
	R1 = 16
	R2 = 12
	R3 = 8
	R4 = 7
)

// Stwo-specific initial states for Fiat-Shamir and Merkle tree hashing

// Blake2s256InitialState is the standard initial state used for Fiat-Shamir channel operations.
// Note: first byte differs from standard IV.
var Blake2s256InitialState = [8]uint32{
	0x6B08E647, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
	0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
}

// LeafInitialState is used for hashing leaf nodes in the Merkle tree.
var LeafInitialState = [8]uint32{
	0x6510b1f7, 0xfd531f42, 0xcff75ec3, 0x382935d0,
	0xab15dbf2, 0x950eb564, 0xe8e92866, 0x28047aca,
}

// NodeInitialState is used for hashing internal nodes in the Merkle tree.
var NodeInitialState = [8]uint32{
	0xe5cf8926, 0x841cea30, 0x7b4acada, 0xfc5d8d28,
	0xfc6ef857, 0xb29da528, 0xc0d319c7, 0x8ae795c8,
}
