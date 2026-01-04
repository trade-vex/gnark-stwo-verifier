// Package merkle implements Merkle tree verification for stwo proofs.
// Uses Blake2s for hashing with domain separation for leaf and internal nodes.
package merkle

import (
	"github.com/gnark-stwo/stwo/blake2s"
	"github.com/gnark-stwo/stwo/mersenne31"
)

// MerkleDecommitment contains the witness data for verifying Merkle queries.
type MerkleDecommitment struct {
	// HashWitness contains the sibling hashes needed for verification
	HashWitness []blake2s.Blake2sHash
	// ColumnWitness contains the column values at queried positions
	ColumnWitness []mersenne31.M31Variable
}
