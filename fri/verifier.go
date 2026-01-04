// Package fri implements FRI verification for Circle STARKs.
package fri

import (
	"github.com/gnark-stwo/stwo/blake2s"
	"github.com/gnark-stwo/stwo/merkle"
	"github.com/gnark-stwo/stwo/mersenne31"
)

// FriLayerProof contains the proof for a single FRI layer.
type FriLayerProof struct {
	// Commitment to the layer polynomial evaluations
	Commitment blake2s.Blake2sHash
	// Values at query positions (evaluations opened at queries)
	EvalValues []mersenne31.QM31Variable
	// Merkle decommitment for the opened values
	Decommitment merkle.MerkleDecommitment
}

// FriProof contains the complete FRI proof.
type FriProof struct {
	// First layer (circle to line folding)
	FirstLayer FriLayerProof
	// Inner layers (line folding)
	InnerLayers []FriLayerProof
	// Last layer polynomial coefficients
	LastLayerPoly []mersenne31.QM31Variable
}
