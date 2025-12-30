// Package stwo provides a gnark circuit for verifying stwo Circle STARK proofs.
//
// This is a direct implementation of the stwo verification algorithm.
package stwo

import (
	"github.com/consensys/gnark/frontend"
	"github.com/gnark-stwo/stwo/blake2s"
	"github.com/gnark-stwo/stwo/fri"
	"github.com/gnark-stwo/stwo/merkle"
	"github.com/gnark-stwo/stwo/mersenne31"
)

// PcsConfig contains the polynomial commitment scheme configuration.
type PcsConfig struct {
	PowBits         int
	LogBlowupFactor int
	LogLastLayerDeg int
	NumQueries      int
}

// =============================================================================
// Wrapper types to work around gnark schema bug with deeply nested slices.
// See: https://github.com/Consensys/gnark/blob/master/frontend/schema/schema.go#L154
// The bug: arrayElementType doesn't handle case Leaf when len(fields) > 0
// =============================================================================

// QM31Column wraps a slice of QM31 values (column evaluations at OOD point).
type QM31Column struct {
	Values []mersenne31.QM31Variable
}

// TreeSampledValues wraps columns for a single tree's sampled values.
type TreeSampledValues struct {
	Columns []QM31Column
}

// M31Column wraps a slice of M31 values (queried values for a tree).
type M31Column struct {
	Values []mersenne31.M31Variable
}

// =============================================================================

// StwoProof contains all data needed to verify a stwo proof.
type StwoProof struct {
	// Merkle commitments for each tree (preprocessed, trace, interaction)
	Commitments []blake2s.Blake2sHash

	// Sampled values at the OOD point - wrapped to avoid gnark schema bug
	SampledValues []TreeSampledValues

	// Merkle decommitments for query positions
	Decommitments []merkle.MerkleDecommitment

	// Values at query positions - wrapped to avoid gnark schema bug
	QueriedValues []M31Column

	// Proof of work nonce
	PowNonce frontend.Variable

	// FRI proof
	FriProof fri.FriProof
}
