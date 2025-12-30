// Package merkle implements Merkle tree verification for stwo proofs.
// Uses Blake2s for hashing with domain separation for leaf and internal nodes.
package merkle

import (
	"github.com/consensys/gnark/frontend"
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

// MerkleVerifier verifies Merkle tree openings.
type MerkleVerifier struct {
	Root           blake2s.Blake2sHash
	TreeHeight     int
	NumColumns     int
	blake2sChip    *blake2s.Blake2sChip
	m31Chip        *mersenne31.M31Chip
	api            frontend.API
}

// NewMerkleVerifier creates a new Merkle verifier.
func NewMerkleVerifier(
	api frontend.API,
	root blake2s.Blake2sHash,
	treeHeight int,
	numColumns int,
	isGroth16 bool,
) *MerkleVerifier {
	return &MerkleVerifier{
		Root:        root,
		TreeHeight:  treeHeight,
		NumColumns:  numColumns,
		blake2sChip: blake2s.NewBlake2sChip(api, isGroth16),
		m31Chip:     mersenne31.NewM31Chip(api, isGroth16),
		api:         api,
	}
}

// VerifyQuery verifies a single Merkle query.
// position: the leaf position being queried
// values: the column values at that position
// siblings: the sibling hashes from leaf to root
func (v *MerkleVerifier) VerifyQuery(
	position frontend.Variable,
	values []mersenne31.M31Variable,
	siblings []blake2s.Blake2sHash,
) {
	// Hash the leaf (column values)
	leafHash := v.hashLeaf(values)

	// Walk up the tree
	currentHash := leafHash
	positionBits := v.api.ToBinary(position, v.TreeHeight)

	for level := 0; level < v.TreeHeight; level++ {
		sibling := siblings[level]
		bit := positionBits[level]

		// If bit is 0, current is left child; if 1, current is right child
		left := v.blake2sChip.Select(bit, sibling, currentHash)
		right := v.blake2sChip.Select(bit, currentHash, sibling)

		// Hash the parent
		currentHash = v.blake2sChip.HashNode(left, right)
	}

	// Verify the computed root matches the expected root
	v.blake2sChip.AssertEqual(currentHash, v.Root)
}

// VerifyQueries verifies multiple Merkle queries efficiently.
// positions: the leaf positions being queried
// allValues: values[i] contains the column values for query i
// decommitment: the witness data (siblings)
func (v *MerkleVerifier) VerifyQueries(
	positions []frontend.Variable,
	allValues [][]mersenne31.M31Variable,
	decommitment MerkleDecommitment,
) {
	numQueries := len(positions)
	if numQueries == 0 {
		return
	}

	// Verify each query
	siblingsPerQuery := v.TreeHeight
	for i := 0; i < numQueries; i++ {
		startIdx := i * siblingsPerQuery
		endIdx := startIdx + siblingsPerQuery
		siblings := decommitment.HashWitness[startIdx:endIdx]
		v.VerifyQuery(positions[i], allValues[i], siblings)
	}
}

// hashLeaf hashes column values to create a leaf node.
func (v *MerkleVerifier) hashLeaf(values []mersenne31.M31Variable) blake2s.Blake2sHash {
	// Convert M31 values to 32-bit words
	words := make([]frontend.Variable, len(values))
	for i, val := range values {
		reduced := v.m31Chip.ReduceSlow(val)
		words[i] = reduced.Value
	}

	return v.blake2sChip.HashLeaf(words)
}

// MerkleTreeVerifier is a more comprehensive verifier that handles
// the stwo-specific tree structure with multiple column sizes.
type MerkleTreeVerifier struct {
	// Commitments for each tree (preprocessed, main, interaction)
	Commitments []blake2s.Blake2sHash
	// Column sizes for each tree (in log2)
	ColumnLogSizes [][]int
	// Log blowup factor for FRI
	LogBlowupFactor int

	blake2sChip *blake2s.Blake2sChip
	m31Chip     *mersenne31.M31Chip
	api         frontend.API
}

// NewMerkleTreeVerifier creates a comprehensive tree verifier.
func NewMerkleTreeVerifier(
	api frontend.API,
	commitments []blake2s.Blake2sHash,
	columnLogSizes [][]int,
	logBlowupFactor int,
	isGroth16 bool,
) *MerkleTreeVerifier {
	return &MerkleTreeVerifier{
		Commitments:     commitments,
		ColumnLogSizes:  columnLogSizes,
		LogBlowupFactor: logBlowupFactor,
		blake2sChip:     blake2s.NewBlake2sChip(api, isGroth16),
		m31Chip:         mersenne31.NewM31Chip(api, isGroth16),
		api:             api,
	}
}

// VerifyTreeQueries verifies queries against a specific tree.
func (v *MerkleTreeVerifier) VerifyTreeQueries(
	treeIdx int,
	queryPositions []frontend.Variable,
	queriedValues [][]mersenne31.M31Variable,
	decommitment MerkleDecommitment,
) {
	root := v.Commitments[treeIdx]
	columnSizes := v.ColumnLogSizes[treeIdx]

	// Determine tree height (max column size + blowup factor)
	maxLogSize := 0
	for _, size := range columnSizes {
		if size > maxLogSize {
			maxLogSize = size
		}
	}
	treeHeight := maxLogSize + v.LogBlowupFactor

	verifier := NewMerkleVerifier(
		v.api,
		root,
		treeHeight,
		len(columnSizes),
		true, // isGroth16
	)

	verifier.VerifyQueries(queryPositions, queriedValues, decommitment)
}

// QueryPosition represents a query position with its bit decomposition.
type QueryPosition struct {
	Position frontend.Variable
	Bits     []frontend.Variable
}

// NewQueryPosition creates a QueryPosition with precomputed bits.
func NewQueryPosition(api frontend.API, position frontend.Variable, numBits int) QueryPosition {
	return QueryPosition{
		Position: position,
		Bits:     api.ToBinary(position, numBits),
	}
}

// SiblingPosition returns the sibling's position (XOR with 1 at level).
func (q *QueryPosition) SiblingPosition(api frontend.API, level int) frontend.Variable {
	// Sibling differs in the bit at this level
	// If our bit is 0, sibling is position + 2^level
	// If our bit is 1, sibling is position - 2^level

	// sibling_pos = position XOR (1 << level)
	// In the circuit, we compute this using select:
	// If bit[level] == 0: sibling = position + (1 << level)
	// If bit[level] == 1: sibling = position - (1 << level)

	offset := frontend.Variable(1 << level)
	posPlus := api.Add(q.Position, offset)
	posMinus := api.Sub(q.Position, offset)

	return api.Select(q.Bits[level], posMinus, posPlus)
}

// ParentPosition returns the parent's position (position >> 1 at level).
func (q *QueryPosition) ParentPosition(api frontend.API) frontend.Variable {
	// Parent position is position / 2
	// We can compute this by dropping the LSB
	if len(q.Bits) < 2 {
		return frontend.Variable(0)
	}

	return api.FromBinary(q.Bits[1:]...)
}

// BatchMerkleVerifier verifies multiple queries that may share common ancestors.
type BatchMerkleVerifier struct {
	Root        blake2s.Blake2sHash
	TreeHeight  int
	blake2sChip *blake2s.Blake2sChip
	api         frontend.API
}

// NewBatchMerkleVerifier creates a batch verifier.
func NewBatchMerkleVerifier(
	api frontend.API,
	root blake2s.Blake2sHash,
	treeHeight int,
	isGroth16 bool,
) *BatchMerkleVerifier {
	return &BatchMerkleVerifier{
		Root:        root,
		TreeHeight:  treeHeight,
		blake2sChip: blake2s.NewBlake2sChip(api, isGroth16),
		api:         api,
	}
}

// VerifyBatch verifies a batch of queries with potential sharing.
// This is more efficient when queries share Merkle tree ancestors.
func (v *BatchMerkleVerifier) VerifyBatch(
	positions []QueryPosition,
	leafHashes []blake2s.Blake2sHash,
	witnessHashes [][]blake2s.Blake2sHash,
) {
	numQueries := len(positions)
	if numQueries == 0 {
		return
	}

	// For each query, verify independently for now
	// TODO: Implement sharing optimization
	for i := 0; i < numQueries; i++ {
		currentHash := leafHashes[i]

		for level := 0; level < v.TreeHeight; level++ {
			sibling := witnessHashes[i][level]
			bit := positions[i].Bits[level]

			left := v.blake2sChip.Select(bit, sibling, currentHash)
			right := v.blake2sChip.Select(bit, currentHash, sibling)

			currentHash = v.blake2sChip.HashNode(left, right)
		}

		v.blake2sChip.AssertEqual(currentHash, v.Root)
	}
}
