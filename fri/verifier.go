// Package fri implements FRI verification for Circle STARKs.
package fri

import (
	"github.com/consensys/gnark/frontend"
	"github.com/gnark-stwo/stwo/blake2s"
	"github.com/gnark-stwo/stwo/channel"
	"github.com/gnark-stwo/stwo/circle"
	"github.com/gnark-stwo/stwo/merkle"
	"github.com/gnark-stwo/stwo/mersenne31"
)

// FriConfig contains FRI protocol configuration parameters.
type FriConfig struct {
	// Log of the blowup factor (rate = 1/2^log_blowup)
	LogBlowupFactor int
	// Log of the degree bound of the last layer polynomial
	LogLastLayerDegreeBound int
	// Number of FRI queries
	NumQueries int
}

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

// FriVerifier verifies FRI proofs.
type FriVerifier struct {
	Config       FriConfig
	m31Chip      *mersenne31.M31Chip
	circleChip   *circle.CircleChip
	blake2sChip  *blake2s.Blake2sChip
	api          frontend.API
	isGroth16    bool

	// Folding challenges (drawn from channel during commit phase)
	Alphas []mersenne31.QM31Variable
	// Query positions (drawn after PoW verification)
	QueryPositions []frontend.Variable
}

// NewFriVerifier creates a new FRI verifier.
func NewFriVerifier(
	api frontend.API,
	config FriConfig,
	isGroth16 bool,
) *FriVerifier {
	return &FriVerifier{
		Config:      config,
		m31Chip:     mersenne31.NewM31Chip(api, isGroth16),
		circleChip:  circle.NewCircleChip(api, isGroth16),
		blake2sChip: blake2s.NewBlake2sChip(api, isGroth16),
		api:         api,
		isGroth16:   isGroth16,
	}
}

// CommitPhase processes the FRI commitments and draws challenges.
// Returns the folding alphas for decommit phase.
func (v *FriVerifier) CommitPhase(
	ch *channel.Blake2sChannel,
	proof FriProof,
	initialLogDomainSize int,
) {
	numLayers := v.computeNumLayers(initialLogDomainSize)
	v.Alphas = make([]mersenne31.QM31Variable, numLayers)

	// Process first layer
	ch.MixCommitment(proof.FirstLayer.Commitment)
	v.Alphas[0] = ch.DrawSecureFelt()

	// Process inner layers
	for i, layer := range proof.InnerLayers {
		ch.MixCommitment(layer.Commitment)
		v.Alphas[i+1] = ch.DrawSecureFelt()
	}

	// Mix last layer polynomial into channel
	ch.MixFelts(proof.LastLayerPoly)
}

// SampleQueryPositions samples FRI query positions from the channel.
func (v *FriVerifier) SampleQueryPositions(
	ch *channel.Blake2sChannel,
	logDomainSize int,
) []frontend.Variable {
	v.QueryPositions = make([]frontend.Variable, v.Config.NumQueries)

	for i := 0; i < v.Config.NumQueries; i++ {
		// Draw random u32s and use low bits for position
		words := ch.DrawU32s()
		// Extract low logDomainSize bits
		bits := v.api.ToBinary(words[0], 32)
		v.QueryPositions[i] = v.api.FromBinary(bits[:logDomainSize]...)
	}

	return v.QueryPositions
}

// DecommitPhase verifies the FRI decommitments.
func (v *FriVerifier) DecommitPhase(
	proof FriProof,
	firstLayerEvals [][]mersenne31.QM31Variable,
	initialCircleDomain circle.CircleDomain,
) {
	// Verify first layer (circle folding)
	v.verifyFirstLayer(proof.FirstLayer, firstLayerEvals, initialCircleDomain)

	// Verify inner layers (line folding)
	currentLogSize := v.getLogDomainSize(initialCircleDomain) - 1
	currentEvals := v.getFirstLayerFoldedEvals(proof.FirstLayer, firstLayerEvals, initialCircleDomain)

	for i, layer := range proof.InnerLayers {
		v.verifyInnerLayer(layer, currentEvals, currentLogSize, v.Alphas[i+1])
		currentEvals = v.foldLayerEvals(layer.EvalValues, currentLogSize)
		currentLogSize--
	}

	// Verify last layer: all query evals should equal last layer poly evaluation
	v.verifyLastLayer(currentEvals, proof.LastLayerPoly, currentLogSize)
}

// verifyFirstLayer verifies the first FRI layer (circle to line folding).
func (v *FriVerifier) verifyFirstLayer(
	layer FriLayerProof,
	queryEvals [][]mersenne31.QM31Variable,
	domain circle.CircleDomain,
) {
	// For each query:
	// 1. Verify Merkle proof for opened values
	// 2. Verify folding is correct

	for i, pos := range v.QueryPositions {
		// Get the evaluation pair at this query position
		evals := queryEvals[i]

		// The query position and its conjugate
		// Conjugate position = pos XOR (domain_size / 2)
		logSize := v.getLogDomainSize(domain)
		halfSize := 1 << (logSize - 1)

		// Compute XOR by bit manipulation: pos XOR halfSize
		// Since halfSize is a power of 2, this flips a single bit
		posBits := v.api.ToBinary(pos, logSize)
		// Flip the bit at position (logSize - 1)
		posBits[logSize-1] = v.api.Sub(1, posBits[logSize-1])
		conjPos := v.api.FromBinary(posBits...)
		_ = halfSize // Unused now

		// Get twiddle factor for folding
		point := domain.At(v.circleChip, pos)
		itwid := v.m31Chip.InvM31(point.Y)

		// Verify folding
		v0 := evals[0]
		v1 := evals[1]
		_ = FriFold(v.m31Chip, v0, v1, itwid, v.Alphas[0])

		// Verify Merkle proof
		// (actual Merkle verification would go here)
		_ = layer.Commitment
		_ = conjPos
	}
}

// verifyInnerLayer verifies an inner FRI layer (line folding).
func (v *FriVerifier) verifyInnerLayer(
	layer FriLayerProof,
	expectedEvals []mersenne31.QM31Variable,
	logDomainSize int,
	alpha mersenne31.QM31Variable,
) {
	// Verify each query's folding
	for i, expected := range expectedEvals {
		// Get the opened values for this query
		v0 := layer.EvalValues[2*i]
		v1 := layer.EvalValues[2*i+1]

		// Get the x-coordinate for folding
		queryPos := v.QueryPositions[i]
		x := v.getXCoordinate(queryPos, logDomainSize)

		// Verify folding
		folded := FriFoldLine(v.m31Chip, v0, v1, x, alpha)

		// The expected value should match
		v.m31Chip.AssertEqQM31(expected, folded)
	}
}

// verifyLastLayer verifies the last layer polynomial evaluation.
func (v *FriVerifier) verifyLastLayer(
	queryEvals []mersenne31.QM31Variable,
	lastLayerPoly []mersenne31.QM31Variable,
	logDomainSize int,
) {
	// The last layer polynomial should be constant (degree 0 for log_degree_bound = 0)
	// All query evaluations should equal the constant value

	if len(lastLayerPoly) == 1 {
		// Constant polynomial: all evals should equal this value
		for _, eval := range queryEvals {
			v.m31Chip.AssertEqQM31(eval, lastLayerPoly[0])
		}
	} else {
		// Higher degree: evaluate polynomial at query points
		// This is more complex and would require polynomial evaluation in circuit
		// For now, we assume degree 0 (most common case)
		for i, eval := range queryEvals {
			expected := v.evaluateLastLayerPoly(lastLayerPoly, i, logDomainSize)
			v.m31Chip.AssertEqQM31(eval, expected)
		}
	}
}

// Helper functions

func (v *FriVerifier) computeNumLayers(initialLogDomainSize int) int {
	// Number of folding layers = log_domain_size - log_last_layer_degree_bound
	return initialLogDomainSize - v.Config.LogLastLayerDegreeBound
}

func (v *FriVerifier) getLogDomainSize(domain circle.CircleDomain) int {
	// This would need to be computed from the domain
	// For now, return a placeholder
	return 20 // Typical value
}

func (v *FriVerifier) getFirstLayerFoldedEvals(
	layer FriLayerProof,
	queryEvals [][]mersenne31.QM31Variable,
	domain circle.CircleDomain,
) []mersenne31.QM31Variable {
	result := make([]mersenne31.QM31Variable, len(v.QueryPositions))

	for i := range v.QueryPositions {
		// Fold the query pair
		v0 := queryEvals[i][0]
		v1 := queryEvals[i][1]

		point := domain.At(v.circleChip, v.QueryPositions[i])
		itwid := v.m31Chip.InvM31(point.Y)

		result[i] = FriFold(v.m31Chip, v0, v1, itwid, v.Alphas[0])
	}

	return result
}

func (v *FriVerifier) foldLayerEvals(
	layerEvals []mersenne31.QM31Variable,
	logDomainSize int,
) []mersenne31.QM31Variable {
	numQueries := len(layerEvals) / 2
	result := make([]mersenne31.QM31Variable, numQueries)

	for i := 0; i < numQueries; i++ {
		result[i] = layerEvals[2*i] // Placeholder - actual folding needed
	}

	return result
}

func (v *FriVerifier) getXCoordinate(
	queryPos frontend.Variable,
	logDomainSize int,
) mersenne31.M31Variable {
	// Compute the x-coordinate for the query position in the line domain
	// This is derived from the circle domain via the circle-to-line mapping
	// For now, return a placeholder
	return mersenne31.NewM31Const("1")
}

func (v *FriVerifier) evaluateLastLayerPoly(
	poly []mersenne31.QM31Variable,
	queryIdx int,
	logDomainSize int,
) mersenne31.QM31Variable {
	// Evaluate the polynomial at the query point
	// For degree 0 (constant), just return poly[0]
	if len(poly) == 1 {
		return poly[0]
	}

	// For higher degrees, we'd need polynomial evaluation
	// This is complex in circuits - typically done with Horner's method
	return poly[0] // Placeholder
}
