// Package fri implements FRI (Fast Reed-Solomon Interactive Oracle Proof) verification.
// This package implements circle-to-line folding specific to Circle STARKs.
package fri

import (
	"github.com/gnark-stwo/stwo/mersenne31"
)

// FriFold performs the FRI folding operation for circle polynomials.
// Given two evaluations f(P) and f(-P) at conjugate points,
// and a folding challenge alpha, computes the folded evaluation.
//
// The formula is:
// f_folded = (f(P) + f(-P)) + alpha * (f(P) - f(-P)) / y
//
// where y is the y-coordinate of P (the inverse twiddle factor).
func FriFold(
	m31Chip *mersenne31.M31Chip,
	v0, v1 mersenne31.QM31Variable, // f(P) and f(-P)
	itwid mersenne31.M31Variable, // Inverse twiddle factor (1/y)
	alpha mersenne31.QM31Variable, // Folding challenge
) mersenne31.QM31Variable {
	// f0 = f(P) + f(-P)  (even part)
	f0 := m31Chip.AddQM31(v0, v1)

	// f1 = (f(P) - f(-P)) * itwid  (odd part divided by y)
	diff := m31Chip.SubQM31(v0, v1)
	f1 := m31Chip.MulQM31ByM31(diff, itwid)

	// result = f0 + alpha * f1
	alphaF1 := m31Chip.MulQM31(alpha, f1)
	return m31Chip.AddQM31(f0, alphaF1)
}

// FriFoldLine performs the FRI folding operation for line polynomials.
// This is used after the initial circle-to-line fold.
//
// Given two evaluations f(x) and f(-x) at symmetric points,
// and a folding challenge alpha, computes the folded evaluation.
//
// The formula matches stwo's ibutterfly:
// f_folded = (f(x) + f(-x)) + alpha * (f(x) - f(-x)) * inv(x)
//
// Note: Unlike some FRI variants, stwo does NOT divide by 2 in ibutterfly.
func FriFoldLine(
	m31Chip *mersenne31.M31Chip,
	v0, v1 mersenne31.QM31Variable, // f(x) and f(-x)
	x mersenne31.M31Variable, // The x-coordinate
	alpha mersenne31.QM31Variable, // Folding challenge
) mersenne31.QM31Variable {
	// f0 = f(x) + f(-x) (NOT divided by 2 - matches stwo ibutterfly)
	f0 := m31Chip.AddQM31(v0, v1)

	// diff = f(x) - f(-x)
	diff := m31Chip.SubQM31(v0, v1)

	// Compute 1/x (NOT 1/(2x) - matches stwo ibutterfly)
	xInv := m31Chip.InvM31(x)

	// f1 = diff * inv(x)
	f1 := m31Chip.MulQM31ByM31(diff, xInv)

	// result = f0 + alpha * f1
	alphaF1 := m31Chip.MulQM31(alpha, f1)
	return m31Chip.AddQM31(f0, alphaF1)
}

// IButterfly performs the inverse butterfly operation.
// Matches stwo's ibutterfly from fft.rs:
// v0 = tmp + v1
// v1 = (tmp - v1) * itwid
// Note: stwo's ibutterfly does NOT divide by 2.
func IButterfly(
	m31Chip *mersenne31.M31Chip,
	v0, v1 mersenne31.QM31Variable,
	itwid mersenne31.M31Variable,
) (mersenne31.QM31Variable, mersenne31.QM31Variable) {
	// tmp = v0
	// v0_new = tmp + v1 = v0 + v1
	sum := m31Chip.AddQM31(v0, v1)

	// v1_new = (tmp - v1) * itwid = (v0 - v1) * itwid
	diff := m31Chip.SubQM31(v0, v1)
	diffScaled := m31Chip.MulQM31ByM31(diff, itwid)

	return sum, diffScaled
}

// SparseCircleEvaluation represents evaluations at a sparse set of circle points.
type SparseCircleEvaluation struct {
	// Evaluations at query positions
	Values []mersenne31.QM31Variable
	// Query positions (indices into the domain)
	Positions []int
	// Log size of the domain
	LogDomainSize int
}

// FoldCircle folds a sparse circle evaluation to a sparse line evaluation.
// This is the first folding step in Circle FRI.
func (s *SparseCircleEvaluation) FoldCircle(
	m31Chip *mersenne31.M31Chip,
	alpha mersenne31.QM31Variable,
	twiddles []mersenne31.M31Variable,
) *SparseLineEvaluation {
	numPairs := len(s.Values) / 2
	foldedValues := make([]mersenne31.QM31Variable, numPairs)
	foldedPositions := make([]int, numPairs)

	for i := 0; i < numPairs; i++ {
		// Pair (v0, v1) at positions (pos, pos + domain_size/2)
		v0 := s.Values[2*i]
		v1 := s.Values[2*i+1]

		// Get the twiddle factor (inverse of y-coordinate)
		itwid := twiddles[i]

		// Fold
		foldedValues[i] = FriFold(m31Chip, v0, v1, itwid, alpha)
		foldedPositions[i] = s.Positions[2*i] // Position in the folded domain
	}

	return &SparseLineEvaluation{
		Values:        foldedValues,
		Positions:     foldedPositions,
		LogDomainSize: s.LogDomainSize - 1,
	}
}

// SparseLineEvaluation represents evaluations at a sparse set of line points.
type SparseLineEvaluation struct {
	Values        []mersenne31.QM31Variable
	Positions     []int
	LogDomainSize int
}

// FoldLine folds a sparse line evaluation to another sparse line evaluation.
func (s *SparseLineEvaluation) FoldLine(
	m31Chip *mersenne31.M31Chip,
	alpha mersenne31.QM31Variable,
	xCoordinates []mersenne31.M31Variable,
) *SparseLineEvaluation {
	numPairs := len(s.Values) / 2
	foldedValues := make([]mersenne31.QM31Variable, numPairs)
	foldedPositions := make([]int, numPairs)

	for i := 0; i < numPairs; i++ {
		v0 := s.Values[2*i]
		v1 := s.Values[2*i+1]
		x := xCoordinates[i]

		foldedValues[i] = FriFoldLine(m31Chip, v0, v1, x, alpha)
		foldedPositions[i] = s.Positions[2*i]
	}

	return &SparseLineEvaluation{
		Values:        foldedValues,
		Positions:     foldedPositions,
		LogDomainSize: s.LogDomainSize - 1,
	}
}

// ComputeTwiddleFactors computes the inverse twiddle factors for circle folding.
// For each query position, this computes 1/y where (x,y) is the circle point.
func ComputeTwiddleFactors(
	m31Chip *mersenne31.M31Chip,
	yCoordinates []mersenne31.M31Variable,
) []mersenne31.M31Variable {
	result := make([]mersenne31.M31Variable, len(yCoordinates))
	for i, y := range yCoordinates {
		result[i] = m31Chip.InvM31(y)
	}
	return result
}
