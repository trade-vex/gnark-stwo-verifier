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
