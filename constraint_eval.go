// Package stwo provides constraint evaluation for AIR composition polynomial verification.
package stwo

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/gnark-stwo/stwo/mersenne31"
)

// ConstraintOp represents the type of operation in a constraint expression.
type ConstraintOp string

const (
	OpAdd   ConstraintOp = "add"   // Binary addition
	OpSub   ConstraintOp = "sub"   // Binary subtraction
	OpMul   ConstraintOp = "mul"   // Binary multiplication
	OpNeg   ConstraintOp = "neg"   // Unary negation
	OpConst ConstraintOp = "const" // Constant QM31 value
	OpCol   ConstraintOp = "col"   // Column reference (tree, col, row_offset)
)

// ConstraintExpr represents a node in a constraint expression tree.
// Constraints are polynomial expressions over trace column values that must evaluate to zero.
type ConstraintExpr struct {
	Op ConstraintOp `json:"op"`

	// For binary ops (add, sub, mul)
	Left  *ConstraintExpr `json:"left,omitempty"`
	Right *ConstraintExpr `json:"right,omitempty"`

	// For unary ops (neg)
	Child *ConstraintExpr `json:"child,omitempty"`

	// For const op - the constant value
	ConstVal [4]uint32 `json:"const_val,omitempty"` // QM31 as [a, b, c, d]

	// For col op - column reference
	TreeIdx int `json:"tree_idx,omitempty"` // Which tree (0=preprocessed, 1=trace, 2=interaction, 3=composition)
	ColIdx  int `json:"col_idx,omitempty"`  // Column index within tree
	RowOff  int `json:"row_off,omitempty"`  // Row offset (0=current, -1=previous, etc.)
}

// LogUpRelation represents a LogUp lookup relation.
// LogUp is used for lookup arguments in the AIR.
type LogUpRelation struct {
	// LookupElements are the random field elements for combining columns
	// drawn from Fiat-Shamir during verification
	LookupElements []mersenne31.QM31Variable `json:"lookup_elements"`

	// Columns involved in this relation
	Columns []ColRef `json:"columns"`

	// Multiplicity expression (typically 1, -1, or a column reference)
	Multiplicity *ConstraintExpr `json:"multiplicity"`
}

// ColRef is a simple column reference.
type ColRef struct {
	TreeIdx int `json:"tree_idx"`
	ColIdx  int `json:"col_idx"`
	RowOff  int `json:"row_off"`
}

// AIRConstraints contains all the constraint data needed for composition polynomial verification.
type AIRConstraints struct {
	// Polynomial constraints that must evaluate to zero
	Constraints []*ConstraintExpr `json:"constraints"`

	// LogUp relations for lookup arguments
	LogUpRelations []LogUpRelation `json:"logup_relations,omitempty"`

	// Claimed LogUp sum (should be zero for valid proofs)
	ClaimedLogUpSum [4]uint32 `json:"claimed_logup_sum,omitempty"`

	// Composition log degree bound
	CompositionLogDegreeBound uint32 `json:"composition_log_degree_bound"`
}

// ConstraintEvaluator evaluates constraint expressions in-circuit.
type ConstraintEvaluator struct {
	api     frontend.API
	m31Chip *mersenne31.M31Chip
}

// NewConstraintEvaluator creates a new constraint evaluator.
func NewConstraintEvaluator(api frontend.API, m31Chip *mersenne31.M31Chip) *ConstraintEvaluator {
	return &ConstraintEvaluator{
		api:     api,
		m31Chip: m31Chip,
	}
}

// EvaluateExpr evaluates a constraint expression tree using sampled values at the OOD point.
// sampledValues[tree][col][offset] contains the QM31 value at that position.
func (e *ConstraintEvaluator) EvaluateExpr(
	expr *ConstraintExpr,
	sampledValues [][][]mersenne31.QM31Variable,
) mersenne31.QM31Variable {
	switch expr.Op {
	case OpAdd:
		left := e.EvaluateExpr(expr.Left, sampledValues)
		right := e.EvaluateExpr(expr.Right, sampledValues)
		return e.m31Chip.AddQM31(left, right)

	case OpSub:
		left := e.EvaluateExpr(expr.Left, sampledValues)
		right := e.EvaluateExpr(expr.Right, sampledValues)
		return e.m31Chip.SubQM31(left, right)

	case OpMul:
		left := e.EvaluateExpr(expr.Left, sampledValues)
		right := e.EvaluateExpr(expr.Right, sampledValues)
		return e.m31Chip.MulQM31(left, right)

	case OpNeg:
		child := e.EvaluateExpr(expr.Child, sampledValues)
		return e.m31Chip.NegQM31(child)

	case OpConst:
		return mersenne31.QM31Variable{
			Value: [4]mersenne31.M31Variable{
				mersenne31.NewM31Const(uintToStr(expr.ConstVal[0])),
				mersenne31.NewM31Const(uintToStr(expr.ConstVal[1])),
				mersenne31.NewM31Const(uintToStr(expr.ConstVal[2])),
				mersenne31.NewM31Const(uintToStr(expr.ConstVal[3])),
			},
		}

	case OpCol:
		// Get the value from sampledValues
		// Note: row offset handling - for OOD evaluation, different offsets
		// correspond to different sampled points (we simplify to single point for now)
		tree := expr.TreeIdx
		col := expr.ColIdx
		off := expr.RowOff

		// Bounds check
		if tree >= len(sampledValues) {
			panic("tree index out of bounds")
		}
		if col >= len(sampledValues[tree]) {
			panic("column index out of bounds")
		}

		// For OOD evaluation, offset 0 is the main point
		// If we have multiple offsets sampled, they're stored sequentially
		offIdx := 0
		if off != 0 {
			// Convert row offset to index in sampled values
			// Typically: offset -1 -> index 0, offset 0 -> index 1 (if mask includes both)
			// This depends on the mask structure - for simplicity assume offset maps directly
			offIdx = -off // -1 -> 1, etc.
		}

		if offIdx >= len(sampledValues[tree][col]) {
			// If offset not available, use index 0
			offIdx = 0
		}

		return sampledValues[tree][col][offIdx]

	default:
		panic("unknown constraint op: " + string(expr.Op))
	}
}

// EvaluateCompositionPolynomial computes the composition polynomial value at the OOD point.
// This verifies: composition_eval == Σ (random_coeff^i * constraint_i / vanishing)
//
// CRITICAL: stwo uses Horner's rule for accumulation:
//   acc = acc * alpha + evaluation
// This gives: alpha^{N-1} * q[0] + alpha^{N-2} * q[1] + ... + alpha^0 * q[N-1]
// where N is the number of constraints.
func (e *ConstraintEvaluator) EvaluateCompositionPolynomial(
	constraints *AIRConstraints,
	sampledValues [][][]mersenne31.QM31Variable,
	randomCoeff mersenne31.QM31Variable,
	vanishingInv mersenne31.QM31Variable,
) mersenne31.QM31Variable {
	// Start with zero
	sum := mersenne31.ZeroQM31()

	// Evaluate each constraint and accumulate using Horner's rule
	for _, constraint := range constraints.Constraints {
		// Evaluate the constraint expression
		constraintEval := e.EvaluateExpr(constraint, sampledValues)

		// Compute constraint quotient: constraint_eval * vanishing_inv
		quotient := e.m31Chip.MulQM31(constraintEval, vanishingInv)

		// Horner's rule: sum = sum * randomCoeff + quotient
		// This matches stwo's PointEvaluationAccumulator::accumulate
		sum = e.m31Chip.MulQM31(sum, randomCoeff)
		sum = e.m31Chip.AddQM31(sum, quotient)
	}

	return sum
}

// ComputeVanishingInverse computes the inverse of the vanishing polynomial at the OOD point.
// For a CanonicCoset of log_size n, the vanishing polynomial is computed by applying
// the circle doubling formula n-1 times: double_x(x) = 2x^2 - 1
//
// This matches stwo's coset_vanishing function.
func (e *ConstraintEvaluator) ComputeVanishingInverse(
	oodPointX mersenne31.QM31Variable,
	logSize uint32,
) mersenne31.QM31Variable {
	// Apply circle doubling log_size - 1 times
	// double_x(x) = 2x^2 - 1
	result := oodPointX
	one := mersenne31.OneQM31()
	for i := uint32(1); i < logSize; i++ {
		// x^2
		xSquared := e.m31Chip.MulQM31(result, result)
		// 2x^2
		xDoubled := e.m31Chip.AddQM31(xSquared, xSquared)
		// 2x^2 - 1
		result = e.m31Chip.SubQM31(xDoubled, one)
	}

	// Return inverse
	return e.m31Chip.InvQM31(result)
}

// ExtractCompositionEval extracts the composition polynomial evaluation from sampled values.
// The composition polynomial is split into parts stored in the last tree.
func (e *ConstraintEvaluator) ExtractCompositionEval(
	sampledValues [][][]mersenne31.QM31Variable,
	oodPointX mersenne31.QM31Variable,
	compositionLogSize uint32,
) mersenne31.QM31Variable {
	// Composition columns are in the last tree
	lastTree := sampledValues[len(sampledValues)-1]

	if len(lastTree) < 8 {
		panic("composition tree must have at least 8 columns")
	}

	// Reconstruct the two halves of the composition polynomial
	// left = columns 0-3 combined as QM31
	// right = columns 4-7 combined as QM31
	left := e.combinePartialEvals(
		lastTree[0][0], lastTree[1][0], lastTree[2][0], lastTree[3][0],
	)
	right := e.combinePartialEvals(
		lastTree[4][0], lastTree[5][0], lastTree[6][0], lastTree[7][0],
	)

	// Compute x^{2^{log_size - 2}} for combining left and right
	// composition(z) = left(z) + x^{2^{log_size-2}} * right(z)
	xPower := oodPointX
	for i := uint32(0); i < compositionLogSize-2; i++ {
		// Circle doubling: x' = 2x^2 - 1
		xSquared := e.m31Chip.MulQM31(xPower, xPower)
		xDoubled := e.m31Chip.AddQM31(xSquared, xSquared)
		one := mersenne31.OneQM31()
		xPower = e.m31Chip.SubQM31(xDoubled, one)
	}

	// composition = left + xPower * right
	rightScaled := e.m31Chip.MulQM31(xPower, right)
	return e.m31Chip.AddQM31(left, rightScaled)
}

// combinePartialEvals combines 4 QM31 partial evaluations into one.
// This is used for reconstructing values from the split representation.
// In stwo, the composition polynomial is split such that each part
// represents one component of the QM31.
func (e *ConstraintEvaluator) combinePartialEvals(
	v0, v1, v2, v3 mersenne31.QM31Variable,
) mersenne31.QM31Variable {
	// The partial evaluations represent the 4 components of a QM31
	// Each vi.Value[0] contains the M31 component at that position
	// TODO: Verify this matches stwo's from_partial_evals
	return mersenne31.QM31Variable{
		Value: [4]mersenne31.M31Variable{
			v0.Value[0],
			v1.Value[0],
			v2.Value[0],
			v3.Value[0],
		},
	}
}

// Helper to convert uint32 to string for constant creation
func uintToStr(v uint32) string {
	return fmt.Sprintf("%d", v)
}
