package stwo

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/gnark-stwo/stwo/mersenne31"
)

// TestConstraintExprCircuit tests constraint expression evaluation in-circuit.
type TestConstraintExprCircuit struct {
	// Input values for sampled columns
	Col0Val [4]frontend.Variable `gnark:",public"`
	Col1Val [4]frontend.Variable `gnark:",public"`
	Col2Val [4]frontend.Variable `gnark:",public"`

	// Expected result
	Expected [4]frontend.Variable `gnark:",public"`

	// The constraint expression structure (not a circuit variable)
	Constraint *ConstraintExpr `gnark:"-"`
}

func (c *TestConstraintExprCircuit) Define(api frontend.API) error {
	m31Chip := mersenne31.NewM31Chip(api, false) // Not Groth16

	// Helper to create M31Variable with proper UpperBound
	m31Mod := new(big.Int).SetUint64((1 << 31) - 1)
	makeM31 := func(v frontend.Variable) mersenne31.M31Variable {
		return mersenne31.M31Variable{Value: v, UpperBound: new(big.Int).Set(m31Mod)}
	}

	// Build sampled values structure: 2 trees, columns, 1 value each per column
	// Format: [tree][column][offset] -> QM31Variable
	sampledValues := [][][]mersenne31.QM31Variable{
		// Tree 0 (preprocessed)
		{
			// Col 0
			{
				mersenne31.QM31Variable{
					Value: [4]mersenne31.M31Variable{
						makeM31(c.Col0Val[0]),
						makeM31(c.Col0Val[1]),
						makeM31(c.Col0Val[2]),
						makeM31(c.Col0Val[3]),
					},
				},
			},
		},
		// Tree 1 (trace)
		{
			// Col 0
			{
				mersenne31.QM31Variable{
					Value: [4]mersenne31.M31Variable{
						makeM31(c.Col1Val[0]),
						makeM31(c.Col1Val[1]),
						makeM31(c.Col1Val[2]),
						makeM31(c.Col1Val[3]),
					},
				},
			},
			// Col 1
			{
				mersenne31.QM31Variable{
					Value: [4]mersenne31.M31Variable{
						makeM31(c.Col2Val[0]),
						makeM31(c.Col2Val[1]),
						makeM31(c.Col2Val[2]),
						makeM31(c.Col2Val[3]),
					},
				},
			},
		},
	}

	// Create evaluator
	evaluator := NewConstraintEvaluator(api, m31Chip)

	// Evaluate the constraint expression
	result := evaluator.EvaluateExpr(c.Constraint, sampledValues)

	// Build expected QM31
	expected := mersenne31.QM31Variable{
		Value: [4]mersenne31.M31Variable{
			makeM31(c.Expected[0]),
			makeM31(c.Expected[1]),
			makeM31(c.Expected[2]),
			makeM31(c.Expected[3]),
		},
	}

	// Assert equality
	m31Chip.AssertEqQM31(result, expected)

	return nil
}

func TestConstraintExprEvaluator(t *testing.T) {
	// Test case: col[1,0] + col[1,1]
	// col[1,0] = (5, 0, 0, 0)
	// col[1,1] = (7, 0, 0, 0)
	// Expected: (12, 0, 0, 0)

	constraint := &ConstraintExpr{
		Op: OpAdd,
		Left: &ConstraintExpr{
			Op:      OpCol,
			TreeIdx: 1,
			ColIdx:  0,
			RowOff:  0,
		},
		Right: &ConstraintExpr{
			Op:      OpCol,
			TreeIdx: 1,
			ColIdx:  1,
			RowOff:  0,
		},
	}

	circuit := &TestConstraintExprCircuit{
		Constraint: constraint,
	}

	witness := &TestConstraintExprCircuit{
		Col0Val:    [4]frontend.Variable{0, 0, 0, 0}, // Not used in this test
		Col1Val:    [4]frontend.Variable{5, 0, 0, 0},
		Col2Val:    [4]frontend.Variable{7, 0, 0, 0},
		Expected:   [4]frontend.Variable{12, 0, 0, 0},
		Constraint: constraint,
	}

	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		t.Fatalf("Failed to compile circuit: %v", err)
	}
	t.Logf("Circuit compiled: %d constraints", cs.GetNbConstraints())

	// Create witness
	w, err := frontend.NewWitness(witness, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("Failed to create witness: %v", err)
	}

	// Verify the constraint system
	pubWitness, err := w.Public()
	if err != nil {
		t.Fatalf("Failed to get public witness: %v", err)
	}

	err = cs.IsSolved(w)
	if err != nil {
		t.Fatalf("Circuit not satisfied: %v", err)
	}

	t.Logf("Public witness: %v", pubWitness)
	t.Log("Test passed: constraint expression evaluation works correctly")
}

func TestConstraintExprMul(t *testing.T) {
	// Test case: col[1,0] * col[1,1]
	// col[1,0] = (3, 0, 0, 0)
	// col[1,1] = (4, 0, 0, 0)
	// Expected: (12, 0, 0, 0) since (3+0i+0u+0iu) * (4+0i+0u+0iu) = 12

	constraint := &ConstraintExpr{
		Op: OpMul,
		Left: &ConstraintExpr{
			Op:      OpCol,
			TreeIdx: 1,
			ColIdx:  0,
			RowOff:  0,
		},
		Right: &ConstraintExpr{
			Op:      OpCol,
			TreeIdx: 1,
			ColIdx:  1,
			RowOff:  0,
		},
	}

	circuit := &TestConstraintExprCircuit{
		Constraint: constraint,
	}

	witness := &TestConstraintExprCircuit{
		Col0Val:    [4]frontend.Variable{0, 0, 0, 0},
		Col1Val:    [4]frontend.Variable{3, 0, 0, 0},
		Col2Val:    [4]frontend.Variable{4, 0, 0, 0},
		Expected:   [4]frontend.Variable{12, 0, 0, 0},
		Constraint: constraint,
	}

	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		t.Fatalf("Failed to compile circuit: %v", err)
	}

	w, err := frontend.NewWitness(witness, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("Failed to create witness: %v", err)
	}

	err = cs.IsSolved(w)
	if err != nil {
		t.Fatalf("Circuit not satisfied: %v", err)
	}

	t.Log("Test passed: multiplication expression evaluation works correctly")
}

func TestConstraintExprSubNeg(t *testing.T) {
	// Test case: col[1,0] - col[1,1] == neg(col[1,1] - col[1,0])
	// col[1,0] = (10, 0, 0, 0)
	// col[1,1] = (3, 0, 0, 0)
	// Expected: (7, 0, 0, 0)

	constraint := &ConstraintExpr{
		Op: OpSub,
		Left: &ConstraintExpr{
			Op:      OpCol,
			TreeIdx: 1,
			ColIdx:  0,
			RowOff:  0,
		},
		Right: &ConstraintExpr{
			Op:      OpCol,
			TreeIdx: 1,
			ColIdx:  1,
			RowOff:  0,
		},
	}

	circuit := &TestConstraintExprCircuit{
		Constraint: constraint,
	}

	witness := &TestConstraintExprCircuit{
		Col0Val:    [4]frontend.Variable{0, 0, 0, 0},
		Col1Val:    [4]frontend.Variable{10, 0, 0, 0},
		Col2Val:    [4]frontend.Variable{3, 0, 0, 0},
		Expected:   [4]frontend.Variable{7, 0, 0, 0},
		Constraint: constraint,
	}

	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		t.Fatalf("Failed to compile circuit: %v", err)
	}

	w, err := frontend.NewWitness(witness, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("Failed to create witness: %v", err)
	}

	err = cs.IsSolved(w)
	if err != nil {
		t.Fatalf("Circuit not satisfied: %v", err)
	}

	t.Log("Test passed: subtraction expression evaluation works correctly")
}

func TestConstraintExprConst(t *testing.T) {
	// Test case: col[1,0] + const(5, 0, 0, 0)
	// col[1,0] = (7, 0, 0, 0)
	// Expected: (12, 0, 0, 0)

	constraint := &ConstraintExpr{
		Op: OpAdd,
		Left: &ConstraintExpr{
			Op:      OpCol,
			TreeIdx: 1,
			ColIdx:  0,
			RowOff:  0,
		},
		Right: &ConstraintExpr{
			Op:       OpConst,
			ConstVal: [4]uint32{5, 0, 0, 0},
		},
	}

	circuit := &TestConstraintExprCircuit{
		Constraint: constraint,
	}

	witness := &TestConstraintExprCircuit{
		Col0Val:    [4]frontend.Variable{0, 0, 0, 0},
		Col1Val:    [4]frontend.Variable{7, 0, 0, 0},
		Col2Val:    [4]frontend.Variable{0, 0, 0, 0},
		Expected:   [4]frontend.Variable{12, 0, 0, 0},
		Constraint: constraint,
	}

	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		t.Fatalf("Failed to compile circuit: %v", err)
	}

	w, err := frontend.NewWitness(witness, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("Failed to create witness: %v", err)
	}

	err = cs.IsSolved(w)
	if err != nil {
		t.Fatalf("Circuit not satisfied: %v", err)
	}

	t.Log("Test passed: constant expression evaluation works correctly")
}

func TestConstraintExprComplex(t *testing.T) {
	// Test case: (col[1,0] * col[1,1]) + (col[1,0] - col[1,1])
	// col[1,0] = (5, 0, 0, 0)
	// col[1,1] = (3, 0, 0, 0)
	// (5 * 3) + (5 - 3) = 15 + 2 = 17
	// Expected: (17, 0, 0, 0)

	constraint := &ConstraintExpr{
		Op: OpAdd,
		Left: &ConstraintExpr{
			Op: OpMul,
			Left: &ConstraintExpr{
				Op:      OpCol,
				TreeIdx: 1,
				ColIdx:  0,
				RowOff:  0,
			},
			Right: &ConstraintExpr{
				Op:      OpCol,
				TreeIdx: 1,
				ColIdx:  1,
				RowOff:  0,
			},
		},
		Right: &ConstraintExpr{
			Op: OpSub,
			Left: &ConstraintExpr{
				Op:      OpCol,
				TreeIdx: 1,
				ColIdx:  0,
				RowOff:  0,
			},
			Right: &ConstraintExpr{
				Op:      OpCol,
				TreeIdx: 1,
				ColIdx:  1,
				RowOff:  0,
			},
		},
	}

	circuit := &TestConstraintExprCircuit{
		Constraint: constraint,
	}

	witness := &TestConstraintExprCircuit{
		Col0Val:    [4]frontend.Variable{0, 0, 0, 0},
		Col1Val:    [4]frontend.Variable{5, 0, 0, 0},
		Col2Val:    [4]frontend.Variable{3, 0, 0, 0},
		Expected:   [4]frontend.Variable{17, 0, 0, 0},
		Constraint: constraint,
	}

	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		t.Fatalf("Failed to compile circuit: %v", err)
	}

	w, err := frontend.NewWitness(witness, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("Failed to create witness: %v", err)
	}

	err = cs.IsSolved(w)
	if err != nil {
		t.Fatalf("Circuit not satisfied: %v", err)
	}

	t.Log("Test passed: complex expression evaluation works correctly")
}
