// Package stwo_test provides integration tests for the stwo verifier circuit.
package stwo_test

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
	stwo "github.com/gnark-stwo/stwo"
	"github.com/gnark-stwo/stwo/blake2s"
	"github.com/gnark-stwo/stwo/fri"
	"github.com/gnark-stwo/stwo/merkle"
	"github.com/gnark-stwo/stwo/mersenne31"
)

// TestFullStwoVerifierCircuit tests that the circuit compiles correctly.
// NOTE: This test only verifies compilation, not proof generation.
// Full proof generation/verification requires real stwo proof data because
// the circuit now includes mathematical constraints (circle equation,
// Merkle verification, etc.) that mock data cannot satisfy.
// Use the CLI with real witness data for full end-to-end testing.
func TestFullStwoVerifierCircuit(t *testing.T) {
	// Create circuit with mock structure (for schema definition)
	circuit := createMockWitness()

	// Compile the circuit to verify it compiles without errors
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		t.Fatalf("Failed to compile circuit: %v", err)
	}
	t.Logf("Circuit compiled successfully: %d constraints", cs.GetNbConstraints())

	// NOTE: Proof generation with mock data is not tested here because
	// the verifier now properly implements security checks that require
	// mathematically consistent data:
	// - Circle equation verification (x² + y² = 1)
	// - Merkle decommitment verification
	// - Permutation checks
	// - FRI folding verification
	//
	// To test full proof generation, use the CLI with real witness data:
	//   ./stwo-verifier prove --witness witness.json --pk proving.key
	t.Log("Compile-only test passed. Use real witness data for full verification testing.")
}

// TestM31Operations tests M31 field arithmetic.
func TestM31Operations(t *testing.T) {
	assert := test.NewAssert(t)

	// Simple circuit to test M31 operations
	circuit := &M31TestCircuit{}
	witness := &M31TestCircuit{
		A: frontend.Variable(100),
		B: frontend.Variable(200),
	}

	assert.ProverSucceeded(circuit, witness, test.WithCurves(ecc.BN254))
}

type M31TestCircuit struct {
	A, B frontend.Variable
}

func (c *M31TestCircuit) Define(api frontend.API) error {
	m31Chip := mersenne31.NewM31Chip(api, true)

	a := mersenne31.M31Variable{
		Value:      c.A,
		UpperBound: big.NewInt(1 << 31),
	}
	b := mersenne31.M31Variable{
		Value:      c.B,
		UpperBound: big.NewInt(1 << 31),
	}

	// Test add
	sum := m31Chip.AddM31(a, b)
	api.AssertIsDifferent(sum.Value, 0)

	// Test mul
	prod := m31Chip.MulM31(a, b)
	api.AssertIsDifferent(prod.Value, 0)

	// Test sub
	diff := m31Chip.SubM31(a, b)
	_ = diff

	return nil
}

// TestQM31Operations tests QM31 field arithmetic.
func TestQM31Operations(t *testing.T) {
	assert := test.NewAssert(t)

	circuit := &QM31TestCircuit{}
	witness := &QM31TestCircuit{
		A0: frontend.Variable(1),
		A1: frontend.Variable(2),
		A2: frontend.Variable(3),
		A3: frontend.Variable(4),
		B0: frontend.Variable(5),
		B1: frontend.Variable(6),
		B2: frontend.Variable(7),
		B3: frontend.Variable(8),
	}

	assert.ProverSucceeded(circuit, witness, test.WithCurves(ecc.BN254))
}

type QM31TestCircuit struct {
	A0, A1, A2, A3 frontend.Variable
	B0, B1, B2, B3 frontend.Variable
}

func (c *QM31TestCircuit) Define(api frontend.API) error {
	m31Chip := mersenne31.NewM31Chip(api, true)
	upperBound := big.NewInt(1 << 31)

	a := mersenne31.QM31Variable{
		Value: [4]mersenne31.M31Variable{
			{Value: c.A0, UpperBound: upperBound},
			{Value: c.A1, UpperBound: upperBound},
			{Value: c.A2, UpperBound: upperBound},
			{Value: c.A3, UpperBound: upperBound},
		},
	}
	b := mersenne31.QM31Variable{
		Value: [4]mersenne31.M31Variable{
			{Value: c.B0, UpperBound: upperBound},
			{Value: c.B1, UpperBound: upperBound},
			{Value: c.B2, UpperBound: upperBound},
			{Value: c.B3, UpperBound: upperBound},
		},
	}

	// Test add
	sum := m31Chip.AddQM31(a, b)
	api.AssertIsDifferent(sum.Value[0].Value, 0)

	// Test sub
	diff := m31Chip.SubQM31(a, b)
	_ = diff

	// Test mul
	prod := m31Chip.MulQM31(a, b)
	api.AssertIsDifferent(prod.Value[0].Value, 0)

	return nil
}

// TestFriFold tests the FRI folding operation.
func TestFriFold(t *testing.T) {
	assert := test.NewAssert(t)

	circuit := &FriFoldTestCircuit{}
	witness := &FriFoldTestCircuit{
		V0_0:   frontend.Variable(10),
		V0_1:   frontend.Variable(20),
		V0_2:   frontend.Variable(30),
		V0_3:   frontend.Variable(40),
		V1_0:   frontend.Variable(50),
		V1_1:   frontend.Variable(60),
		V1_2:   frontend.Variable(70),
		V1_3:   frontend.Variable(80),
		ITwid:  frontend.Variable(100),
		Alpha0: frontend.Variable(1),
		Alpha1: frontend.Variable(2),
		Alpha2: frontend.Variable(3),
		Alpha3: frontend.Variable(4),
	}

	assert.ProverSucceeded(circuit, witness, test.WithCurves(ecc.BN254))
}

type FriFoldTestCircuit struct {
	V0_0, V0_1, V0_2, V0_3 frontend.Variable
	V1_0, V1_1, V1_2, V1_3 frontend.Variable
	ITwid                  frontend.Variable
	Alpha0, Alpha1         frontend.Variable
	Alpha2, Alpha3         frontend.Variable
}

func (c *FriFoldTestCircuit) Define(api frontend.API) error {
	m31Chip := mersenne31.NewM31Chip(api, true)
	upperBound := big.NewInt(1 << 31)

	v0 := mersenne31.QM31Variable{
		Value: [4]mersenne31.M31Variable{
			{Value: c.V0_0, UpperBound: upperBound},
			{Value: c.V0_1, UpperBound: upperBound},
			{Value: c.V0_2, UpperBound: upperBound},
			{Value: c.V0_3, UpperBound: upperBound},
		},
	}
	v1 := mersenne31.QM31Variable{
		Value: [4]mersenne31.M31Variable{
			{Value: c.V1_0, UpperBound: upperBound},
			{Value: c.V1_1, UpperBound: upperBound},
			{Value: c.V1_2, UpperBound: upperBound},
			{Value: c.V1_3, UpperBound: upperBound},
		},
	}
	itwid := mersenne31.M31Variable{Value: c.ITwid, UpperBound: upperBound}
	alpha := mersenne31.QM31Variable{
		Value: [4]mersenne31.M31Variable{
			{Value: c.Alpha0, UpperBound: upperBound},
			{Value: c.Alpha1, UpperBound: upperBound},
			{Value: c.Alpha2, UpperBound: upperBound},
			{Value: c.Alpha3, UpperBound: upperBound},
		},
	}

	result := fri.FriFold(m31Chip, v0, v1, itwid, alpha)
	api.AssertIsDifferent(result.Value[0].Value, 0)

	return nil
}

// createMockWitness creates a mock witness for testing.
func createMockWitness() *stwo.FullStwoVerifierCircuit {
	upperBound := big.NewInt(1 << 31)

	// Helper to create a QM31 with all values set
	makeQM31 := func(a, b, c, d int) mersenne31.QM31Variable {
		return mersenne31.QM31Variable{
			Value: [4]mersenne31.M31Variable{
				{Value: frontend.Variable(a), UpperBound: upperBound},
				{Value: frontend.Variable(b), UpperBound: upperBound},
				{Value: frontend.Variable(c), UpperBound: upperBound},
				{Value: frontend.Variable(d), UpperBound: upperBound},
			},
		}
	}

	// Helper to create a Blake2sHash
	makeHash := func(seed int) blake2s.Blake2sHash {
		var h blake2s.Blake2sHash
		for j := 0; j < 8; j++ {
			h.Words[j] = frontend.Variable(uint32(seed*8 + j + 1))
		}
		return h
	}

	// Create mock commitments
	commitments := make([]blake2s.Blake2sHash, 3)
	for i := range commitments {
		commitments[i] = makeHash(i)
	}

	// Create mock sampled values (using wrapper types)
	// Tree 0: preprocessed, Tree 1: trace, Tree 2: interaction/composition
	// The last tree (composition) must have at least 8 columns for composition poly verification
	sampledValues := make([]stwo.TreeSampledValues, 3)
	// Trees 0 and 1: single column each
	for i := 0; i < 2; i++ {
		sampledValues[i] = stwo.TreeSampledValues{
			Columns: []stwo.QM31Column{
				{Values: []mersenne31.QM31Variable{makeQM31(1, 2, 3, 4)}},
			},
		}
	}
	// Tree 2 (composition): 8 columns for composition polynomial (split into 8 parts)
	compositionCols := make([]stwo.QM31Column, 8)
	for i := 0; i < 8; i++ {
		compositionCols[i] = stwo.QM31Column{
			Values: []mersenne31.QM31Variable{makeQM31(i+1, i+2, i+3, i+4)},
		}
	}
	sampledValues[2] = stwo.TreeSampledValues{Columns: compositionCols}

	// Create mock decommitments
	decommitments := make([]merkle.MerkleDecommitment, 3)
	for i := range decommitments {
		hashWitness := make([]blake2s.Blake2sHash, 4)
		for j := range hashWitness {
			hashWitness[j] = makeHash(i*4 + j + 10)
		}
		decommitments[i] = merkle.MerkleDecommitment{
			HashWitness: hashWitness,
		}
	}

	// Create mock queried values (using wrapper types)
	queriedValues := make([]stwo.M31Column, 2)
	for i := range queriedValues {
		vals := make([]mersenne31.M31Variable, 4)
		for j := range vals {
			vals[j] = mersenne31.M31Variable{
				Value:      frontend.Variable(i*4 + j + 1),
				UpperBound: upperBound,
			}
		}
		queriedValues[i] = stwo.M31Column{Values: vals}
	}

	// Create mock FRI first layer
	firstLayer := fri.FriLayerProof{
		Commitment: makeHash(100),
		EvalValues: make([]mersenne31.QM31Variable, 4),
		Decommitment: merkle.MerkleDecommitment{
			HashWitness: []blake2s.Blake2sHash{makeHash(101), makeHash(102)},
		},
	}
	for i := range firstLayer.EvalValues {
		firstLayer.EvalValues[i] = makeQM31(i+1, 0, 0, 0)
	}

	// Create mock inner layers
	// Number of inner layers = numFriLayers - 1
	// numFriLayers = maxLogSize + LogBlowupFactor - LogLastLayerDeg
	//              = 4 + 1 - 0 = 5
	// numInnerLayers = 5 - 1 = 4
	numInnerLayers := 4
	innerLayers := make([]fri.FriLayerProof, numInnerLayers)
	for i := range innerLayers {
		evalValues := make([]mersenne31.QM31Variable, 4)
		for j := range evalValues {
			evalValues[j] = makeQM31(i*4+j+10, 0, 0, 0)
		}
		innerLayers[i] = fri.FriLayerProof{
			Commitment: makeHash(110 + i),
			EvalValues: evalValues,
			Decommitment: merkle.MerkleDecommitment{
				HashWitness: []blake2s.Blake2sHash{makeHash(120 + i)},
			},
		}
	}

	friProof := fri.FriProof{
		FirstLayer:    firstLayer,
		InnerLayers:   innerLayers,
		LastLayerPoly: []mersenne31.QM31Variable{makeQM31(42, 0, 0, 0)},
	}

	// Create placeholder public input hash
	var publicInputHash blake2s.Blake2sHash
	for i := 0; i < 8; i++ {
		publicInputHash.Words[i] = frontend.Variable(12345 + i)
	}

	// Create mock AIR constraints (required for compilation)
	// This is a simple constraint: col(1,0,0) - col(1,0,0) = 0
	// The constraint is trivially satisfied but tests the constraint evaluation path.
	mockConstraints := &stwo.AIRConstraints{
		Constraints: []*stwo.ConstraintExpr{
			{
				Op: stwo.OpSub,
				Left: &stwo.ConstraintExpr{
					Op:      stwo.OpCol,
					TreeIdx: 1,
					ColIdx:  0,
					RowOff:  0,
				},
				Right: &stwo.ConstraintExpr{
					Op:      stwo.OpCol,
					TreeIdx: 1,
					ColIdx:  0,
					RowOff:  0,
				},
			},
		},
		CompositionLogDegreeBound: 5,
	}

	return &stwo.FullStwoVerifierCircuit{
		PublicInputHash: publicInputHash,
		Proof: stwo.StwoProof{
			Commitments:   commitments,
			SampledValues: sampledValues,
			Decommitments: decommitments,
			QueriedValues: queriedValues,
			PowNonce:      frontend.Variable(67890),
			FriProof:      friProof,
		},
		Config: stwo.PcsConfig{
			PowBits:         8,
			LogBlowupFactor: 1,
			LogLastLayerDeg: 0,
			NumQueries:      2,
		},
		ColumnLogSizes: [][]int{
			{4}, // preprocessed
			{4}, // trace
			{4}, // interaction
		},
		AIRConstraints: mockConstraints,
	}
}

// BenchmarkCircuitCompilation benchmarks circuit compilation.
func BenchmarkCircuitCompilation(b *testing.B) {
	circuit := &stwo.FullStwoVerifierCircuit{
		Config: stwo.PcsConfig{
			PowBits:         16,
			LogBlowupFactor: 1,
			LogLastLayerDeg: 0,
			NumQueries:      10,
		},
		ColumnLogSizes: [][]int{
			{10},
			{10, 10},
			{10, 10, 10, 10},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = frontend.Compile(ecc.BN254.ScalarField(), nil, circuit)
	}
}
